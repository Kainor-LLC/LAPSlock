import Foundation
import AuthKit
import CredentialKit

// Build Spec §2.2, §5, §7, §8, device inventory fetching.
//
// Responsibilities:
//   * page through /v1.0/deviceManagement/managedDevices via $top + @odata.nextLink
//   * request only the fields the UI needs ($select), keeping payloads small
//   * cache per TENANT, and tear the cache down completely on account switch (§3.3/§7)
//   * translate HTTP status into the actionable error cases the UI renders (§8)
//
// Cache safety: the cache key includes the tenant id, and `reset()` drops everything.
// Device inventory is not secret, but showing one customer's device names inside another
// tenant's session would be a serious trust failure, so the teardown is unconditional.

enum InventoryHTTP {
    static let base = "https://graph.microsoft.com"

    /// Fields the list UI actually needs. `azureADDeviceId` is the important one, it is
    /// the Entra device id Windows LAPS reveal keys on, and it arrives here directly
    /// rather than requiring a second lookup (see ManagedDeviceSummary header).
    ///
    /// The user fields below are here for SEARCH, not display. An admin working a ticket
    /// has a person's name or an email address, rarely a device name, so a search that
    /// only covers deviceName sends them scrolling. Every property listed is on the v1.0
    /// managedDevice resource and covered by DeviceManagementManagedDevices.Read.All, so
    /// none of this widens the consent ask.
    ///
    /// Careful when editing: Graph rejects the whole request with 400 if $select names a
    /// property that does not exist, which takes the device list down entirely rather than
    /// degrading. Verify any addition against the v1.0 managedDevice schema first.
    static let selectFields = [
        "id",
        "deviceName",
        "managedDeviceName",
        "operatingSystem",
        "osVersion",
        "azureADDeviceId",
        "userPrincipalName",
        "userDisplayName",
        "emailAddress",
        "serialNumber",
        "model",
        "manufacturer",
        "complianceState",
        "lastSyncDateTime"
    ]

    static func firstPageURL(pageSize: Int) -> URL {
        var comps = URLComponents(string: base)!
        comps.path = "/v1.0/deviceManagement/managedDevices"
        comps.queryItems = [
            URLQueryItem(name: "$select", value: selectFields.joined(separator: ",")),
            URLQueryItem(name: "$top", value: String(pageSize))
        ]
        return comps.url!
    }

    static func makeSession() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.urlCache = nil
        cfg.httpCookieStorage = nil
        cfg.timeoutIntervalForRequest = 30
        return URLSession(configuration: cfg)
    }

    static func validate(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { throw InventoryError.transport(status: -1) }
        // Capture Graph's request-id before throwing. It is the first thing Microsoft support
        // asks for, and the typed errors below deliberately do not carry it, see
        // GraphResponseTracer for why this is a side channel rather than an error payload.
        if !(200...299).contains(http.statusCode) {
            GraphResponseTracer.shared.recordFailure(http)
        }
        switch http.statusCode {
        case 200...299: return
        case 401: throw InventoryError.consentRequired
        case 403: throw InventoryError.notAuthorized
        case 429:
            let retry = http.value(forHTTPHeaderField: "Retry-After").flatMap(TimeInterval.init)
            throw InventoryError.throttled(retryAfter: retry)
        case 500...599: throw InventoryError.serviceUnavailable(status: http.statusCode)
        default: throw InventoryError.transport(status: http.statusCode)
        }
    }

    static func date(_ any: Any?) -> Date? {
        guard let s = any as? String else { return nil }
        return withFraction.date(from: s) ?? plain.date(from: s)
    }

    // Built once: this runs for every device in a fill, and two formatters per device was
    // up to 40,000 of them for a large tenant. ISO8601DateFormatter is thread-safe.
    private static let withFraction: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static let plain = ISO8601DateFormatter()
}

public actor DeviceInventoryService {
    public static let requiredScopes = [LapsCredentialScopes.intuneDevices]

    private let auth: AuthManaging
    private let session: URLSession
    private let pageSize: Int

    /// Cached devices keyed by the OPERATING tenant, so a session in one tenant can never
    /// render another tenant's inventory. Not the signed-in account's home tenant: an MSP
    /// working in a customer would otherwise file the customer's devices under their own.
    private var cache: [String: [ManagedDeviceSummary]] = [:]
    private var nextLinkByTenant: [String: String?] = [:]

    /// Moves on every first-page load and every reset. A page that was asked for under an
    /// older generation is dropped when it arrives, so a refresh or a reset can never be
    /// followed by a stale page appended to the fresh list or overwriting its next link.
    private var generation = 0

    /// - session: injected by tests. Production gets an ephemeral session.
    public init(auth: AuthManaging, pageSize: Int = 100, session: URLSession? = nil) {
        self.auth = auth
        self.session = session ?? InventoryHTTP.makeSession()
        // Graph accepts up to 1000; 100 keeps the first page fast on a phone.
        self.pageSize = max(1, min(pageSize, 1000))
    }

    // MARK: - fetching

    /// Fetches the first page, replacing any cached inventory for the current tenant.
    /// Call on initial load and on pull-to-refresh.
    @discardableResult
    public func loadFirstPage() async throws -> DevicePage {
        generation += 1
        let asked = generation
        let tenantId = try await currentTenantId()
        let page = try await fetch(url: InventoryHTTP.firstPageURL(pageSize: pageSize))
        // A newer load or a reset happened while this one was out. It owns the cache now.
        guard asked == generation else { return page }
        cache[tenantId] = page.devices
        nextLinkByTenant[tenantId] = page.nextLink
        return page
    }

    /// Fetches the next page and appends it. Returns nil when there is nothing more.
    @discardableResult
    public func loadNextPage() async throws -> DevicePage? {
        let asked = generation
        let tenantId = try await currentTenantId()
        guard let link = nextLinkByTenant[tenantId] ?? nil, let url = URL(string: link) else {
            return nil
        }
        // The bearer token goes with the request, so only a Graph link is followed.
        guard GraphClient.isPageLink(url) else { throw InventoryError.decodeFailure }
        let page = try await fetch(url: url)
        guard asked == generation else { throw CancellationError() }
        cache[tenantId, default: []].append(contentsOf: page.devices)
        nextLinkByTenant[tenantId] = page.nextLink
        return page
    }

    private func fetch(url: URL) async throws -> DevicePage {
        let token = try await auth.token(scopes: Self.requiredScopes, allowInteractive: false)
        var req = URLRequest(url: url)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        // Ask Graph to keep going when a single device record is malformed rather than
        // failing the whole page.
        req.setValue("odata.maxpagesize=\(pageSize)", forHTTPHeaderField: "Prefer")

        let (data, response) = try await session.data(for: req)
        try InventoryHTTP.validate(response)

        guard
            let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let value = root["value"] as? [[String: Any]]
        else { throw InventoryError.decodeFailure }

        // Skip unusable records (no id) instead of failing the page.
        let devices = value.compactMap { ManagedDeviceSummary(graphEntry: $0) }
        let nextLink = root["@odata.nextLink"] as? String
        return DevicePage(devices: devices, nextLink: nextLink)
    }

    // MARK: - cache access

    public func cachedDevices() async throws -> [ManagedDeviceSummary] {
        let tenantId = try await currentTenantId()
        return cache[tenantId] ?? []
    }

    public func hasMore() async throws -> Bool {
        let tenantId = try await currentTenantId()
        return (nextLinkByTenant[tenantId] ?? nil) != nil
    }

    /// Full teardown. MUST be called on sign-out and on account switch (§7).
    public func reset() {
        generation += 1
        cache.removeAll()
        nextLinkByTenant.removeAll()
    }

    private func currentTenantId() async throws -> String {
        guard let account = await auth.currentAccount else { throw InventoryError.consentRequired }
        return (await auth.operatingTenantId ?? account.tenantId).lowercased()
    }
}

// MARK: - search

/// Client-side search. Graph's managedDevices resource has no dependable server-side
/// substring search on deviceName, so filtering happens locally over the cached page set.
///
/// Known limitation: "the cached page set" means the pages loaded so far. A device that
/// exists but has not been paged in will not be found. `InventoryFill` pages the rest in
/// the background for this reason.
///
/// Performance: this runs on the main thread on every keystroke. Each field and the query
/// are folded once (case and diacritics), then compared with plain `==`, `hasPrefix` and
/// `contains`, and every device is scored in a single pass before one sort on the
/// precomputed rank. Folding inside the comparator instead costs roughly 100,000 Unicode
/// folds per keystroke on a 500-device tenant. If it ever needs to be faster, cache folded
/// fields by device id; not before measurement says so.
public enum DeviceSearch {

    private static let foldOptions: String.CompareOptions = [.caseInsensitive, .diacriticInsensitive]

    /// Normalises case and diacritics once, so later comparisons are ordinary string ops.
    private static func fold(_ s: String) -> String {
        s.folding(options: foldOptions, locale: nil)
    }

    /// Searchable fields other than the device name, ordered roughly by how often an admin
    /// has that value to hand when working a ticket.
    private static func secondaryFields(_ device: ManagedDeviceSummary) -> [String] {
        [
            device.userDisplayName,
            device.userPrincipalName,
            device.emailAddress,
            device.serialNumber,
            device.model,
            device.managedDeviceName
        ].compactMap { $0 }
    }

    /// Case- and diacritic-insensitive substring match across the fields an admin would
    /// actually type: device name, the primary user by real name, UPN or mail address,
    /// serial number, model, and Intune's own device name.
    public static func matches(_ device: ManagedDeviceSummary, query: String) -> Bool {
        let raw = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return true }
        return score(device, foldedQuery: fold(raw)) != nil
    }

    /// Filters and orders results. Exact and prefix name matches sort above the rest,
    /// because an admin typing a device name usually wants that device first.
    public static func filter(_ devices: [ManagedDeviceSummary], query: String) -> [ManagedDeviceSummary] {
        let raw = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else {
            return devices.sorted { $0.deviceName.localizedCaseInsensitiveCompare($1.deviceName) == .orderedAscending }
        }

        let q = fold(raw)

        // One pass: match and score together, so no device is examined twice and no score
        // is recomputed inside the comparator.
        var scored: [(device: ManagedDeviceSummary, rank: Int)] = []
        scored.reserveCapacity(devices.count)
        for device in devices {
            if let rank = score(device, foldedQuery: q) {
                scored.append((device, rank))
            }
        }

        scored.sort { a, b in
            if a.rank != b.rank { return a.rank < b.rank }
            return a.device.deviceName.localizedCaseInsensitiveCompare(b.device.deviceName) == .orderedAscending
        }
        return scored.map(\.device)
    }

    /// Ranks a hit by HOW it matched, not just whether it did. Nil means no match.
    ///
    /// Device name outranks everything at equal match strength, but strength counts across
    /// all fields, so an exact match on a user's name beats an incidental substring buried
    /// in a model string:
    ///
    ///   0 exact on device name        1 exact on any other field
    ///   2 prefix on device name       3 prefix on any other field
    ///   4 substring on device name    5 substring on any other field
    private static func score(_ device: ManagedDeviceSummary, foldedQuery q: String) -> Int? {
        var best: Int?

        if let s = strength(fold(device.deviceName), q) {
            // Exact on the device name is the best possible outcome; stop looking.
            if s == 0 { return 0 }
            best = s * 2
        }

        for field in secondaryFields(device) {
            guard let s = strength(fold(field), q) else { continue }
            let rank = s * 2 + 1
            if best == nil || rank < best! { best = rank }
            // Rank 1 is the best a secondary field can achieve, and rank 0 already
            // returned above, so there is nothing better left to find.
            if best == 1 { break }
        }

        return best
    }

    /// 0 exact, 1 prefix, 2 substring, nil no match. Both arguments must already be
    /// folded, these are plain comparisons, not locale-aware ones.
    private static func strength(_ foldedField: String, _ foldedQuery: String) -> Int? {
        if foldedField == foldedQuery { return 0 }
        if foldedField.hasPrefix(foldedQuery) { return 1 }
        if foldedField.contains(foldedQuery) { return 2 }
        return nil
    }
}
