import Foundation
import AuthKit

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
        listURL(top: pageSize, filter: nil)
    }

    static func listURL(top: Int, filter: String?) -> URL {
        var comps = URLComponents(string: base)!
        comps.path = "/v1.0/deviceManagement/managedDevices"
        comps.queryItems = [
            URLQueryItem(name: "$select", value: selectFields.joined(separator: ",")),
            URLQueryItem(name: "$top", value: String(top))
        ]
        if let filter { comps.queryItems?.append(URLQueryItem(name: "$filter", value: filter)) }
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
    /// The same string as CredentialKit's `LapsCredentialScopes.intuneDevices`, written out
    /// rather than imported, as AuthKitMSAL does: this module must not link CredentialKit.
    /// A test on each side pins the string, so the two cannot drift apart.
    public static let requiredScopes = ["DeviceManagementManagedDevices.Read.All"]

    private let auth: AuthManaging
    private let session: URLSession
    private let pageSize: Int
    private let fillPageSize: Int

    /// Cached devices keyed by the OPERATING tenant, so a session in one tenant can never
    /// render another tenant's inventory. Not the signed-in account's home tenant: an MSP
    /// working in a customer would otherwise file the customer's devices under their own.
    private var cache: [String: [ManagedDeviceSummary]] = [:]
    private var nextLinkByTenant: [String: String?] = [:]
    /// Ids already in the cache, per tenant, so no device is ever added twice.
    private var knownIds: [String: Set<String>] = [:]
    /// Tenants whose first page was the small one and whose next page starts the large
    /// walk from the beginning.
    private var freshWalkPending: Set<String> = []
    /// Whether Graph accepted `startswith` on deviceName, once asked. Nil until then.
    private var prefixLookupWorks: Bool?

    /// Moves on every first-page load and every reset. A page that was asked for under an
    /// older generation is dropped when it arrives, so a refresh or a reset can never be
    /// followed by a stale page appended to the fresh list or overwriting its next link.
    private var generation = 0

    /// - pageSize: the first page. 100 keeps it fast on a phone.
    /// - fillPageSize: every page after it. Larger pages are fewer round trips: 20,000
    ///   devices in 20 requests rather than 200. Graph documents no maximum for this
    ///   resource; if it returns fewer, the walk simply takes more pages.
    /// - session: the signed-in session's shared one; tests pass their own.
    public init(auth: AuthManaging, pageSize: Int = 100, fillPageSize: Int = 1000, session: URLSession? = nil) {
        self.auth = auth
        self.session = session ?? InventoryHTTP.makeSession()
        self.pageSize = max(1, min(pageSize, 1000))
        self.fillPageSize = max(self.pageSize, min(fillPageSize, 1000))
    }

    // MARK: - fetching

    /// Fetches the first page, replacing any cached inventory for the current tenant.
    /// Call on initial load and on pull-to-refresh.
    @discardableResult
    public func loadFirstPage() async throws -> DevicePage {
        generation += 1
        let asked = generation
        let tenantId = try await currentTenantId()
        let page = try await fetch(url: InventoryHTTP.firstPageURL(pageSize: pageSize), pageSize: pageSize)
        // A newer load or a reset happened while this one was out. It owns the cache now.
        guard asked == generation else { return page }
        let unique = Self.unique(page.devices, known: [])
        cache[tenantId] = unique.devices
        knownIds[tenantId] = unique.ids
        nextLinkByTenant[tenantId] = page.nextLink
        // More to come, in pages larger than this one: the next page starts that walk.
        if page.nextLink != nil, fillPageSize > pageSize {
            freshWalkPending.insert(tenantId)
        } else {
            freshWalkPending.remove(tenantId)
        }
        return DevicePage(devices: unique.devices, nextLink: page.nextLink)
    }

    /// Fetches the next page and appends what it adds. Returns nil when there is nothing
    /// more. The page returned holds only devices not already loaded.
    ///
    /// After a small first page, the first call starts the walk again from the beginning
    /// in large pages and skips the devices already on screen; a `nextLink` keeps the page
    /// size it was made with, so the small walk cannot simply be continued in large pages.
    @discardableResult
    public func loadNextPage() async throws -> DevicePage? {
        let asked = generation
        let tenantId = try await currentTenantId()
        let url: URL
        if freshWalkPending.contains(tenantId) {
            url = InventoryHTTP.firstPageURL(pageSize: fillPageSize)
        } else {
            guard let link = nextLinkByTenant[tenantId] ?? nil, let next = URL(string: link) else {
                return nil
            }
            // The bearer token goes with the request, so only a Graph link is followed.
            guard GraphClient.isPageLink(next) else { throw InventoryError.decodeFailure }
            url = next
        }
        let page = try await fetch(url: url, pageSize: fillPageSize)
        guard asked == generation else { throw CancellationError() }
        let unique = Self.unique(page.devices, known: knownIds[tenantId] ?? [])
        cache[tenantId, default: []].append(contentsOf: unique.devices)
        knownIds[tenantId] = unique.ids
        nextLinkByTenant[tenantId] = page.nextLink
        freshWalkPending.remove(tenantId)
        return DevicePage(devices: unique.devices, nextLink: page.nextLink)
    }

    /// The devices whose ids are not already known, in order, and the ids known after them.
    private static func unique(_ devices: [ManagedDeviceSummary], known: Set<String>) -> (devices: [ManagedDeviceSummary], ids: Set<String>) {
        var ids = known
        var out: [ManagedDeviceSummary] = []
        out.reserveCapacity(devices.count)
        for device in devices where ids.insert(device.id).inserted {
            out.append(device)
        }
        return (out, ids)
    }

    // MARK: - asking Graph directly

    /// Devices Graph finds for what was typed, for while the list is still loading and
    /// the devices already here match nothing. Exact matches on the device name, the
    /// serial number and the primary user's sign-in address, and names starting with it.
    ///
    /// Best effort and never interactive: a lookup that fails returns nothing. Graph
    /// documents no filter support for this resource, so `startswith` is tried once, and
    /// if Graph refuses it, not again this session. Every device returned is checked
    /// against the query here, because a filter Graph does not understand can come back
    /// ignored rather than refused, and the first devices of the tenant are not matches.
    public func lookup(_ query: String) async -> [ManagedDeviceSummary] {
        let typed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !typed.isEmpty, typed.count <= 120 else { return [] }
        let literal = "'" + typed.replacingOccurrences(of: "'", with: "''") + "'"
        var filters = ["deviceName eq " + literal, "serialNumber eq " + literal]
        if typed.contains("@") { filters.append("userPrincipalName eq " + literal) }
        let tryPrefix = prefixLookupWorks != false
        if tryPrefix { filters.append("startswith(deviceName," + literal + ")") }
        let prefixFilter = filters.last

        var found: [ManagedDeviceSummary] = []
        var prefixRefused = false
        await withTaskGroup(of: (filter: String, devices: [ManagedDeviceSummary]?, refused: Bool).self) { group in
            for filter in filters {
                group.addTask { [self] in
                    do {
                        let page = try await fetch(url: InventoryHTTP.listURL(top: 25, filter: filter), pageSize: 25)
                        return (filter, page.devices, false)
                    } catch InventoryError.transport(let status) where status == 400 {
                        return (filter, nil, true)
                    } catch {
                        return (filter, nil, false)
                    }
                }
            }
            for await result in group {
                if let devices = result.devices { found.append(contentsOf: devices) }
                if result.refused, tryPrefix, result.filter == prefixFilter { prefixRefused = true }
            }
        }
        if tryPrefix { prefixLookupWorks = !prefixRefused }

        let folded = typed.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
        var seen = Set<String>()
        return found.filter { device in
            guard seen.insert(device.id).inserted else { return false }
            let key = device.searchKey
            return key.name == folded || key.name.hasPrefix(folded) || key.others.contains(folded)
        }
    }

    private func fetch(url: URL, pageSize: Int) async throws -> DevicePage {
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
        knownIds.removeAll()
        freshWalkPending.removeAll()
    }

    private func currentTenantId() async throws -> String {
        guard let account = await auth.currentAccount else { throw InventoryError.consentRequired }
        return (await auth.operatingTenantId ?? account.tenantId).lowercased()
    }
}

// MARK: - search

/// Client-side search. Graph's managedDevices resource has no dependable server-side
/// substring search on deviceName, so filtering happens locally over the devices loaded.
///
/// Known limitation: "loaded" means the pages fetched so far. A device that exists but
/// has not been paged in will not be found. `InventoryFill` pages the rest in the
/// background for this reason, and the list asks Graph directly while it runs.
///
/// Performance: every device carries its fields folded once (`DeviceSearchKey`), so a
/// search is one substring check per device, and only the devices that pass are ranked.
/// It used to fold every field of every device on every keystroke, 56 ms over 20,000
/// devices in a release build on a Mac, several times that on a phone.
public enum DeviceSearch {

    private static let foldOptions: String.CompareOptions = [.caseInsensitive, .diacriticInsensitive]

    /// Normalises case and diacritics once, so later comparisons are ordinary string ops.
    private static func fold(_ s: String) -> String {
        s.folding(options: foldOptions, locale: nil)
    }

    /// Case- and diacritic-insensitive substring match across the fields an admin would
    /// actually type: device name, the primary user by real name, UPN or mail address,
    /// serial number, model, and Intune's own device name.
    public static func matches(_ device: ManagedDeviceSummary, query: String) -> Bool {
        let raw = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return true }
        return score(device.searchKey, foldedQuery: fold(raw)) != nil
    }

    /// Filters and orders results. Exact and prefix name matches sort above the rest,
    /// because an admin typing a device name usually wants that device first. An empty
    /// query is every device, by name.
    public static func filter(_ devices: [ManagedDeviceSummary], query: String) -> [ManagedDeviceSummary] {
        let raw = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return devices.sorted(by: inNameOrder) }
        return ranked(devices, foldedQuery: fold(raw)).map(\.device)
    }

    /// Adds devices to a list already in name order, keeping it in order: the newcomers
    /// are sorted, then both are walked once, instead of sorting everything again.
    public static func merged(_ sorted: [ManagedDeviceSummary], adding newcomers: [ManagedDeviceSummary]) -> [ManagedDeviceSummary] {
        merge(sorted, newcomers.sorted(by: inNameOrder), by: inNameOrder)
    }

    /// Adds devices to search results already in result order: only the newcomers are
    /// matched and ranked, then merged in. The same list `filter` would give for all of
    /// them together.
    public static func merged(results: [ManagedDeviceSummary], query: String,
                              adding newcomers: [ManagedDeviceSummary]) -> [ManagedDeviceSummary] {
        let raw = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return merged(results, adding: newcomers) }
        let q = fold(raw)
        let hits = ranked(newcomers, foldedQuery: q)
        guard !hits.isEmpty else { return results }
        let existing = results.map { (device: $0, rank: score($0.searchKey, foldedQuery: q) ?? Int.max) }
        return merge(existing, hits, by: inRankOrder).map(\.device)
    }

    /// Name order: the folded name, then the id, so equal names keep one order everywhere.
    /// A plain comparison of folded names rather than a locale-aware one; the two differ
    /// only on punctuation and accented letters, and this one costs a fraction as much.
    public static func inNameOrder(_ a: ManagedDeviceSummary, _ b: ManagedDeviceSummary) -> Bool {
        if a.searchKey.name != b.searchKey.name { return a.searchKey.name < b.searchKey.name }
        return a.id < b.id
    }

    private static func inRankOrder(_ a: (device: ManagedDeviceSummary, rank: Int),
                                    _ b: (device: ManagedDeviceSummary, rank: Int)) -> Bool {
        if a.rank != b.rank { return a.rank < b.rank }
        return inNameOrder(a.device, b.device)
    }

    /// Matches and ranks in one pass, so no device is examined twice and no rank is
    /// recomputed inside the comparator.
    private static func ranked(_ devices: [ManagedDeviceSummary], foldedQuery q: String) -> [(device: ManagedDeviceSummary, rank: Int)] {
        var scored: [(device: ManagedDeviceSummary, rank: Int)] = []
        for device in devices {
            if let rank = score(device.searchKey, foldedQuery: q) {
                scored.append((device, rank))
            }
        }
        scored.sort(by: inRankOrder)
        return scored
    }

    private static func merge<T>(_ a: [T], _ b: [T], by before: (T, T) -> Bool) -> [T] {
        guard !b.isEmpty else { return a }
        guard !a.isEmpty else { return b }
        var out: [T] = []
        out.reserveCapacity(a.count + b.count)
        var i = 0
        var j = 0
        while i < a.count, j < b.count {
            if before(b[j], a[i]) {
                out.append(b[j])
                j += 1
            } else {
                out.append(a[i])
                i += 1
            }
        }
        out.append(contentsOf: a[i...])
        out.append(contentsOf: b[j...])
        return out
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
    private static func score(_ key: DeviceSearchKey, foldedQuery q: String) -> Int? {
        // Most devices do not match at all; one check rules them out.
        guard key.all.contains(q) else { return nil }

        var best: Int?

        if let s = strength(key.name, q) {
            // Exact on the device name is the best possible outcome; stop looking.
            if s == 0 { return 0 }
            best = s * 2
        }

        for field in key.others {
            guard let s = strength(field, q) else { continue }
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
