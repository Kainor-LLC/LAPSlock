import Foundation
import AuthKit
import CredentialKit

// Build Spec §2.2, §5, §7, §8 — device inventory fetching.
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

    /// Fields the list UI actually needs. `azureADDeviceId` is the important one — it is
    /// the Entra device id Windows LAPS reveal keys on, and it arrives here directly
    /// rather than requiring a second lookup (see ManagedDeviceSummary header).
    static let selectFields = [
        "id",
        "deviceName",
        "operatingSystem",
        "osVersion",
        "azureADDeviceId",
        "userPrincipalName",
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
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return withFraction.date(from: s) ?? ISO8601DateFormatter().date(from: s)
    }
}

public actor DeviceInventoryService {
    public static let requiredScopes = [LapsCredentialScopes.intuneDevices]

    private let auth: AuthManaging
    private let session: URLSession
    private let pageSize: Int

    /// Cached devices keyed by tenant id, so a session in one tenant can never render
    /// another tenant's inventory.
    private var cache: [String: [ManagedDeviceSummary]] = [:]
    private var nextLinkByTenant: [String: String?] = [:]

    public init(auth: AuthManaging, pageSize: Int = 100) {
        self.auth = auth
        self.session = InventoryHTTP.makeSession()
        // Graph accepts up to 1000; 100 keeps the first page fast on a phone.
        self.pageSize = max(1, min(pageSize, 1000))
    }

    // MARK: - fetching

    /// Fetches the first page, replacing any cached inventory for the current tenant.
    /// Call on initial load and on pull-to-refresh.
    @discardableResult
    public func loadFirstPage() async throws -> DevicePage {
        let tenantId = try await currentTenantId()
        let page = try await fetch(url: InventoryHTTP.firstPageURL(pageSize: pageSize))
        cache[tenantId] = page.devices
        nextLinkByTenant[tenantId] = page.nextLink
        return page
    }

    /// Fetches the next page and appends it. Returns nil when there is nothing more.
    @discardableResult
    public func loadNextPage() async throws -> DevicePage? {
        let tenantId = try await currentTenantId()
        guard let link = nextLinkByTenant[tenantId] ?? nil, let url = URL(string: link) else {
            return nil
        }
        let page = try await fetch(url: url)
        cache[tenantId, default: []].append(contentsOf: page.devices)
        nextLinkByTenant[tenantId] = page.nextLink
        return page
    }

    /// Pages until exhausted, up to `maxPages`. Client-side search needs the full set
    /// (Graph's managedDevices does not support a usable server-side name search), so
    /// this backstops very large tenants rather than paging forever.
    @discardableResult
    public func loadAll(maxPages: Int = 50) async throws -> [ManagedDeviceSummary] {
        _ = try await loadFirstPage()
        var pages = 1
        while pages < maxPages, try await loadNextPage() != nil {
            pages += 1
        }
        return try await cachedDevices()
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
        cache.removeAll()
        nextLinkByTenant.removeAll()
    }

    private func currentTenantId() async throws -> String {
        guard let account = await auth.currentAccount else { throw InventoryError.consentRequired }
        return account.tenantId
    }
}

// MARK: - search

/// Client-side search. Graph's managedDevices resource has no dependable server-side
/// substring search on deviceName, so filtering happens locally over the cached page set.
public enum DeviceSearch {

    /// Case- and diacritic-insensitive substring match across the fields an admin would
    /// actually type: device name, primary user, serial number, and model.
    public static func matches(_ device: ManagedDeviceSummary, query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return true }

        let haystacks = [
            device.deviceName,
            device.userPrincipalName,
            device.serialNumber,
            device.model
        ].compactMap { $0 }

        return haystacks.contains { field in
            field.range(of: q, options: [.caseInsensitive, .diacriticInsensitive]) != nil
        }
    }

    /// Filters and orders results. Exact and prefix name matches sort above the rest,
    /// because an admin typing a device name usually wants that device first.
    public static func filter(_ devices: [ManagedDeviceSummary], query: String) -> [ManagedDeviceSummary] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else {
            return devices.sorted { $0.deviceName.localizedCaseInsensitiveCompare($1.deviceName) == .orderedAscending }
        }

        let hits = devices.filter { matches($0, query: q) }
        return hits.sorted { a, b in
            let ra = rank(a, query: q)
            let rb = rank(b, query: q)
            if ra != rb { return ra < rb }
            return a.deviceName.localizedCaseInsensitiveCompare(b.deviceName) == .orderedAscending
        }
    }

    private static func rank(_ device: ManagedDeviceSummary, query: String) -> Int {
        let name = device.deviceName
        if name.compare(query, options: [.caseInsensitive, .diacriticInsensitive]) == .orderedSame { return 0 }
        if name.range(of: query, options: [.caseInsensitive, .diacriticInsensitive, .anchored]) != nil { return 1 }
        if name.range(of: query, options: [.caseInsensitive, .diacriticInsensitive]) != nil { return 2 }
        return 3
    }
}
