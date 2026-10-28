import Foundation

// The seam between the Digest screen and the public feeds, so the screen can be built
// and reviewed against demo data and tested without the network.

public protocol ThreatDigestProviding: Sendable {
    /// Every source fetched, merged and returned with each source's outcome. A source
    /// that fails is reported, not thrown: the others still render. A provider may answer
    /// with a digest it read moments ago.
    func digest() async throws -> DigestSnapshot
    /// The same, asking every feed again now: pull to refresh.
    func refreshedDigest() async throws -> DigestSnapshot
    /// The last digest this provider has, from memory or from its copies on disk, without
    /// the network. Nil when there is none. For a first paint while `digest()` reads.
    func lastDigest() async -> DigestSnapshot?
}

public extension ThreatDigestProviding {
    func refreshedDigest() async throws -> DigestSnapshot { try await digest() }
    func lastDigest() async -> DigestSnapshot? { nil }
}

/// Fetches the feeds. Foundation only, an ephemeral session, a fixed host allowlist, a
/// size cap, and nothing in the request but the URL, an Accept header and, on a repeat
/// read, the validator the feed's own server sent for that file. No cookies, no token,
/// no identifier of any kind.
///
/// The digest lasts for the life of the app, not of a signed-in session (OPTIMIZATION-PLAN.md,
/// step G, decision 7). The feeds are public and nothing about a tenant goes with them, so
/// a tenant switch has no reason to read them again. A digest is reused for `freshFor`;
/// after that, or on pull to refresh, each feed is asked whether it changed, and a 304
/// reuses the copy already held. The last good copy of each feed is kept in Caches, so a
/// cold launch shows the digest at once and offline. Public data only.
public actor ThreatDigestService: ThreatDigestProviding {

    public static let allowedHosts: Set<String> = ["www.cisa.gov", "api.msrc.microsoft.com"]
    /// Bytes. The KEV catalog is under two megabytes and the advisories feed under two;
    /// anything past this is a feed that changed shape, not something to parse.
    public static let maxBytes = 8_000_000
    public static let kevWindowDays = 60
    public static let msrcWindowDays = 30
    /// How long a digest is reused before the feeds are asked again.
    public static let freshFor: TimeInterval = 15 * 60

    private let session: URLSession
    private let now: @Sendable () -> Date
    private let byteLimit: Int
    private let cacheDirectory: URL?

    /// What each feed last answered, with the validators to ask it again conditionally.
    private var held: [DigestSource: (meta: Held, data: Data)] = [:]
    private var lastSnapshot: DigestSnapshot?
    private var diskRead = false

    struct Held: Codable, Sendable {
        var url: URL
        var etag: String?
        var lastModified: String?
        var readAt: Date
    }

    /// One for the process. The feeds are public and nothing about a tenant goes with them,
    /// so there is no reason to open new connections for each signed-in session.
    public static let sharedSession = makeSession()

    /// The digest the app uses, for the life of the process, with its copies on disk.
    public static let shared = ThreatDigestService(cacheDirectory: defaultCacheDirectory)

    /// Caches/ThreatDigest: the public feeds' last good payloads. The system may clear it.
    public static var defaultCacheDirectory: URL? {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?
            .appendingPathComponent("ThreatDigest", isDirectory: true)
    }

    /// - session: injected by tests. Nil uses `sharedSession`.
    /// - byteLimit: injected by tests so the cap can be crossed without megabytes of input.
    /// - cacheDirectory: where the last good copies go. Nil keeps them in memory only.
    public init(
        session: URLSession? = nil,
        now: @escaping @Sendable () -> Date = { Date() },
        byteLimit: Int = ThreatDigestService.maxBytes,
        cacheDirectory: URL? = nil
    ) {
        self.session = session ?? Self.sharedSession
        self.now = now
        self.byteLimit = byteLimit
        self.cacheDirectory = cacheDirectory
    }

    public static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        config.timeoutIntervalForRequest = 20
        config.timeoutIntervalForResource = 60
        config.waitsForConnectivity = false
        config.httpAdditionalHeaders = ["Accept": "application/json, application/rss+xml, application/xml;q=0.9, */*;q=0.1"]
        return URLSession(configuration: config)
    }

    public func digest() async throws -> DigestSnapshot {
        if let lastSnapshot, now().timeIntervalSince(lastSnapshot.fetchedAt) < Self.freshFor { return lastSnapshot }
        return try await refreshedDigest()
    }

    public func refreshedDigest() async throws -> DigestSnapshot {
        readDiskOnce()
        let at = now()
        async let kev = read(.kev, at: at)
        async let msrc = read(.msrc, at: at)
        async let alerts = read(.cisaAlert, at: at)
        async let advisories = read(.cisaAdvisory, at: at)
        let snapshot = Self.snapshot(await [kev, msrc, alerts, advisories], at: at)
        lastSnapshot = snapshot
        return snapshot
    }

    public func lastDigest() async -> DigestSnapshot? {
        if let lastSnapshot { return lastSnapshot }
        readDiskOnce()
        guard let oldest = held.values.map(\.meta.readAt).min() else { return nil }
        let results = [DigestSource.kev, .msrc, .cisaAlert, .cisaAdvisory].map { source -> SourceResult in
            guard let copy = held[source], let items = try? Self.decode(source, copy.data, now: oldest) else {
                return SourceResult(items: [], status: DigestSourceStatus(source: source, state: .unavailable(reason: "Not read yet.")))
            }
            return SourceResult(items: items, status: DigestSourceStatus(source: source, state: .ok(itemCount: items.count)))
        }
        return Self.snapshot(results, at: oldest)
    }

    struct SourceResult {
        var items: [DigestItem]
        var status: DigestSourceStatus
    }

    private static func snapshot(_ results: [SourceResult], at: Date) -> DigestSnapshot {
        let items = DigestMerge.merge(
            kev: results[0].items, msrc: results[1].items, alerts: results[2].items, advisories: results[3].items)
        return DigestSnapshot(items: items, statuses: results.map(\.status), fetchedAt: at)
    }

    static func url(for source: DigestSource, now: Date) -> URL {
        switch source {
        case .kev:          return KEVCatalog.url
        // From the start of the day, so the address, and with it the validator, holds
        // for the whole day rather than changing with every second.
        case .msrc:         return MSRCPage.url(since: startOfDay(now.addingTimeInterval(-TimeInterval(msrcWindowDays) * 86_400)))
        case .cisaAlert:    return CISAFeeds.alerts
        case .cisaAdvisory: return CISAFeeds.advisories
        }
    }

    static func decode(_ source: DigestSource, _ data: Data, now: Date) throws -> [DigestItem] {
        switch source {
        case .kev:          return try JSONDecoder().decode(KEVCatalog.self, from: data).items(addedWithinDays: kevWindowDays, now: now)
        case .msrc:         return try JSONDecoder().decode(MSRCPage.self, from: data).items
        case .cisaAlert, .cisaAdvisory: return CISAFeeds.items(RSSReader.read(data), source: source)
        }
    }

    private static func startOfDay(_ date: Date) -> Date {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.startOfDay(for: date)
    }

    /// One feed: asked conditionally when a copy of the same address is held. A feed that
    /// fails falls back to the last good copy, said so in its status.
    private func read(_ source: DigestSource, at: Date) async -> SourceResult {
        let url = Self.url(for: source, now: at)
        let previous = held[source].flatMap { $0.meta.url == url ? $0 : nil }
        do {
            let answer = try await exchange(url, etag: previous?.meta.etag, lastModified: previous?.meta.lastModified)
            let data: Data
            if answer.notModified {
                guard let previous else { throw DigestError.transport(status: 304) }
                data = previous.data
                held[source]?.meta.readAt = at
            } else {
                data = answer.data
            }
            let items = try Self.decode(source, data, now: at)
            if !answer.notModified {
                keep(source, Held(url: url, etag: answer.etag, lastModified: answer.lastModified, readAt: at), data)
            }
            return SourceResult(items: items, status: DigestSourceStatus(source: source, state: .ok(itemCount: items.count)))
        } catch {
            let reason = Self.describe(Self.digestError(error))
            if let copy = held[source], let items = try? Self.decode(source, copy.data, now: at) {
                return SourceResult(items: items, status: DigestSourceStatus(source: source, state: .unavailable(reason: reason + " Showing the last copy read.")))
            }
            return SourceResult(items: [], status: DigestSourceStatus(source: source, state: .unavailable(reason: reason)))
        }
    }

    private static func digestError(_ error: Error) -> DigestError {
        if let digest = error as? DigestError { return digest }
        if error is DecodingError { return .decodeFailure }
        let offline = (error as? URLError).map { [.notConnectedToInternet, .networkConnectionLost, .cannotFindHost, .cannotConnectToHost, .timedOut].contains($0.code) } ?? false
        return offline ? .offline : .transport(status: 0)
    }

    // MARK: - the copies on disk

    private func readDiskOnce() {
        guard !diskRead else { return }
        diskRead = true
        guard let directory = cacheDirectory else { return }
        for source in DigestSource.allCases where held[source] == nil {
            guard let metaData = try? Data(contentsOf: directory.appendingPathComponent(source.rawValue + ".json")),
                  let meta = try? JSONDecoder().decode(Held.self, from: metaData),
                  let data = try? Data(contentsOf: directory.appendingPathComponent(source.rawValue + ".data"))
            else { continue }
            held[source] = (meta, data)
        }
    }

    /// Kept only once it decoded, so a broken payload never replaces a good one.
    private func keep(_ source: DigestSource, _ meta: Held, _ data: Data) {
        held[source] = (meta, data)
        guard let directory = cacheDirectory else { return }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? data.write(to: directory.appendingPathComponent(source.rawValue + ".data"), options: .atomic)
        if let encoded = try? JSONEncoder().encode(meta) {
            try? encoded.write(to: directory.appendingPathComponent(source.rawValue + ".json"), options: .atomic)
        }
    }

    // MARK: - the request

    struct Answer {
        var data: Data
        var notModified: Bool
        var etag: String?
        var lastModified: String?
    }

    /// One GET, for tests and anything that wants the body alone.
    func get(_ url: URL) async throws -> Data {
        try await exchange(url).data
    }

    /// One GET. The host check is here, on the URL about to be sent, not on a constant
    /// somewhere else, so a typo cannot widen where this target talks to; and again on every
    /// redirect, which URLSession would otherwise follow to any host on its own.
    ///
    /// The size cap is enforced while reading, so a feed that grew is abandoned at the cap
    /// rather than read into memory whole and refused afterwards.
    func exchange(_ url: URL, etag: String? = nil, lastModified: String? = nil) async throws -> Answer {
        guard Self.isAllowed(url) else { throw DigestError.hostNotAllowed(url.host ?? "") }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        if let etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
        if let lastModified { request.setValue(lastModified, forHTTPHeaderField: "If-Modified-Since") }
        let redirects = RedirectGuard()
        let bytes: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (bytes, response) = try await session.bytes(for: request, delegate: redirects)
        } catch {
            // A refused redirect can surface as the 3xx itself or as a failed load,
            // depending on the loading path. Either way it is the refusal that matters.
            if let refused = redirects.refusedHost { throw DigestError.hostNotAllowed(refused) }
            throw error
        }
        if let refused = redirects.refusedHost { throw DigestError.hostNotAllowed(refused) }
        guard let http = response as? HTTPURLResponse else { throw DigestError.transport(status: 0) }
        if http.statusCode == 304, etag != nil || lastModified != nil {
            return Answer(data: Data(), notModified: true)
        }
        guard (200..<300).contains(http.statusCode) else { throw DigestError.transport(status: http.statusCode) }
        guard http.expectedContentLength <= Int64(byteLimit) else { throw DigestError.tooLarge }

        var body: [UInt8] = []
        body.reserveCapacity(http.expectedContentLength > 0 ? Int(http.expectedContentLength) : 64 * 1024)
        for try await byte in bytes {
            body.append(byte)
            if body.count > byteLimit { throw DigestError.tooLarge }
        }
        return Answer(
            data: Data(body), notModified: false,
            etag: http.value(forHTTPHeaderField: "ETag"),
            lastModified: http.value(forHTTPHeaderField: "Last-Modified"))
    }

    static func isAllowed(_ url: URL) -> Bool {
        guard let host = url.host?.lowercased() else { return false }
        return allowedHosts.contains(host) && url.scheme?.lowercased() == "https"
    }

    /// Refuses any redirect that leaves the allowlist, and remembers where it pointed so the
    /// refusal is reported as one rather than as a strange status.
    private final class RedirectGuard: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        private let lock = NSLock()
        private var refused: String?

        var refusedHost: String? {
            lock.withLock { refused }
        }

        func urlSession(
            _ session: URLSession, task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest
        ) async -> URLRequest? {
            guard let url = request.url, ThreatDigestService.isAllowed(url) else {
                lock.withLock { refused = request.url?.host ?? "" }
                return nil
            }
            return request
        }
    }

    public static func describe(_ error: DigestError) -> String {
        switch error {
        case .hostNotAllowed(let host): return "Refused: " + host + " is not a digest source."
        case .transport(let status):    return status == 0 ? "The feed did not answer." : "The feed answered with an error (\(status))."
        case .tooLarge:                 return "The feed is larger than expected and was not read."
        case .decodeFailure:            return "The feed changed shape and could not be read."
        case .offline:                  return "No connection."
        }
    }
}
