import Foundation

// The seam between the Digest screen and the public feeds, so the screen can be built
// and reviewed against demo data and tested without the network.

public protocol ThreatDigestProviding: Sendable {
    /// Every source fetched, merged and returned with each source's outcome. A source
    /// that fails is reported, not thrown: the others still render.
    func digest() async throws -> DigestSnapshot
}

/// Fetches the feeds. Foundation only, an ephemeral session, a fixed host allowlist, a
/// size cap, and nothing in the request but the URL and an Accept header. No cookies,
/// no token, no identifier of any kind.
public actor ThreatDigestService: ThreatDigestProviding {

    public static let allowedHosts: Set<String> = ["www.cisa.gov", "api.msrc.microsoft.com"]
    /// Bytes. The KEV catalog is under two megabytes and the advisories feed under two;
    /// anything past this is a feed that changed shape, not something to parse.
    public static let maxBytes = 8_000_000
    public static let kevWindowDays = 60
    public static let msrcWindowDays = 30

    private let session: URLSession
    private let now: @Sendable () -> Date
    private let byteLimit: Int

    /// - byteLimit: injected by tests so the cap can be crossed without megabytes of input.
    public init(session: URLSession? = nil, now: @escaping @Sendable () -> Date = { Date() }, byteLimit: Int = ThreatDigestService.maxBytes) {
        self.session = session ?? Self.makeSession()
        self.now = now
        self.byteLimit = byteLimit
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
        let at = now()
        async let kev = fetchKEV(now: at)
        async let msrc = fetchMSRC(now: at)
        async let alerts = fetchRSS(CISAFeeds.alerts, source: .cisaAlert)
        async let advisories = fetchRSS(CISAFeeds.advisories, source: .cisaAdvisory)
        let results = await [kev, msrc, alerts, advisories]
        let items = DigestMerge.merge(
            kev: results[0].items, msrc: results[1].items, alerts: results[2].items, advisories: results[3].items)
        return DigestSnapshot(items: items, statuses: results.map(\.status), fetchedAt: at)
    }

    struct SourceResult {
        var items: [DigestItem]
        var status: DigestSourceStatus
    }

    private func fetchKEV(now: Date) async -> SourceResult {
        await fetch(KEVCatalog.url, source: .kev) { data in
            let catalog = try JSONDecoder().decode(KEVCatalog.self, from: data)
            return catalog.items(addedWithinDays: Self.kevWindowDays, now: now)
        }
    }

    private func fetchMSRC(now: Date) async -> SourceResult {
        let since = now.addingTimeInterval(-TimeInterval(Self.msrcWindowDays) * 86_400)
        return await fetch(MSRCPage.url(since: since), source: .msrc) { data in
            try JSONDecoder().decode(MSRCPage.self, from: data).items
        }
    }

    private func fetchRSS(_ url: URL, source: DigestSource) async -> SourceResult {
        await fetch(url, source: source) { data in
            CISAFeeds.items(RSSReader.read(data), source: source)
        }
    }

    private func fetch(_ url: URL, source: DigestSource, _ decode: (Data) throws -> [DigestItem]) async -> SourceResult {
        do {
            let data = try await get(url)
            let items = try decode(data)
            return SourceResult(items: items, status: DigestSourceStatus(source: source, state: .ok(itemCount: items.count)))
        } catch let error as DigestError {
            return SourceResult(items: [], status: DigestSourceStatus(source: source, state: .unavailable(reason: Self.describe(error))))
        } catch is DecodingError {
            return SourceResult(items: [], status: DigestSourceStatus(source: source, state: .unavailable(reason: Self.describe(.decodeFailure))))
        } catch {
            let offline = (error as? URLError).map { [.notConnectedToInternet, .networkConnectionLost, .cannotFindHost, .cannotConnectToHost, .timedOut].contains($0.code) } ?? false
            return SourceResult(items: [], status: DigestSourceStatus(source: source, state: .unavailable(reason: Self.describe(offline ? .offline : .transport(status: 0)))))
        }
    }

    /// One GET. The host check is here, on the URL about to be sent, not on a constant
    /// somewhere else, so a typo cannot widen where this target talks to; and again on every
    /// redirect, which URLSession would otherwise follow to any host on its own.
    ///
    /// The size cap is enforced while reading, so a feed that grew is abandoned at the cap
    /// rather than read into memory whole and refused afterwards.
    func get(_ url: URL) async throws -> Data {
        guard Self.isAllowed(url) else { throw DigestError.hostNotAllowed(url.host ?? "") }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
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
        guard (200..<300).contains(http.statusCode) else { throw DigestError.transport(status: http.statusCode) }
        guard http.expectedContentLength <= Int64(byteLimit) else { throw DigestError.tooLarge }

        var body: [UInt8] = []
        body.reserveCapacity(http.expectedContentLength > 0 ? Int(http.expectedContentLength) : 64 * 1024)
        for try await byte in bytes {
            body.append(byte)
            if body.count > byteLimit { throw DigestError.tooLarge }
        }
        return Data(body)
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
            lock.lock(); defer { lock.unlock() }
            return refused
        }

        func urlSession(
            _ session: URLSession, task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest
        ) async -> URLRequest? {
            guard let url = request.url, ThreatDigestService.isAllowed(url) else {
                lock.lock(); refused = request.url?.host ?? ""; lock.unlock()
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
