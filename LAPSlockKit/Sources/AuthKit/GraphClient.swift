import Foundation

// The Graph client for the modules that read tenant state: sign-in triage, tenant pulse,
// Conditional Access, and whatever follows. Build Spec section 3.4 asked for one client in
// AuthKit for non-sensitive calls; until now each Kit carried its own session, its own
// validate and its own 429 handling. New modules use this one. The three existing Kits are
// deliberately NOT moved onto it: the credential path is verified on hardware and stays as
// it is.
//
// What it is not for: credentials. CredentialKit keeps its own fetch, which parses a
// password straight into a SensitiveValue and never hands a response body to a general
// decoder. Nothing here should ever be given a scope that can read one.
//
// Foundation only, no logging framework. AuthKit sits inside CredentialKit's link graph, so
// a logger here would be a logger there. What diagnostics may know travels through
// `observer`: the path TEMPLATE, the API version, the method, the status and the duration.
// Never a URL with an identifier in it, never a header, never a body.
//
// Rules carried in code rather than in a comment:
//   * The API version is pinned per request and is part of the record, because Graph moves
//     endpoints between beta and v1.0 and changes shapes when it does.
//   * 429 is retried for GET only, honouring Retry-After up to a cap, a bounded number of
//     times, and so is a POST that only reads and says so (`readOnly`). A 503 or 504 on
//     either is retried once. A write is never retried by this client; whoever owns the
//     write decides. One 429 slows every read this client sends until its wait is over.
//   * Every failing response records its request-id in GraphResponseTracer, because that
//     id is the first thing Microsoft support asks for.
//   * The session is ephemeral: no disk cache, no cookies. Nothing the networking layer
//     sees is written to the app container.
//
// Not handled yet, on purpose: a claims challenge on a read. Conditional Access can demand
// an authentication context on Graph reads too, and it arrives as a 401 with a claims
// parameter. Here that maps to consentRequired, which is wrong in detail and right in
// effect, the module re-requests interactively and MSAL carries the claims. Revisit when a
// read-only module meets one on a real tenant.

public enum GraphAPIVersion: String, Sendable, Equatable, CaseIterable {
    case v1_0 = "v1.0"
    case beta = "beta"
}

public struct GraphRequest: Sendable, Equatable {
    public enum Method: String, Sendable, Equatable {
        case get = "GET"
        case post = "POST"
        case patch = "PATCH"
        case delete = "DELETE"

        /// Anything but a GET changes something, so it is never retried and only the
        /// write gate may send it.
        public var isWrite: Bool { self != .get }
    }

    public var method: Method
    public var version: GraphAPIVersion
    /// Path under the version segment, with a leading slash:
    /// `/identity/conditionalAccess/policies`.
    public var path: String
    /// What the observer sees. Defaults to the path. Pass one whenever the path carries an
    /// identifier, so a diagnostics report says `/users/{id}` and not whose id it was.
    public var template: String
    public var query: [URLQueryItem]
    public var headers: [String: String]
    public var body: Data?
    /// Delegated scopes to acquire a token for. A module declares them once and passes the
    /// same list on every call, which is what makes incremental consent predictable.
    public var scopes: [String]
    /// Silent by default. A module turns this on for exactly one call, the first after the
    /// user opened it, so the consent prompt appears at a moment that makes sense.
    public var allowInteractive: Bool
    /// A claims challenge to satisfy when acquiring the token, as the JSON Graph sent.
    /// Set by a write's explicit resume after a challenge and by nothing else.
    public var claims: String?
    /// A POST that only reads, such as `getByIds` or an advanced hunting query. It gives
    /// that POST a GET's retries. Set by the Kit that builds such a read and by nothing
    /// else: `ActionRunner` refuses any request carrying it, so a write cannot borrow it.
    public var readOnly: Bool

    /// Whether this client may send it again: a GET, or a POST marked `readOnly`. Never a
    /// PATCH or DELETE, whatever the flag says.
    public var isRetryable: Bool {
        method == .get || (method == .post && readOnly)
    }

    public init(
        method: Method = .get,
        version: GraphAPIVersion = .v1_0,
        path: String,
        template: String? = nil,
        query: [URLQueryItem] = [],
        headers: [String: String] = [:],
        body: Data? = nil,
        scopes: [String],
        allowInteractive: Bool = false,
        claims: String? = nil,
        readOnly: Bool = false
    ) {
        self.method = method
        self.version = version
        self.path = path.hasPrefix("/") ? path : "/" + path
        self.template = template ?? self.path
        self.query = query
        self.headers = headers
        self.body = body
        self.scopes = scopes
        self.allowInteractive = allowInteractive
        self.claims = claims
        self.readOnly = readOnly
    }
}

public enum GraphError: Error, Sendable, Equatable {
    /// 401, or no token could be acquired silently. The module re-requests with
    /// `allowInteractive` on, once, and then stops.
    case consentRequired
    /// 403. The scope is consented but the signed-in admin's role does not cover it, or a
    /// licence is missing. Graph does not say which; the module's copy has to.
    case notAuthorized
    case notFound
    /// 400, with Graph's own error code when it sent one. The code is an identifier such as
    /// `Request_UnsupportedQuery` and is safe to record; the message beside it is prose and
    /// is dropped here.
    case badRequest(code: String?)
    /// 429 after the retry budget, or on a write, which is never retried.
    case throttled(retryAfter: TimeInterval?)
    case serviceUnavailable(status: Int)
    /// No HTTP response, or a status nothing above claims. -1 when nothing arrived.
    case transport(status: Int)
    case decodeFailure
    case cancelled
}

/// What the app layer may learn about a call. Typed fields only, by construction.
public struct GraphCallRecord: Sendable, Equatable {
    public let template: String
    public let version: GraphAPIVersion
    public let method: GraphRequest.Method
    /// Nil when no response arrived.
    public let httpStatus: Int?
    public let durationMs: Int
    /// How many times the request was sent again before this outcome: 429s waited out,
    /// and a 503 or 504 retried.
    public let retries: Int

    public init(template: String, version: GraphAPIVersion, method: GraphRequest.Method,
                httpStatus: Int?, durationMs: Int, retries: Int) {
        self.template = template
        self.version = version
        self.method = method
        self.httpStatus = httpStatus
        self.durationMs = durationMs
        self.retries = retries
    }
}

public struct GraphResponse: Sendable {
    public let status: Int
    public let data: Data
    /// Graph's `request-id`, for a support case.
    public let requestId: String?
    /// The response headers, for the one caller that needs them: a write reading a claims
    /// challenge out of `WWW-Authenticate`. Empty on the validated path.
    public let headers: [String: String]

    public init(status: Int, data: Data, requestId: String?, headers: [String: String] = [:]) {
        self.status = status
        self.data = data
        self.requestId = requestId
        self.headers = headers
    }
}

/// Items gathered across pages, and whether the walk stopped before the end.
public struct GraphCollection<Item: Sendable>: Sendable {
    public let items: [Item]
    /// Where the next page would come from, when the page budget ran out first.
    public let nextLink: URL?
    public var truncated: Bool { nextLink != nil }

    public init(items: [Item], nextLink: URL?) {
        self.items = items
        self.nextLink = nextLink
    }
}

public struct GraphRetryPolicy: Sendable, Equatable {
    /// 429 retries on a retryable request. Writes get none regardless.
    public var maxRetries: Int
    /// Longest Retry-After honoured. Graph can ask for minutes; an admin on a phone will
    /// not wait that long for a list, so beyond this the module hears about it instead.
    public var maxWait: TimeInterval
    /// Wait when Graph sent no Retry-After, or one that could not be read.
    public var defaultWait: TimeInterval
    /// Retries for a 503 or 504 on a retryable request: Graph's brief unavailability, which
    /// a second attempt usually gets past.
    public var serviceRetries: Int

    public init(maxRetries: Int, maxWait: TimeInterval, defaultWait: TimeInterval, serviceRetries: Int = 1) {
        self.maxRetries = maxRetries
        self.maxWait = maxWait
        self.defaultWait = defaultWait
        self.serviceRetries = serviceRetries
    }

    public static let standard = GraphRetryPolicy(maxRetries: 2, maxWait: 10, defaultWait: 2)
    public static let none = GraphRetryPolicy(maxRetries: 0, maxWait: 0, defaultWait: 0, serviceRetries: 0)
}

public final class GraphClient: Sendable {

    public typealias Sleeper = @Sendable (TimeInterval) async throws -> Void
    public typealias Observer = @Sendable (GraphCallRecord) -> Void
    /// Extra seconds added to a wait of the given length.
    public typealias Jitter = @Sendable (TimeInterval) -> TimeInterval

    public static let defaultBase = URL(string: "https://graph.microsoft.com")!

    public static let systemSleep: Sleeper = { seconds in
        try await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
    }

    /// Up to a fifth more, so reads that were throttled together do not all come back in
    /// the same instant and get throttled again.
    public static let systemJitter: Jitter = { wait in
        wait > 0 ? Double.random(in: 0...(wait * 0.2)) : 0
    }

    private let auth: any AuthManaging
    private let base: URL
    private let session: URLSession
    private let retryPolicy: GraphRetryPolicy
    private let observer: Observer?
    private let tracer: GraphResponseTracer
    private let sleep: Sleeper
    private let jitter: Jitter
    private let throttle = Throttle()

    /// - Parameters:
    ///   - session: the app passes the signed-in session's one session, so every service
    ///     reuses its connections; tests pass their own. Nil builds an ephemeral one.
    ///   - observer: receives one record per call, success or failure. The app wires it to
    ///     the diagnostics recorder; the Kits never see it.
    ///   - sleep: injected by tests so a 429 retry does not actually wait.
    ///   - jitter: injected by tests so a wait is exact.
    public init(
        auth: any AuthManaging,
        base: URL = GraphClient.defaultBase,
        session: URLSession? = nil,
        retryPolicy: GraphRetryPolicy = .standard,
        observer: Observer? = nil,
        tracer: GraphResponseTracer = .shared,
        sleep: @escaping Sleeper = GraphClient.systemSleep,
        jitter: @escaping Jitter = GraphClient.systemJitter
    ) {
        self.auth = auth
        self.base = base
        self.session = session ?? Self.makeSession()
        self.retryPolicy = retryPolicy
        self.observer = observer
        self.tracer = tracer
        self.sleep = sleep
        self.jitter = jitter
    }

    /// When this client was last told to slow down. Every retryable request waits it out
    /// before going, so a burst of reads after a 429 waits once together instead of each
    /// meeting its own 429. Writes never wait on it: they go when the admin confirmed.
    private actor Throttle {
        private var until: Date?

        func hold(for seconds: TimeInterval, from now: Date = Date()) {
            let end = now.addingTimeInterval(seconds)
            if until.map({ end > $0 }) ?? true { until = end }
        }

        func remaining(at now: Date = Date()) -> TimeInterval {
            guard let until else { return 0 }
            return max(0, until.timeIntervalSince(now))
        }
    }

    /// Ephemeral: no disk cache, no cookie store. Same shape as the sessions the existing
    /// Kits build, written once here.
    ///
    /// - timeout: seconds a request may wait for data. The background check passes less,
    ///   so one slow response cannot hold its run past iOS's thirty seconds.
    public static func makeSession(timeout: TimeInterval = 30) -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.urlCache = nil
        cfg.httpCookieStorage = nil
        cfg.httpCookieAcceptPolicy = .never
        cfg.httpShouldSetCookies = false
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        cfg.timeoutIntervalForRequest = timeout
        return URLSession(configuration: cfg)
    }

    // MARK: - building

    public func url(for request: GraphRequest) -> URL {
        var comps = URLComponents(url: base, resolvingAgainstBaseURL: false)!
        comps.path = "/" + request.version.rawValue + request.path
        comps.queryItems = request.query.isEmpty ? nil : request.query
        return comps.url!
    }

    // MARK: - sending

    /// One call, with the 429 policy applied. Throws `GraphError` and nothing else.
    public func send(_ request: GraphRequest) async throws -> GraphResponse {
        try await perform(url: url(for: request), request: request)
    }

    /// One call whose status is handed back rather than judged, for a write that must
    /// read a 401's claims challenge or a 403 itself. Transport and token failures still
    /// throw; nothing is retried, whatever the status.
    public func sendUnvalidated(_ request: GraphRequest) async throws -> GraphResponse {
        try await perform(url: url(for: request), request: request, validate: false)
    }

    /// One call decoded into a model with the Graph date rules applied.
    public func decode<T: Decodable>(_ type: T.Type, from request: GraphRequest) async throws -> T {
        let response = try await send(request)
        do {
            return try Self.decoder.decode(T.self, from: response.data)
        } catch {
            throw GraphError.decodeFailure
        }
    }

    /// Walks `value` across `@odata.nextLink` pages, up to `maxPages`.
    ///
    /// A budget rather than "until exhausted", because a tenant's sign-in log is not
    /// something to page through on a phone. The result says whether it stopped short.
    public func collection<T: Decodable & Sendable>(
        _ type: T.Type,
        from request: GraphRequest,
        maxPages: Int = 20
    ) async throws -> GraphCollection<T> {
        try await collection(type, at: url(for: request), like: request, maxPages: maxPages)
    }

    /// Continues a walk from a `nextLink`, for a load-more row.
    ///
    /// One token for the whole walk, not one per page: MSAL hands out a token with at least
    /// five minutes left, and asking again for every page queued each one behind the
    /// Keychain lookups of every other request in flight.
    public func collection<T: Decodable & Sendable>(
        _ type: T.Type,
        at start: URL,
        like request: GraphRequest,
        maxPages: Int = 20
    ) async throws -> GraphCollection<T> {
        var items: [T] = []
        var next: URL? = start
        var pages = 0
        var token: String?
        while let pageURL = next, pages < max(1, maxPages) {
            guard Self.isPageLink(pageURL, on: base) else { throw GraphError.decodeFailure }
            let sent = try await perform(url: pageURL, request: request, token: token)
            token = sent.token
            let response = sent.response
            let page: Page<T>
            do {
                page = try Self.decoder.decode(Page<T>.self, from: response.data)
            } catch {
                throw GraphError.decodeFailure
            }
            items.append(contentsOf: page.value)
            next = page.nextLink.flatMap { URL(string: $0) }
            pages += 1
        }
        return GraphCollection(items: items, nextLink: next)
    }

    /// Whether a page link may be followed. The bearer token goes with every request, so a
    /// link is followed only over https to the host this client was built for. Graph never
    /// sends anything else; this makes sure a response that did could not collect a token.
    public static func isPageLink(_ url: URL, on base: URL = GraphClient.defaultBase) -> Bool {
        url.scheme?.lowercased() == "https" && url.host?.lowercased() == base.host?.lowercased()
    }

    private struct Page<T: Decodable>: Decodable {
        let value: [T]
        let nextLink: String?
        enum CodingKeys: String, CodingKey {
            case value
            case nextLink = "@odata.nextLink"
        }
    }

    private func perform(url: URL, request: GraphRequest, validate: Bool = true) async throws -> GraphResponse {
        try await perform(url: url, request: request, validate: validate, token: nil).response
    }

    /// Sends one request, with a token already held for it or a fresh one, and hands back
    /// the token it used so a paged walk can use it again.
    private func perform(
        url: URL, request: GraphRequest, validate: Bool = true, token held: String?
    ) async throws -> (response: GraphResponse, token: String) {
        let started = Date()
        var retries = 0
        var throttledRetries = 0
        var serviceRetries = 0
        var lastStatus: Int?

        do {
            let token: String
            if let held {
                token = held
            } else {
                token = try await self.token(for: request)
            }
            // A read waits out a 429 another request already met, once, before going.
            if request.isRetryable {
                let pause = await throttle.remaining()
                if pause > 0 { try await sleep(pause + jitter(pause)) }
            }
            while true {
                var urlRequest = URLRequest(url: url)
                urlRequest.httpMethod = request.method.rawValue
                urlRequest.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
                urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
                if let body = request.body {
                    urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
                    urlRequest.httpBody = body
                }
                for (name, value) in request.headers {
                    urlRequest.setValue(value, forHTTPHeaderField: name)
                }

                let data: Data
                let response: URLResponse
                do {
                    (data, response) = try await session.data(for: urlRequest)
                } catch is CancellationError {
                    throw GraphError.cancelled
                } catch let error as URLError where error.code == .cancelled {
                    throw GraphError.cancelled
                } catch {
                    throw GraphError.transport(status: -1)
                }

                guard let http = response as? HTTPURLResponse else {
                    throw GraphError.transport(status: -1)
                }
                lastStatus = http.statusCode
                if !(200...299).contains(http.statusCode) {
                    tracer.recordFailure(http)
                }

                if http.statusCode == 429 {
                    // Every read this client sends waits this out, not only this one.
                    let wait = min(Self.retryAfter(http) ?? retryPolicy.defaultWait, retryPolicy.maxWait)
                    await throttle.hold(for: wait)
                    if request.isRetryable, throttledRetries < retryPolicy.maxRetries {
                        throttledRetries += 1
                        retries += 1
                        try await sleep(wait + jitter(wait))
                        continue
                    }
                }

                if http.statusCode == 503 || http.statusCode == 504,
                   request.isRetryable, serviceRetries < retryPolicy.serviceRetries {
                    serviceRetries += 1
                    retries += 1
                    let wait = min(Self.retryAfter(http) ?? retryPolicy.defaultWait, retryPolicy.maxWait)
                    try await sleep(wait + jitter(wait))
                    continue
                }

                if validate { try Self.validate(http, data: data) }
                record(request, status: http.statusCode, started: started, retries: retries)
                var headers: [String: String] = [:]
                if !validate {
                    for (key, value) in http.allHeaderFields {
                        if let key = key as? String, let value = value as? String { headers[key] = value }
                    }
                }
                let graphResponse = GraphResponse(
                    status: http.statusCode,
                    data: data,
                    requestId: http.value(forHTTPHeaderField: "request-id"),
                    headers: headers)
                return (graphResponse, token)
            }
        } catch let error as GraphError {
            record(request, status: lastStatus, started: started, retries: retries)
            throw error
        } catch {
            // Only the injected sleep can throw anything else, and it throws on cancellation.
            record(request, status: lastStatus, started: started, retries: retries)
            throw GraphError.cancelled
        }
    }

    private func token(for request: GraphRequest) async throws -> String {
        do {
            if let claims = request.claims {
                return try await auth.token(scopes: request.scopes, claims: claims, allowInteractive: request.allowInteractive)
            }
            return try await auth.token(scopes: request.scopes, allowInteractive: request.allowInteractive)
        } catch let error as AuthError {
            switch error {
            case .consentRequired, .interactionRequired, .noAccount:
                throw GraphError.consentRequired
            case .userCancelled:
                throw GraphError.cancelled
            case .tenantMismatch, .underlying:
                throw GraphError.transport(status: -1)
            }
        } catch is CancellationError {
            throw GraphError.cancelled
        } catch {
            throw GraphError.transport(status: -1)
        }
    }

    private func record(_ request: GraphRequest, status: Int?, started: Date, retries: Int) {
        guard let observer else { return }
        observer(GraphCallRecord(
            template: request.template,
            version: request.version,
            method: request.method,
            httpStatus: status,
            durationMs: Int(Date().timeIntervalSince(started) * 1000),
            retries: retries))
    }

    // MARK: - validating

    static func validate(_ http: HTTPURLResponse, data: Data) throws {
        switch http.statusCode {
        case 200...299: return
        case 401: throw GraphError.consentRequired
        case 403: throw GraphError.notAuthorized
        case 404: throw GraphError.notFound
        case 400: throw GraphError.badRequest(code: errorCode(data))
        case 429: throw GraphError.throttled(retryAfter: retryAfter(http))
        case 500...599: throw GraphError.serviceUnavailable(status: http.statusCode)
        default: throw GraphError.transport(status: http.statusCode)
        }
    }

    /// Seconds from `Retry-After`. Graph sends an integer; the HTTP-date form is ignored
    /// and falls back to the policy default.
    static func retryAfter(_ http: HTTPURLResponse) -> TimeInterval? {
        guard let raw = http.value(forHTTPHeaderField: "Retry-After")?
                .trimmingCharacters(in: .whitespacesAndNewlines),
              let seconds = TimeInterval(raw), seconds >= 0
        else { return nil }
        return seconds
    }

    /// Graph's error code alone. The message beside it is prose and stays out.
    static func errorCode(_ data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let error = json["error"] as? [String: Any],
              let code = error["code"] as? String, !code.isEmpty
        else { return nil }
        return code
    }

    // MARK: - decoding

    /// Graph's dates, which carry up to seven fractional digits where Foundation reads three.
    /// Built once: decoding does not change it, and a decoder per call and per page added up.
    public static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            guard let date = GraphDates.parse(raw) else {
                throw DecodingError.dataCorruptedError(
                    in: container, debugDescription: "not an ISO 8601 date")
            }
            return date
        }
        return decoder
    }()
}

public enum GraphDates {

    /// Parses `2026-10-25T12:34:56Z` and `2026-10-25T12:34:56.1234567Z` alike.
    ///
    /// Fractions are cut to three digits before parsing rather than dropped, so two
    /// events inside the same second still order correctly in a sign-in list.
    public static func parse(_ raw: String) -> Date? {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let dot = value.firstIndex(of: ".") else {
            return plain.date(from: value)
        }
        let afterDot = value[value.index(after: dot)...]
        let digits = afterDot.prefix { $0.isNumber }
        let rest = afterDot.dropFirst(digits.count)
        let threeDigits = String(digits.prefix(3)).padding(toLength: 3, withPad: "0", startingAt: 0)
        return fractional.date(from: String(value[..<dot]) + "." + threeDigits + String(rest))
    }

    // Built once. They were computed properties, so every date parsed built a formatter:
    // thousands for one Expiring Credentials load. ISO8601DateFormatter is thread-safe.
    private static let plain: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    private static let fractional: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}
