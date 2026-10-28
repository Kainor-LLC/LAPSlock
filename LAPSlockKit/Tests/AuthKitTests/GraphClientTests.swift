import XCTest
@testable import AuthKit

// The shared Graph client. What is tested is what can be wrong without anybody noticing:
// the URL it builds, how each status maps, that 429 waits exactly as long as asked and no
// longer, that a write is never retried, that the request-id reaches the tracer, and that
// the observer sees a template and never a real path.

// MARK: - doubles

/// Records what was asked of it, and can be told to fail per scope.
private final class RecordingAuth: AuthManaging, @unchecked Sendable {
    var account = AdminAccount(
        id: "aaaaaaaa-1111-2222-3333-444455556666.4470dc21-a4b7-4729-a232-56d4c0eedf73",
        tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73",
        username: "admin@example.com",
        objectId: "aaaaaaaa-1111-2222-3333-444455556666")

    var failures: [String: AuthError] = [:]
    private(set) var calls: [(scopes: [String], interactive: Bool)] = []

    var currentAccount: AdminAccount? { get async { account } }

    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        calls.append((scopes, allowInteractive))
        if let first = scopes.first, let error = failures[first] { throw error }
        return "token-for-" + scopes.joined(separator: "+")
    }

    func signIn() async throws -> AdminAccount { account }
    func signOut(account: AdminAccount) async throws {}
}

/// Serves canned HTTP responses in order, per path substring.
private final class StubProtocol: URLProtocol {
    struct Reply {
        var status: Int
        var body: String
        var headers: [String: String] = [:]
    }
    nonisolated(unsafe) static var replies: [String: [Reply]] = [:]
    nonisolated(unsafe) static var requests: [URLRequest] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requests.append(request)
        let path = request.url?.absoluteString ?? ""
        let key = Self.replies.keys.first { path.lowercased().contains($0.lowercased()) }
        let reply = key.flatMap { k -> Reply? in
            guard var queue = Self.replies[k], !queue.isEmpty else { return nil }
            let next = queue.removeFirst()
            Self.replies[k] = queue
            return next
        } ?? Reply(status: 599, body: "{}")

        let response = HTTPURLResponse(
            url: request.url!, statusCode: reply.status,
            httpVersion: "HTTP/1.1", headerFields: reply.headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(reply.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func reset() { replies = [:]; requests = [] }

    static func session() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: cfg)
    }
}

/// Captures what the client asked to wait for, instead of waiting.
private final class SleepLog: @unchecked Sendable {
    private let lock = NSLock()
    private var waits: [TimeInterval] = []
    var recorded: [TimeInterval] { lock.lock(); defer { lock.unlock() }; return waits }
    func sleeper() -> GraphClient.Sleeper {
        { [self] seconds in
            lock.lock(); waits.append(seconds); lock.unlock()
        }
    }
}

private final class RecordBox: @unchecked Sendable {
    private let lock = NSLock()
    private var records: [GraphCallRecord] = []
    var all: [GraphCallRecord] { lock.lock(); defer { lock.unlock() }; return records }
    func observer() -> GraphClient.Observer {
        { [self] record in lock.lock(); records.append(record); lock.unlock() }
    }
}

private struct Policy: Decodable, Equatable {
    let id: String
    let displayName: String
    let modifiedDateTime: Date?
}

// MARK: - tests

final class GraphClientTests: XCTestCase {

    private var auth: RecordingAuth!
    private var sleeps: SleepLog!
    private var tracer: GraphResponseTracer!
    private var records: RecordBox!
    private var client: GraphClient!

    private let scopes = ["Policy.Read.All"]

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
        auth = RecordingAuth()
        sleeps = SleepLog()
        tracer = GraphResponseTracer()
        records = RecordBox()
        client = GraphClient(
            auth: auth,
            session: StubProtocol.session(),
            retryPolicy: GraphRetryPolicy(maxRetries: 2, maxWait: 10, defaultWait: 2),
            observer: records.observer(),
            tracer: tracer,
            sleep: sleeps.sleeper(),
            jitter: { _ in 0 })
    }

    override func tearDown() {
        StubProtocol.reset()
        super.tearDown()
    }

    private func policies(_ version: GraphAPIVersion = .v1_0) -> GraphRequest {
        GraphRequest(
            version: version,
            path: "/identity/conditionalAccess/policies",
            query: [URLQueryItem(name: "$select", value: "id,displayName")],
            scopes: scopes)
    }

    private let policyBody = #"{"value":[{"id":"p1","displayName":"Require MFA","modifiedDateTime":"2026-10-20T08:15:30.1234567Z"}]}"#

    // MARK: building

    func test_theURLCarriesTheVersionThePathAndTheQuery() {
        let url = client.url(for: policies(.beta)).absoluteString
        XCTAssertTrue(url.hasPrefix("https://graph.microsoft.com/beta/identity/conditionalAccess/policies?"), url)
        XCTAssertTrue(url.contains("$select=id,displayName"), url)
    }

    func test_aPathWithoutALeadingSlashIsNormalised() {
        let request = GraphRequest(path: "users", scopes: scopes)
        XCTAssertEqual(request.path, "/users")
        XCTAssertEqual(request.template, "/users")
        XCTAssertEqual(client.url(for: request).absoluteString, "https://graph.microsoft.com/v1.0/users")
    }

    func test_theBearerTokenAndAcceptHeaderAreSet() async throws {
        StubProtocol.replies = ["policies": [.init(status: 200, body: policyBody)]]
        _ = try await client.send(policies())
        let sent = try XCTUnwrap(StubProtocol.requests.first)
        XCTAssertEqual(sent.value(forHTTPHeaderField: "Authorization"), "Bearer token-for-Policy.Read.All")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "Accept"), "application/json")
        XCTAssertEqual(sent.httpMethod, "GET")
    }

    func test_theTokenIsRequestedSilentlyForTheRequestScopes() async throws {
        StubProtocol.replies = ["policies": [.init(status: 200, body: policyBody)]]
        _ = try await client.send(policies())
        XCTAssertEqual(auth.calls.count, 1)
        XCTAssertEqual(auth.calls.first?.scopes, scopes)
        XCTAssertEqual(auth.calls.first?.interactive, false)
    }

    // MARK: decoding

    func test_aSuccessDecodesWithGraphDates() async throws {
        StubProtocol.replies = ["policies": [.init(status: 200, body: policyBody)]]
        let page = try await client.collection(Policy.self, from: policies())
        XCTAssertEqual(page.items.map(\.id), ["p1"])
        XCTAssertFalse(page.truncated)
        let modified = try XCTUnwrap(page.items.first?.modifiedDateTime)
        XCTAssertEqual(modified, GraphDates.parse("2026-10-20T08:15:30.123Z"))
    }

    func test_anUnreadableBodyIsADecodeFailure() async {
        StubProtocol.replies = ["policies": [.init(status: 200, body: "not json")]]
        await assertThrows(.decodeFailure) { try await client.collection(Policy.self, from: policies()) }
    }

    func test_graphDatesParseWithAndWithoutFractions() throws {
        let plain = try XCTUnwrap(GraphDates.parse("2026-10-25T12:34:56Z"))
        let seven = try XCTUnwrap(GraphDates.parse("2026-10-25T12:34:56.1234567Z"))
        let three = try XCTUnwrap(GraphDates.parse("2026-10-25T12:34:56.123Z"))
        let one = try XCTUnwrap(GraphDates.parse("2026-10-25T12:34:56.1Z"))
        XCTAssertEqual(seven, three)
        XCTAssertEqual(one.timeIntervalSince(plain), 0.1, accuracy: 0.001)
        XCTAssertEqual(seven.timeIntervalSince(plain), 0.123, accuracy: 0.001)
        XCTAssertNil(GraphDates.parse("yesterday"))
    }

    // MARK: status mapping

    func test_401IsConsentRequired() async {
        StubProtocol.replies = ["policies": [.init(status: 401, body: "{}")]]
        await assertThrows(.consentRequired) { try await client.send(policies()) }
    }

    func test_403IsNotAuthorized() async {
        StubProtocol.replies = ["policies": [.init(status: 403, body: "{}")]]
        await assertThrows(.notAuthorized) { try await client.send(policies()) }
    }

    func test_404IsNotFound() async {
        StubProtocol.replies = ["policies": [.init(status: 404, body: "{}")]]
        await assertThrows(.notFound) { try await client.send(policies()) }
    }

    func test_400CarriesTheGraphErrorCodeAndNotTheMessage() async {
        let body = #"{"error":{"code":"Request_UnsupportedQuery","message":"Tenant contoso.com cannot filter on that"}}"#
        StubProtocol.replies = ["policies": [.init(status: 400, body: body)]]
        await assertThrows(.badRequest(code: "Request_UnsupportedQuery")) { try await client.send(policies()) }
    }

    func test_5xxIsServiceUnavailable() async {
        StubProtocol.replies = ["policies": [.init(status: 503, body: ""), .init(status: 503, body: "")]]
        await assertThrows(.serviceUnavailable(status: 503)) { try await client.send(policies()) }
        XCTAssertEqual(StubProtocol.requests.count, 2, "one retry, then the failure")
    }

    func test_a500IsNotRetried() async {
        StubProtocol.replies = ["policies": [.init(status: 500, body: ""), .init(status: 200, body: policyBody)]]
        await assertThrows(.serviceUnavailable(status: 500)) { try await client.send(policies()) }
        XCTAssertEqual(StubProtocol.requests.count, 1)
        XCTAssertEqual(sleeps.recorded, [])
    }

    func test_anUnexpectedStatusIsTransport() async {
        StubProtocol.replies = ["policies": [.init(status: 418, body: "")]]
        await assertThrows(.transport(status: 418)) { try await client.send(policies()) }
    }

    // MARK: throttling

    func test_a429OnAGETWaitsForRetryAfterThenSucceeds() async throws {
        StubProtocol.replies = ["policies": [
            .init(status: 429, body: "", headers: ["Retry-After": "3"]),
            .init(status: 200, body: policyBody),
        ]]
        let response = try await client.send(policies())
        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(sleeps.recorded, [3])
        XCTAssertEqual(StubProtocol.requests.count, 2)
        XCTAssertEqual(records.all.last?.retries, 1)
    }

    func test_aMissingRetryAfterUsesThePolicyDefault() async throws {
        StubProtocol.replies = ["policies": [
            .init(status: 429, body: ""),
            .init(status: 200, body: policyBody),
        ]]
        _ = try await client.send(policies())
        XCTAssertEqual(sleeps.recorded, [2])
    }

    func test_retryAfterIsCappedAtTheMaximumWait() async throws {
        StubProtocol.replies = ["policies": [
            .init(status: 429, body: "", headers: ["Retry-After": "60"]),
            .init(status: 200, body: policyBody),
        ]]
        _ = try await client.send(policies())
        XCTAssertEqual(sleeps.recorded, [10])
    }

    func test_429BeyondTheRetryBudgetIsThrottled() async {
        StubProtocol.replies = ["policies": [
            .init(status: 429, body: "", headers: ["Retry-After": "1"]),
            .init(status: 429, body: "", headers: ["Retry-After": "1"]),
            .init(status: 429, body: "", headers: ["Retry-After": "7"]),
        ]]
        await assertThrows(.throttled(retryAfter: 7)) { try await client.send(policies()) }
        XCTAssertEqual(sleeps.recorded, [1, 1])
        XCTAssertEqual(StubProtocol.requests.count, 3)
    }

    func test_a429OnAPOSTIsNeverRetried() async {
        StubProtocol.replies = ["policies": [
            .init(status: 429, body: "", headers: ["Retry-After": "1"]),
            .init(status: 200, body: policyBody),
        ]]
        let post = GraphRequest(
            method: .post, path: "/identity/conditionalAccess/policies",
            body: Data("{}".utf8), scopes: scopes)
        await assertThrows(.throttled(retryAfter: 1)) { try await client.send(post) }
        XCTAssertEqual(sleeps.recorded, [])
        XCTAssertEqual(StubProtocol.requests.count, 1)
        XCTAssertEqual(StubProtocol.requests.first?.httpMethod, "POST")
        XCTAssertEqual(StubProtocol.requests.first?.value(forHTTPHeaderField: "Content-Type"), "application/json")
    }

    func test_a503OnAGETIsRetriedOnceThenSucceeds() async throws {
        StubProtocol.replies = ["policies": [
            .init(status: 503, body: ""),
            .init(status: 200, body: policyBody),
        ]]
        let response = try await client.send(policies())
        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(sleeps.recorded, [2], "no Retry-After: the policy default")
        XCTAssertEqual(records.all.last?.retries, 1)
    }

    func test_a504HonoursRetryAfter() async throws {
        StubProtocol.replies = ["policies": [
            .init(status: 504, body: "", headers: ["Retry-After": "4"]),
            .init(status: 200, body: policyBody),
        ]]
        _ = try await client.send(policies())
        XCTAssertEqual(sleeps.recorded, [4])
    }

    func test_a503OnAPOSTIsNeverRetried() async {
        StubProtocol.replies = ["policies": [.init(status: 503, body: ""), .init(status: 200, body: policyBody)]]
        let post = GraphRequest(method: .post, path: "/identity/conditionalAccess/policies", body: Data("{}".utf8), scopes: scopes)
        await assertThrows(.serviceUnavailable(status: 503)) { try await client.send(post) }
        XCTAssertEqual(StubProtocol.requests.count, 1)
        XCTAssertEqual(sleeps.recorded, [])
    }

    func test_aReadOnlyPOSTGetsAGETsRetry() async throws {
        StubProtocol.replies = ["policies": [
            .init(status: 429, body: "", headers: ["Retry-After": "1"]),
            .init(status: 200, body: policyBody),
        ]]
        let read = GraphRequest(method: .post, path: "/identity/conditionalAccess/policies", body: Data("{}".utf8),
                                scopes: scopes, readOnly: true)
        let response = try await client.send(read)
        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(sleeps.recorded, [1])
        XCTAssertEqual(StubProtocol.requests.count, 2)
    }

    func test_readOnlyNeverMakesAPatchOrDeleteRetryable() async {
        for method in [GraphRequest.Method.patch, .delete] {
            StubProtocol.reset()
            StubProtocol.replies = ["policies": [
                .init(status: 429, body: "", headers: ["Retry-After": "1"]),
                .init(status: 200, body: policyBody),
            ]]
            let write = GraphRequest(method: method, path: "/identity/conditionalAccess/policies", body: Data("{}".utf8),
                                     scopes: scopes, readOnly: true)
            XCTAssertFalse(write.isRetryable)
            await assertThrows(.throttled(retryAfter: 1)) { try await client.send(write) }
            XCTAssertEqual(StubProtocol.requests.count, 1, method.rawValue)
        }
    }

    func test_a429SlowsTheNextReadToo() async throws {
        StubProtocol.replies = ["policies": [
            .init(status: 429, body: "", headers: ["Retry-After": "3"]),
            .init(status: 200, body: policyBody),
            .init(status: 200, body: policyBody),
        ]]
        _ = try await client.send(policies())
        _ = try await client.send(policies())
        XCTAssertEqual(sleeps.recorded.count, 2, "the second read waits out what is left of the first one's 429")
        XCTAssertEqual(sleeps.recorded.first, 3)
        XCTAssertGreaterThan(sleeps.recorded.last ?? 0, 2)
        XCTAssertLessThanOrEqual(sleeps.recorded.last ?? 0, 3)
    }

    func test_aWriteNeverWaitsForTheThrottle() async throws {
        StubProtocol.replies = ["policies": [
            .init(status: 429, body: "", headers: ["Retry-After": "3"]),
            .init(status: 200, body: policyBody),
            .init(status: 204, body: ""),
        ]]
        _ = try await client.send(policies())
        let write = GraphRequest(method: .post, path: "/identity/conditionalAccess/policies", body: Data("{}".utf8), scopes: scopes)
        _ = try await client.send(write)
        XCTAssertEqual(sleeps.recorded, [3], "the write went when it was sent")
    }

    func test_jitterIsAddedToEveryWait() async throws {
        let jittered = GraphClient(
            auth: auth, session: StubProtocol.session(),
            retryPolicy: GraphRetryPolicy(maxRetries: 2, maxWait: 10, defaultWait: 2),
            tracer: tracer, sleep: sleeps.sleeper(), jitter: { $0 / 2 })
        StubProtocol.replies = ["policies": [
            .init(status: 429, body: "", headers: ["Retry-After": "4"]),
            .init(status: 200, body: policyBody),
        ]]
        _ = try await jittered.send(policies())
        XCTAssertEqual(sleeps.recorded, [6])
    }

    // MARK: diagnostics

    func test_aFailureRecordsTheRequestIdInTheTracer() async {
        StubProtocol.replies = ["policies": [
            .init(status: 403, body: "{}", headers: ["request-id": "11111111-2222-3333-4444-555555555555"]),
        ]]
        await assertThrows(.notAuthorized) { try await client.send(policies()) }
        XCTAssertEqual(tracer.attributableRequestId(httpStatus: 403), "11111111-2222-3333-4444-555555555555")
    }

    func test_aSuccessRecordsNothingInTheTracer() async throws {
        StubProtocol.replies = ["policies": [
            .init(status: 200, body: policyBody, headers: ["request-id": "11111111-2222-3333-4444-555555555555"]),
        ]]
        _ = try await client.send(policies())
        XCTAssertNil(tracer.attributableRequestId(httpStatus: nil))
    }

    func test_theObserverSeesTheTemplateAndNotThePath() async throws {
        StubProtocol.replies = ["users": [.init(status: 200, body: "{}")]]
        let request = GraphRequest(
            version: .beta,
            path: "/users/aaaaaaaa-1111-2222-3333-444455556666",
            template: "/users/{id}",
            scopes: ["User.Read.All"])
        _ = try await client.send(request)
        let record = try XCTUnwrap(records.all.last)
        XCTAssertEqual(record.template, "/users/{id}")
        XCTAssertEqual(record.version, .beta)
        XCTAssertEqual(record.method, .get)
        XCTAssertEqual(record.httpStatus, 200)
        XCTAssertEqual(record.retries, 0)
    }

    func test_theObserverSeesAFailureToo() async {
        StubProtocol.replies = ["policies": [.init(status: 500, body: "")]]
        await assertThrows(.serviceUnavailable(status: 500)) { try await client.send(policies()) }
        XCTAssertEqual(records.all.last?.httpStatus, 500)
    }

    // MARK: auth

    func test_aConsentFailureFromAuthNeverReachesTheNetwork() async {
        auth.failures = ["Policy.Read.All": .consentRequired]
        await assertThrows(.consentRequired) { try await client.send(policies()) }
        XCTAssertTrue(StubProtocol.requests.isEmpty)
        XCTAssertNil(records.all.last?.httpStatus)
    }

    func test_aCancelledSignInIsCancelled() async {
        auth.failures = ["Policy.Read.All": .userCancelled]
        await assertThrows(.cancelled) { try await client.send(policies()) }
        XCTAssertTrue(StubProtocol.requests.isEmpty)
    }

    // MARK: paging

    func test_aCollectionFollowsTheNextLink() async throws {
        let first = #"{"value":[{"id":"p1","displayName":"A"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=abc"}"#
        let second = #"{"value":[{"id":"p2","displayName":"B"}]}"#
        StubProtocol.replies = ["policies": [.init(status: 200, body: first), .init(status: 200, body: second)]]
        let page = try await client.collection(Policy.self, from: policies())
        XCTAssertEqual(page.items.map(\.id), ["p1", "p2"])
        XCTAssertFalse(page.truncated)
        XCTAssertEqual(StubProtocol.requests.count, 2)
        XCTAssertTrue(StubProtocol.requests.last?.url?.absoluteString.contains("skiptoken=abc") == true)
    }

    func test_aCollectionAsksForOneTokenForTheWholeWalk() async throws {
        let first = #"{"value":[{"id":"p1","displayName":"A"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=abc"}"#
        let second = #"{"value":[{"id":"p2","displayName":"B"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=def"}"#
        let third = #"{"value":[{"id":"p3","displayName":"C"}]}"#
        StubProtocol.replies = ["policies": [.init(status: 200, body: first), .init(status: 200, body: second), .init(status: 200, body: third)]]
        let page = try await client.collection(Policy.self, from: policies())
        XCTAssertEqual(page.items.map(\.id), ["p1", "p2", "p3"])
        XCTAssertEqual(auth.calls.count, 1, "three pages, one token")
        XCTAssertEqual(Set(StubProtocol.requests.compactMap { $0.value(forHTTPHeaderField: "Authorization") }).count, 1)
    }

    func test_aCollectionStopsAtThePageBudgetAndSaysSo() async throws {
        let first = #"{"value":[{"id":"p1","displayName":"A"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=abc"}"#
        StubProtocol.replies = ["policies": [.init(status: 200, body: first)]]
        let page = try await client.collection(Policy.self, from: policies(), maxPages: 1)
        XCTAssertEqual(page.items.map(\.id), ["p1"])
        XCTAssertTrue(page.truncated)
        XCTAssertEqual(page.nextLink?.absoluteString.contains("skiptoken=abc"), true)
        XCTAssertEqual(StubProtocol.requests.count, 1)
    }

    func test_aNextLinkToAnotherHostIsNeverFollowed() async {
        let first = #"{"value":[{"id":"p1","displayName":"A"}],"@odata.nextLink":"https://graph.microsoft.com.example.net/v1.0/identity/conditionalAccess/policies?$skiptoken=abc"}"#
        StubProtocol.replies = ["policies": [.init(status: 200, body: first)]]
        await assertThrows(.decodeFailure) { try await client.collection(Policy.self, from: policies()) }
        XCTAssertEqual(StubProtocol.requests.count, 1)
    }

    func test_onlyHttpsGraphLinksArePageLinks() {
        XCTAssertTrue(GraphClient.isPageLink(URL(string: "https://graph.microsoft.com/v1.0/x?$skiptoken=a")!))
        XCTAssertTrue(GraphClient.isPageLink(URL(string: "https://GRAPH.microsoft.com/beta/x")!))
        XCTAssertFalse(GraphClient.isPageLink(URL(string: "http://graph.microsoft.com/v1.0/x")!))
        XCTAssertFalse(GraphClient.isPageLink(URL(string: "https://graph.microsoft.com.example.net/v1.0/x")!))
        XCTAssertFalse(GraphClient.isPageLink(URL(string: "https://example.com/graph.microsoft.com")!))
    }

    // MARK: helpers

    private func assertThrows<T>(
        _ expected: GraphError,
        file: StaticString = #filePath, line: UInt = #line,
        _ body: () async throws -> T
    ) async {
        do {
            _ = try await body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let error as GraphError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("expected GraphError, got \(error)", file: file, line: line)
        }
    }
}
