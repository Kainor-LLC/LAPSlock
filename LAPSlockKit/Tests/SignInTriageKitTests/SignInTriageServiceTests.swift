import XCTest
import AuthKit
@testable import SignInTriageKit

private final class RecordingAuth: AuthManaging, @unchecked Sendable {
    var account = AdminAccount(id: "a.b", tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73", username: "admin@example.com", objectId: "a")
    var failures: [String: AuthError] = [:]
    private(set) var calls: [[String]] = []
    var currentAccount: AdminAccount? { get async { account } }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        calls.append(scopes)
        if let first = scopes.first, let error = failures[first] { throw error }
        return "token"
    }
    func signIn() async throws -> AdminAccount { account }
    func signOut(account: AdminAccount) async throws {}
}

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
        let url = request.url?.absoluteString ?? ""
        let key = Self.replies.keys.first { url.lowercased().contains($0.lowercased()) }
        let reply = key.flatMap { k -> Reply? in
            guard var queue = Self.replies[k], !queue.isEmpty else { return nil }
            let next = queue.removeFirst()
            Self.replies[k] = queue
            return next
        } ?? Reply(status: 599, body: "{}")
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: reply.headers)!
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

final class SignInTriageServiceTests: XCTestCase {

    private var auth: RecordingAuth!
    private var service: SignInTriageService!

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
        auth = RecordingAuth()
        let graph = GraphClient(auth: auth, session: StubProtocol.session(), retryPolicy: .none, tracer: GraphResponseTracer(), sleep: { _ in })
        service = SignInTriageService(graph: graph)
    }

    override func tearDown() {
        StubProtocol.reset()
        super.tearDown()
    }

    func test_userSearchFiltersOnNameAndAddressWithTheBasicScope() async throws {
        StubProtocol.replies = ["v1.0/users": [.init(status: 200, body: #"{"value":[{"id":"u2","displayName":"Zed","userPrincipalName":"zed@c.com"},{"id":"u1","displayName":"Al","userPrincipalName":"al@c.com","mail":"al@c.com"}]}"#)]]
        let users = try await service.searchUsers(prefix: "a")
        XCTAssertTrue(users.isEmpty, "one character is too short to search")
        let found = try await service.searchUsers(prefix: "o'b")
        XCTAssertEqual(found.map(\.displayName), ["Al", "Zed"])
        let url = try XCTUnwrap(StubProtocol.requests.last?.url?.absoluteString.removingPercentEncoding)
        XCTAssertTrue(url.contains("startswith(displayName,'o''b') or startswith(userPrincipalName,'o''b')"), url)
        XCTAssertTrue(url.contains("$top=10"), url)
        XCTAssertEqual(auth.calls.last, ["User.ReadBasic.All"])
    }

    func test_signInsCarryTheFilterTheHeaderAndBothScopes() async throws {
        StubProtocol.replies = ["signIns": [.init(status: 200, body: #"{"value":[{"id":"s1","status":{"errorCode":0}},{"id":"s2","status":{"errorCode":53003}},{"id":"s3","status":{"errorCode":0}}]}"#)]]
        let events = try await service.signIns(SignInQuery(userPrincipalName: "jane@contoso.com", failuresOnly: true, limit: 20))
        XCTAssertEqual(events.map(\.id), ["s2"])
        let request = try XCTUnwrap(StubProtocol.requests.first)
        let url = try XCTUnwrap(request.url?.absoluteString.removingPercentEncoding)
        XCTAssertTrue(url.contains("userPrincipalName eq 'jane@contoso.com'"), url)
        XCTAssertTrue(url.contains("$top=100"), url)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Prefer"), "include-unknown-enum-members")
        XCTAssertEqual(auth.calls.first, ["AuditLog.Read.All", "Policy.Read.All"])
    }

    func test_errorsMap() async {
        StubProtocol.replies = ["signIns": [.init(status: 403, body: "{}")]]
        do {
            _ = try await service.signIns(SignInQuery(userPrincipalName: "x@y.com"))
            XCTFail("expected notAuthorized")
        } catch {
            XCTAssertEqual(error as? SignInTriageError, .notAuthorized)
        }
        XCTAssertEqual(SignInTriageError(.consentRequired), .consentRequired)
        XCTAssertEqual(SignInTriageError(.throttled(retryAfter: 1)), .throttled(retryAfter: 1))
        XCTAssertEqual(SignInTriageError(.badRequest(code: nil)), .transport(status: 400))
    }
}
