import XCTest
import AuthKit
@testable import SignInTriageKit

private final class RecordingAuth: AuthManaging, @unchecked Sendable {
    var account = AdminAccount(id: "a.b", tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73", username: "admin@example.com", objectId: "a")
    var failures: [String: AuthError] = [:]
    private(set) var calls: [[String]] = []
    private let lock = NSLock()
    var currentAccount: AdminAccount? { get async { account } }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        lock.lock(); calls.append(scopes); lock.unlock()
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
    /// URLSession calls startLoading on its own threads, and the services under test send
    /// requests concurrently; unguarded, the shared state above corrupts the heap now and then.
    static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock()
        Self.requests.append(request)
        let url = request.url?.absoluteString ?? ""
        let key = Self.replies.keys.first { url.lowercased().contains($0.lowercased()) }
        let reply = key.flatMap { k -> Reply? in
            guard var queue = Self.replies[k], !queue.isEmpty else { return nil }
            let next = queue.removeFirst()
            Self.replies[k] = queue
            return next
        } ?? Reply(status: 599, body: "{}")
        Self.lock.unlock()
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

    func test_theDirectoryIsReadInGraphsLargestPagesWithTheBasicScope() async throws {
        let next = "https://graph.microsoft.com/v1.0/users?$select=id&$top=999&$skiptoken=X1"
        StubProtocol.replies = ["v1.0/users": [
            .init(status: 200, body: #"{"value":[{"id":"u1","displayName":"Al","userPrincipalName":"al@c.com"}],"@odata.nextLink":""# + next + #""}"#),
            .init(status: 200, body: #"{"value":[{"id":"u2","displayName":"Bo","userPrincipalName":"bo@c.com","mail":"bo@c.com"}]}"#)]]
        let first = try await service.directoryPage(after: nil)
        XCTAssertEqual(first.users.map(\.id), ["u1"])
        XCTAssertEqual(first.next?.absoluteString, next)
        let url = try XCTUnwrap(StubProtocol.requests.first?.url?.absoluteString.removingPercentEncoding)
        XCTAssertTrue(url.contains("$select=id,displayName,userPrincipalName,mail"), url)
        XCTAssertTrue(url.contains("$top=999"), url)
        XCTAssertEqual(auth.calls.first, ["User.ReadBasic.All"])
        let second = try await service.directoryPage(after: first.next)
        XCTAssertEqual(second.users.map(\.mail), ["bo@c.com"])
        XCTAssertNil(second.next)
        XCTAssertEqual(StubProtocol.requests.last?.url?.absoluteString, next, "the link is followed as Graph gave it")

        StubProtocol.replies = ["v1.0/users": [.init(status: 403, body: "{}")]]
        do {
            _ = try await service.directoryPage(after: nil)
            XCTFail("expected notAuthorized")
        } catch {
            XCTAssertEqual(error as? SignInTriageError, .notAuthorized)
        }
    }

    func test_signInsCarryTheFilterTheHeaderAndBothScopes() async throws {
        StubProtocol.replies = ["signIns": [.init(status: 200, body: #"{"value":[{"id":"s1","status":{"errorCode":0}},{"id":"s2","status":{"errorCode":53003}},{"id":"s3","status":{"errorCode":0}}]}"#)]]
        let events = try await service.signIns(SignInQuery(userPrincipalName: "jane@contoso.com", failuresOnly: true, limit: 20))
        XCTAssertEqual(events.map(\.id), ["s2"])
        let request = try XCTUnwrap(StubProtocol.requests.first)
        let url = try XCTUnwrap(request.url?.absoluteString.removingPercentEncoding)
        XCTAssertTrue(url.contains("userPrincipalName eq 'jane@contoso.com' and status/errorCode ne 0"), url)
        XCTAssertTrue(url.contains("$top=20"), "Graph filters, so the fetch is what the screen shows: " + url)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Prefer"), "include-unknown-enum-members")
        XCTAssertEqual(auth.calls.first, ["AuditLog.Read.All", "Policy.Read.All"])
    }

    func test_aRefusedFailureClauseFiltersOnThePhoneForTheSession() async throws {
        let body = #"{"value":[{"id":"s1","status":{"errorCode":0}},{"id":"s2","status":{"errorCode":53003}}]}"#
        StubProtocol.replies = ["signIns": [
            .init(status: 400, body: #"{"error":{"code":"Request_UnsupportedQuery"}}"#),
            .init(status: 200, body: body),
            .init(status: 200, body: body)]]
        let query = SignInQuery(userPrincipalName: "jane@contoso.com", failuresOnly: true, limit: 20)
        let first = try await service.signIns(query)
        let second = try await service.signIns(query)
        XCTAssertEqual(first.map(\.id), ["s2"])
        XCTAssertEqual(second.map(\.id), ["s2"])
        let urls = StubProtocol.requests.compactMap { $0.url?.absoluteString.removingPercentEncoding }
        XCTAssertEqual(urls.count, 3, "one refusal, then the phone's filter both times")
        XCTAssertTrue(urls[1].contains("$top=100") && !urls[1].contains("errorCode"), urls[1])
        XCTAssertFalse(urls[2].contains("errorCode"), urls[2])
    }

    func test_everySignInIsNotFilteredByGraph() async throws {
        StubProtocol.replies = ["signIns": [.init(status: 200, body: #"{"value":[]}"#)]]
        _ = try await service.signIns(SignInQuery(userPrincipalName: "jane@contoso.com", limit: 20))
        let url = try XCTUnwrap(StubProtocol.requests.first?.url?.absoluteString.removingPercentEncoding)
        XCTAssertFalse(url.contains("errorCode"), url)
        XCTAssertTrue(url.contains("$top=20"), url)
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
