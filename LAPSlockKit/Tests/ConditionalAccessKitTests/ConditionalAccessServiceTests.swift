import XCTest
import AuthKit
@testable import ConditionalAccessKit

// MARK: - doubles

private final class RecordingAuth: AuthManaging, @unchecked Sendable {
    var account = AdminAccount(
        id: "aaaaaaaa-1111-2222-3333-444455556666.4470dc21-a4b7-4729-a232-56d4c0eedf73",
        tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73",
        username: "admin@example.com",
        objectId: "aaaaaaaa-1111-2222-3333-444455556666")
    var failures: [String: AuthError] = [:]
    private(set) var calls: [(scopes: [String], interactive: Bool)] = []
    private let lock = NSLock()

    var currentAccount: AdminAccount? { get async { account } }

    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        lock.lock(); calls.append((scopes, allowInteractive)); lock.unlock()
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
    nonisolated(unsafe) static var requests: [(url: String, method: String, body: Data?)] = []
    /// URLSession calls startLoading on its own threads, and the services under test send
    /// requests concurrently; unguarded, the shared state above corrupts the heap now and then.
    static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let url = request.url?.absoluteString ?? ""
        let body = request.httpBodyStream.flatMap { stream -> Data in
            stream.open()
            var data = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buffer, maxLength: buffer.count)
                if n <= 0 { break }
                data.append(buffer, count: n)
            }
            stream.close()
            return data
        } ?? request.httpBody
        Self.requests.append((url, request.httpMethod ?? "", body))
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

// MARK: - tests

final class ConditionalAccessServiceTests: XCTestCase {

    private var auth: RecordingAuth!
    private var service: ConditionalAccessService!

    private let group = "22222222-2222-4222-8222-222222222222"
    private let user = "44444444-4444-4444-8444-444444444444"
    private let role = "62e90394-69f5-4237-9190-012177145e10"
    private let app = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
    private let location = "55555555-5555-4555-8555-555555555555"
    private let policyId = "11111111-1111-4111-8111-111111111111"

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
        auth = RecordingAuth()
        let graph = GraphClient(
            auth: auth, session: StubProtocol.session(), retryPolicy: .none,
            tracer: GraphResponseTracer(), sleep: { _ in })
        service = ConditionalAccessService(graph: graph)
    }

    override func tearDown() {
        StubProtocol.reset()
        super.tearDown()
    }

    private var policiesBody: String {
        #"{"value":[{"id":"\#(policyId)","displayName":"Old","state":"enabled","modifiedDateTime":"2026-01-01T00:00:00Z","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}}},{"id":"33333333-3333-4333-8333-333333333333","displayName":"New","state":"disabled","modifiedDateTime":"2026-10-01T00:00:00Z","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}}}]}"#
    }

    // MARK: policies

    func test_policiesAreReadOnV1WithThePolicyScopeAndSortedNewestFirst() async throws {
        StubProtocol.replies = ["conditionalAccess/policies": [.init(status: 200, body: policiesBody)]]
        let policies = try await service.policies()
        XCTAssertEqual(policies.map(\.displayName), ["New", "Old"])
        let sent = try XCTUnwrap(StubProtocol.requests.first)
        XCTAssertTrue(sent.url.hasPrefix("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"), sent.url)
        XCTAssertEqual(sent.method, "GET")
        XCTAssertEqual(auth.calls.first?.scopes, ["Policy.Read.All", "Directory.Read.All"])
        XCTAssertEqual(auth.calls.first?.interactive, false)
    }

    func test_a401BecomesConsentRequired() async {
        StubProtocol.replies = ["conditionalAccess/policies": [.init(status: 401, body: "{}")]]
        do {
            _ = try await service.policies()
            XCTFail("expected consentRequired")
        } catch {
            XCTAssertEqual(error as? ConditionalAccessError, .consentRequired)
        }
    }

    func test_a403BecomesNotAuthorized() async {
        StubProtocol.replies = ["conditionalAccess/policies": [.init(status: 403, body: "{}")]]
        do {
            _ = try await service.policies()
            XCTFail("expected notAuthorized")
        } catch {
            XCTAssertEqual(error as? ConditionalAccessError, .notAuthorized)
        }
    }

    func test_errorMappingCoversEveryGraphCase() {
        XCTAssertEqual(ConditionalAccessError(.throttled(retryAfter: 3)), .throttled(retryAfter: 3))
        XCTAssertEqual(ConditionalAccessError(.serviceUnavailable(status: 503)), .serviceUnavailable(status: 503))
        XCTAssertEqual(ConditionalAccessError(.notFound), .transport(status: 404))
        XCTAssertEqual(ConditionalAccessError(.badRequest(code: "x")), .transport(status: 400))
        XCTAssertEqual(ConditionalAccessError(.decodeFailure), .decodeFailure)
        XCTAssertEqual(ConditionalAccessError(.cancelled), .cancelled)
    }

    // MARK: names

    private func seedNameReplies() {
        StubProtocol.replies = [
            "directoryObjects/getByIds": [.init(status: 200, body: ##"{"value":[{"@odata.type":"#microsoft.graph.group","id":"\##(group)","displayName":"Helpdesk"},{"@odata.type":"#microsoft.graph.user","id":"\##(user)","displayName":"Jane Admin"}]}"##)],
            "directoryRoleTemplates": [.init(status: 200, body: #"{"value":[{"id":"\#(role)","displayName":"Global Administrator"},{"id":"other","displayName":"Other"}]}"#)],
            "servicePrincipals": [.init(status: 200, body: #"{"value":[{"appId":"\#(app)","displayName":"Windows Azure Service Management API"}]}"#)],
            "namedLocations": [.init(status: 200, body: #"{"value":[{"id":"\#(location)","displayName":"Head office"}]}"#)],
        ]
    }

    private var allReferences: Set<DirectoryReference> {
        [
            DirectoryReference(kind: .group, id: group),
            DirectoryReference(kind: .user, id: user),
            DirectoryReference(kind: .role, id: role),
            DirectoryReference(kind: .application, id: app),
            DirectoryReference(kind: .location, id: location),
        ]
    }

    func test_namesResolveEachKindOnItsOwnEndpoint() async throws {
        seedNameReplies()
        let names = try await service.names(for: allReferences)
        XCTAssertEqual(names[DirectoryReference(kind: .group, id: group)], "Helpdesk")
        XCTAssertEqual(names[DirectoryReference(kind: .user, id: user)], "Jane Admin")
        XCTAssertEqual(names[DirectoryReference(kind: .role, id: role)], "Global Administrator")
        XCTAssertEqual(names[DirectoryReference(kind: .application, id: app)], "Windows Azure Service Management API")
        XCTAssertEqual(names[DirectoryReference(kind: .location, id: location)], "Head office")

        let getByIds = try XCTUnwrap(StubProtocol.requests.first { $0.url.contains("getByIds") })
        XCTAssertEqual(getByIds.method, "POST")
        let body = try XCTUnwrap(getByIds.body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(Set(json["ids"] as? [String] ?? []), [group, user])
        XCTAssertEqual(Set(json["types"] as? [String] ?? []), ["user", "group"])

        let principals = try XCTUnwrap(StubProtocol.requests.first { $0.url.contains("servicePrincipals") })
        XCTAssertTrue(principals.url.contains("appId"), principals.url)
        XCTAssertTrue(principals.url.removingPercentEncoding?.contains("'" + app + "'") == true, principals.url)
    }

    func test_oneResolverFailingLeavesTheOthersResolved() async throws {
        seedNameReplies()
        StubProtocol.replies["servicePrincipals"] = [.init(status: 403, body: "{}")]
        let names = try await service.names(for: allReferences)
        XCTAssertNil(names[DirectoryReference(kind: .application, id: app)])
        XCTAssertEqual(names[DirectoryReference(kind: .group, id: group)], "Helpdesk")
        XCTAssertEqual(names.count, 4)
    }

    func test_namesAreCachedAcrossCalls() async throws {
        seedNameReplies()
        _ = try await service.names(for: allReferences)
        let requestsAfterFirst = StubProtocol.requests.count
        let again = try await service.names(for: allReferences)
        XCTAssertEqual(StubProtocol.requests.count, requestsAfterFirst)
        XCTAssertEqual(again.count, 5)
    }

    func test_resetForgetsTheCache() async throws {
        seedNameReplies()
        _ = try await service.names(for: [DirectoryReference(kind: .group, id: group)])
        await service.reset()
        seedNameReplies()
        let before = StubProtocol.requests.count
        _ = try await service.names(for: [DirectoryReference(kind: .group, id: group)])
        XCTAssertGreaterThan(StubProtocol.requests.count, before)
    }

    func test_anEmptyReferenceSetMakesNoRequests() async throws {
        let names = try await service.names(for: [])
        XCTAssertTrue(names.isEmpty)
        XCTAssertTrue(StubProtocol.requests.isEmpty)
    }

    // MARK: who changed this

    func test_changesAreReadFromTheAuditLogWithTheAuditScope() async throws {
        let body = #"{"value":[{"id":"e1","activityDisplayName":"Update conditional access policy","activityDateTime":"2026-10-22T10:00:00Z","result":"success","initiatedBy":{"user":{"userPrincipalName":"sec@contoso.com","displayName":"Sec Admin"},"app":null},"targetResources":[{"id":"\#(policyId)","modifiedProperties":[{"displayName":"ConditionalAccessPolicy","oldValue":"x","newValue":"y"}]}]},{"id":"e2","activityDisplayName":"Update conditional access policy","activityDateTime":"2026-09-01T10:00:00Z","result":"success","initiatedBy":{"user":null,"app":{"displayName":"Automation","servicePrincipalName":null}},"targetResources":[]}]}"#
        StubProtocol.replies = ["directoryAudits": [.init(status: 200, body: body)]]
        let changes = try await service.changes(forPolicyId: policyId)
        XCTAssertEqual(changes.count, 2)
        XCTAssertEqual(changes[0].actor, "sec@contoso.com")
        XCTAssertEqual(changes[0].changedProperties, ["ConditionalAccessPolicy"])
        XCTAssertEqual(changes[0].result, "success")
        XCTAssertEqual(changes[1].actor, "Automation")
        XCTAssertEqual(changes[1].changedProperties, [])
        let sent = try XCTUnwrap(StubProtocol.requests.first)
        XCTAssertTrue(sent.url.removingPercentEncoding?.contains("t/id eq '" + policyId + "'") == true, sent.url)
        XCTAssertEqual(auth.calls.first?.scopes, ["AuditLog.Read.All", "Directory.Read.All"])
    }

    func test_changesRefuseANonGUIDWithoutANetworkCall() async throws {
        let changes = try await service.changes(forPolicyId: "x' or 1 eq 1")
        XCTAssertTrue(changes.isEmpty)
        XCTAssertTrue(StubProtocol.requests.isEmpty)
    }

    func test_changesMapAuditErrors() async {
        StubProtocol.replies = ["directoryAudits": [.init(status: 401, body: "{}")]]
        do {
            _ = try await service.changes(forPolicyId: policyId)
            XCTFail("expected consentRequired")
        } catch {
            XCTAssertEqual(error as? ConditionalAccessError, .consentRequired)
        }
    }
}
