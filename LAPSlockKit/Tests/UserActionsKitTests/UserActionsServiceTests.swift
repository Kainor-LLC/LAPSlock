import XCTest
import AuthKit
import ActionGateKit
import PrivilegedAccessKit
@testable import UserActionsKit

// The sign-in method wipe against a stub network (OPTIMIZATION-PLAN.md, step G, DEV-8 b):
// one role check for the whole change, every DELETE sent once and logged, and the first
// refusal stopping the rest.

private final class RecordingAuth: AuthManaging, @unchecked Sendable {
    let account = AdminAccount(
        id: "aaaaaaaa-1111-2222-3333-444455556666.4470dc21-a4b7-4729-a232-56d4c0eedf73",
        tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73",
        username: "admin@example.com",
        objectId: "aaaaaaaa-1111-2222-3333-444455556666")
    var currentAccount: AdminAccount? { get async { account } }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String { "token" }
    func token(scopes: [String], claims: String?, allowInteractive: Bool) async throws -> String { "token" }
    func signIn() async throws -> AdminAccount { account }
    func signOut(account: AdminAccount) async throws {}
}

/// Replies keyed by "METHOD|path suffix".
private final class StubProtocol: URLProtocol {
    struct Reply { var status: Int; var body: String }
    nonisolated(unsafe) static var replies: [String: [Reply]] = [:]
    nonisolated(unsafe) static var sent: [String] = []
    static let lock = NSLock()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock()
        let line = (request.httpMethod ?? "") + "|" + (request.url?.path ?? "")
        Self.sent.append(line)
        let key = Self.replies.keys.first { key in
            let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
            return line.hasPrefix(parts[0] + "|") && line.hasSuffix(parts[1])
        }
        let reply = key.flatMap { k -> Reply? in
            guard var queue = Self.replies[k], !queue.isEmpty else { return nil }
            let next = queue.removeFirst(); Self.replies[k] = queue; return next
        } ?? Reply(status: 599, body: "{}")
        Self.lock.unlock()
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(reply.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
    static func reset() { replies = [:]; sent = [] }
    static func session() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: cfg)
    }
    static func count(_ prefix: String) -> Int { lock.withLock { sent.filter { $0.hasPrefix(prefix) }.count } }
}

private final class CountingGate: RoleGateChecking, @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    let active: Set<String>
    init(active: Set<String>) { self.active = active }
    var calls: Int { lock.withLock { count } }
    func activeRoleTemplateIds() async throws -> Set<String> {
        lock.withLock { count += 1 }
        return active
    }
    func eligibleAccess() async -> [EligibleAccess] { [] }
}

final class UserActionsServiceTests: XCTestCase {

    private let jane = UserActionTarget(userId: "u-1", userPrincipalName: "jane.okafor@demo.example", displayName: "Jane Okafor")
    private let tenant = "4470dc21-a4b7-4729-a232-56d4c0eedf73"
    private let methods = ##"{"value":[{"id":"pw","@odata.type":"#microsoft.graph.passwordAuthenticationMethod"},{"id":"m1","@odata.type":"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"},{"id":"p1","@odata.type":"#microsoft.graph.phoneAuthenticationMethod"},{"id":"f1","@odata.type":"#microsoft.graph.fido2AuthenticationMethod"}]}"##

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
    }

    private func service(_ gate: CountingGate, log: InMemoryShiftLog) -> UserActionsService {
        let graph = GraphClient(auth: RecordingAuth(), session: StubProtocol.session(), retryPolicy: .none, tracer: GraphResponseTracer(), sleep: { _ in })
        let runner = ActionRunner(graph: graph, gate: gate, log: log, tenantId: { [tenant] in tenant })
        return UserActionsService(graph: graph, runner: runner, log: log, tenantId: { [tenant] in tenant })
    }

    private var holdsTheRole: CountingGate {
        CountingGate(active: Set(UserActionKind.authenticationWipe.requiredRoles.map { $0.lowercased() }))
    }

    func test_theWipeChecksTheRoleOnceAndLogsEveryRemoval() async {
        StubProtocol.replies = [
            "GET|/authentication/methods": [.init(status: 200, body: methods)],
            "DELETE|microsoftAuthenticatorMethods/m1": [.init(status: 204, body: "")],
            "DELETE|phoneMethods/p1": [.init(status: 204, body: "")],
            "DELETE|fido2Methods/f1": [.init(status: 204, body: "")],
        ]
        let gate = holdsTheRole
        let log = InMemoryShiftLog()
        let result = await service(gate, log: log).authenticationWipe(jane, satisfying: nil)
        XCTAssertEqual(result.outcome, .requested(requestId: nil))
        XCTAssertEqual(result.removed.count, 3)
        XCTAssertEqual(result.kept, ["Password"])
        XCTAssertEqual(gate.calls, 1, "one role check for the change, not one per method")
        XCTAssertEqual(StubProtocol.count("DELETE|"), 3)
        let entries = await log.entries(tenantId: tenant)
        XCTAssertEqual(entries.count, 3, "each removal still logged")
    }

    func test_aRefusalPartWayStopsTheRest() async {
        StubProtocol.replies = [
            "GET|/authentication/methods": [.init(status: 200, body: methods)],
            "DELETE|microsoftAuthenticatorMethods/m1": [.init(status: 204, body: "")],
            "DELETE|phoneMethods/p1": [.init(status: 403, body: "{}")],
            "DELETE|fido2Methods/f1": [.init(status: 204, body: "")],
        ]
        let gate = holdsTheRole
        let result = await service(gate, log: InMemoryShiftLog()).authenticationWipe(jane, satisfying: nil)
        XCTAssertEqual(result.removed.count, 1)
        if case .notAuthorized = result.outcome {} else { XCTFail("expected the refusal, got \(String(describing: result.outcome))") }
        XCTAssertEqual(StubProtocol.count("DELETE|"), 2, "nothing is sent after the refusal")
        XCTAssertEqual(gate.calls, 1)
    }
}
