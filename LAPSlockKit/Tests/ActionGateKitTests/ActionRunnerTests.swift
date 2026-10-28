import XCTest
import AuthKit
import PrivilegedAccessKit
@testable import ActionGateKit

// MARK: - doubles

private final class RecordingAuth: AuthManaging, @unchecked Sendable {
    var account = AdminAccount(
        id: "aaaaaaaa-1111-2222-3333-444455556666.4470dc21-a4b7-4729-a232-56d4c0eedf73",
        tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73",
        username: "admin@example.com",
        objectId: "aaaaaaaa-1111-2222-3333-444455556666")
    private(set) var calls: [(scopes: [String], claims: String?, interactive: Bool)] = []
    private let lock = NSLock()
    var currentAccount: AdminAccount? { get async { account } }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        lock.lock(); calls.append((scopes, nil, allowInteractive)); lock.unlock(); return "token"
    }
    func token(scopes: [String], claims: String?, allowInteractive: Bool) async throws -> String {
        lock.lock(); calls.append((scopes, claims, allowInteractive)); lock.unlock(); return "token-with-claims"
    }
    func signIn() async throws -> AdminAccount { account }
    func signOut(account: AdminAccount) async throws {}
}

private final class StubProtocol: URLProtocol {
    struct Reply { var status: Int; var body: String; var headers: [String: String] = [:] }
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
        let key = Self.replies.keys.first { url.contains($0) }
        let reply = key.flatMap { k -> Reply? in
            guard var queue = Self.replies[k], !queue.isEmpty else { return nil }
            let next = queue.removeFirst(); Self.replies[k] = queue; return next
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

private struct StubGate: RoleGateChecking {
    var active: Set<String>?
    var eligible: [EligibleAccess] = []
    func activeRoleTemplateIds() async throws -> Set<String> {
        guard let active else { throw ActionGateError.gateUnavailable }
        return active
    }
    func eligibleAccess() async -> [EligibleAccess] { eligible }
}

/// Counts the role checks, for the ones that should not happen.
private final class CountingGate: RoleGateChecking, @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    let error: Error?
    let active: Set<String>
    let eligible: [EligibleAccess]
    init(active: Set<String> = [], eligible: [EligibleAccess] = [], error: Error? = nil) {
        self.active = active
        self.eligible = eligible
        self.error = error
    }
    var calls: Int { lock.withLock { count } }
    func activeRoleTemplateIds() async throws -> Set<String> {
        lock.withLock { count += 1 }
        if let error { throw error }
        return active
    }
    func eligibleAccess() async -> [EligibleAccess] { eligible }
}

// MARK: - tests

final class ActionRunnerTests: XCTestCase {

    private let intuneAdmin = "3a2c62db-5318-420d-8d74-23affee5d9d5"
    private let globalAdmin = "62e90394-69f5-4237-9190-012177145e10"
    private let tenant = "4470dc21-a4b7-4729-a232-56d4c0eedf73"
    private var auth: RecordingAuth!
    private var log: InMemoryShiftLog!

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
        auth = RecordingAuth()
        log = InMemoryShiftLog()
    }

    private func runner(gate: any RoleGateChecking) -> ActionRunner {
        let graph = GraphClient(auth: auth, session: StubProtocol.session(), retryPolicy: .none, tracer: GraphResponseTracer(), sleep: { _ in })
        return ActionRunner(graph: graph, gate: gate, log: log, tenantId: { [tenant] in tenant }, now: { Date(timeIntervalSince1970: 1_800_000_000) })
    }

    private func restart(required: [String] = []) -> WriteAction {
        WriteAction(
            id: "device.restart",
            title: "Restart",
            tier: .confirm,
            target: ActionTarget(label: "LT-FIELD-207", id: "dev-1"),
            request: GraphRequest(method: .post, path: "/deviceManagement/managedDevices/dev-1/rebootNow", template: "/deviceManagement/managedDevices/{id}/rebootNow", scopes: ["DeviceManagementManagedDevices.PrivilegedOperations.All"]),
            requiredRoleTemplateIds: required,
            successCopy: "Restart requested.")
    }

    private var eligibleIntune: EligibleAccess {
        EligibleAccess(id: "elig-1", kind: .directoryRole(roleDefinitionId: intuneAdmin, directoryScopeId: "/"), displayName: "Intune Administrator", eligibilityEndsAt: nil)
    }

    func test_aSuccessfulPostIsRequestedOnceAndLogged() async {
        StubProtocol.replies = ["rebootNow": [.init(status: 204, body: "", headers: ["request-id": "req-1"])]]
        let outcome = await runner(gate: StubGate(active: [intuneAdmin])).run(restart(required: [intuneAdmin]))
        XCTAssertEqual(outcome, .requested(requestId: "req-1"))
        XCTAssertEqual(StubProtocol.requests.count, 1)
        XCTAssertEqual(StubProtocol.requests.first?.httpMethod, "POST")
        XCTAssertEqual(auth.calls.first?.interactive, false)
        let entries = await log.entries(tenantId: tenant)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries.first?.outcome, "requested")
        XCTAssertEqual(entries.first?.requestId, "req-1")
        XCTAssertEqual(entries.first?.line, "2027-01-15 08:00:00Z | Restart | LT-FIELD-207 (dev-1) | requested | request-id req-1")
    }

    func test_aGetIsRefusedBeforeSending() async {
        let action = WriteAction(id: "x", title: "X", tier: .none, target: ActionTarget(label: "t", id: "1"),
                                 request: GraphRequest(path: "/me", scopes: ["User.Read"]), successCopy: "")
        let outcome = await runner(gate: StubGate(active: [])).run(action)
        XCTAssertEqual(outcome, .failed(.refused(reason: "A read is not a write action.")))
        XCTAssertTrue(StubProtocol.requests.isEmpty)
        let entries = await log.entries(tenantId: tenant)
        XCTAssertEqual(entries.first?.outcome, "refused")
    }

    func test_aWriteMarkedAsAReadIsRefusedBeforeSending() async {
        // `readOnly` would give the POST a read's 429 retry in the Graph client, and a write
        // sent twice is the one thing the runner exists to prevent.
        var request = restart().request
        request.readOnly = true
        let action = WriteAction(id: "device.restart", title: "Restart", tier: .confirm,
                                 target: ActionTarget(label: "LT-FIELD-207", id: "dev-1"),
                                 request: request, successCopy: "Restart requested.")
        StubProtocol.replies = ["rebootNow": [.init(status: 204, body: "")]]
        let outcome = await runner(gate: StubGate(active: [])).run(action)
        XCTAssertEqual(outcome, .failed(.refused(reason: "A write cannot be marked as a read.")))
        XCTAssertTrue(StubProtocol.requests.isEmpty)
        let entries = await log.entries(tenantId: tenant)
        XCTAssertEqual(entries.first?.outcome, "refused")
    }

    func test_theGateOffersActivationWhenTheRoleIsEligibleButNotActive() async {
        let outcome = await runner(gate: StubGate(active: [], eligible: [eligibleIntune])).run(restart(required: [intuneAdmin, globalAdmin]))
        XCTAssertEqual(outcome, .needsActivation(eligible: [eligibleIntune]))
        XCTAssertTrue(StubProtocol.requests.isEmpty, "nothing is sent when the gate speaks")
        let entries = await log.entries(tenantId: tenant)
        XCTAssertEqual(entries.first?.outcome, "needsActivation")
    }

    func test_theGateLetsGraphDecideWhenItCannotReadOrNothingIsEligible() async {
        StubProtocol.replies = ["rebootNow": [.init(status: 204, body: ""), .init(status: 204, body: "")]]
        let unreadable = await runner(gate: StubGate(active: nil)).run(restart(required: [intuneAdmin]))
        XCTAssertTrue(unreadable.isRequested)
        let nothingEligible = await runner(gate: StubGate(active: [], eligible: [])).run(restart(required: [intuneAdmin]))
        XCTAssertTrue(nothingEligible.isRequested)
        XCTAssertEqual(StubProtocol.requests.count, 2)
    }

    func test_a403OffersWhateverIsEligible() async {
        StubProtocol.replies = ["rebootNow": [.init(status: 403, body: "{}", headers: ["request-id": "req-403"])]]
        let outcome = await runner(gate: StubGate(active: nil, eligible: [eligibleIntune])).run(restart())
        XCTAssertEqual(outcome, .notAuthorized(eligible: [eligibleIntune]))
        let entries = await log.entries(tenantId: tenant)
        XCTAssertEqual(entries.first?.outcome, "notAuthorized")
        XCTAssertEqual(entries.first?.requestId, "req-403")
    }

    func test_a401WithAClaimsChallengeIsHandedBackNotRetried() async throws {
        let claims = #"{"access_token":{"acrs":{"essential":true,"value":"c1"}}}"#
        let encoded = Data(claims.utf8).base64EncodedString()
        StubProtocol.replies = ["rebootNow": [.init(status: 401, body: "", headers: ["WWW-Authenticate": "Bearer realm=\"\", error=\"insufficient_claims\", claims=\"\(encoded)\""])]]
        let outcome = await runner(gate: StubGate(active: nil)).run(restart())
        guard case .challenged(let challenge) = outcome else { return XCTFail("expected challenge, got \(outcome)") }
        XCTAssertEqual(challenge.json, claims)
        XCTAssertEqual(StubProtocol.requests.count, 1)
    }

    func test_a400WithClaimsInTheMessageIsAChallengeToo() async {
        let body = #"{"error":{"code":"RoleAssignmentRequestAcrsValidationFailed","message":"The required claims are missing: claims={\"access_token\":{\"acrs\":{\"essential\":true,\"value\":\"c1\"}}}"}}"#
        StubProtocol.replies = ["rebootNow": [.init(status: 400, body: body)]]
        let outcome = await runner(gate: StubGate(active: nil)).run(restart())
        guard case .challenged = outcome else { return XCTFail("expected challenge, got \(outcome)") }
    }

    func test_resumeSendsOnceWithClaimsInteractivelyAndStopsOnASecondChallenge() async {
        let claims = #"{"access_token":{"acrs":{"essential":true,"value":"c1"}}}"#
        let encoded = Data(claims.utf8).base64EncodedString()
        let challengeReply = StubProtocol.Reply(status: 401, body: "", headers: ["WWW-Authenticate": "Bearer claims=\"\(encoded)\""])
        StubProtocol.replies = ["rebootNow": [.init(status: 204, body: "", headers: ["request-id": "req-2"]), challengeReply]]
        let r = runner(gate: StubGate(active: nil))
        let challenge = ClaimsChallenge(json: claims)!
        let first = await r.resume(restart(), satisfying: challenge)
        XCTAssertEqual(first, .requested(requestId: "req-2"))
        XCTAssertEqual(auth.calls.last?.claims, claims)
        XCTAssertEqual(auth.calls.last?.interactive, true)
        let second = await r.resume(restart(), satisfying: challenge)
        guard case .failed(.refused) = second else { return XCTFail("a second challenge must stop, got \(second)") }
        XCTAssertEqual(StubProtocol.requests.count, 2)
    }

    func test_a429IsNeverRetried() async {
        StubProtocol.replies = ["rebootNow": [.init(status: 429, body: "", headers: ["Retry-After": "7"]), .init(status: 204, body: "")]]
        let outcome = await runner(gate: StubGate(active: nil)).run(restart())
        XCTAssertEqual(outcome, .failed(.throttled(retryAfter: 7)))
        XCTAssertEqual(StubProtocol.requests.count, 1)
    }

    func test_otherStatusesMap() async {
        StubProtocol.replies = ["rebootNow": [
            .init(status: 404, body: ""), .init(status: 503, body: ""), .init(status: 400, body: #"{"error":{"code":"BadRequest","message":"x"}}"#), .init(status: 418, body: "")
        ]]
        let r = runner(gate: StubGate(active: nil))
        var outcomes: [ActionOutcome] = []
        for _ in 0..<4 { outcomes.append(await r.run(restart())) }
        XCTAssertEqual(outcomes, [.failed(.notFound), .failed(.serviceUnavailable(status: 503)), .failed(.badRequest(code: "BadRequest")), .failed(.transport(status: 418))])
        let entries = await log.entries(tenantId: tenant)
        XCTAssertEqual(entries.count, 4)
    }

    func test_patchAndDeleteAreWritesToo() async {
        StubProtocol.replies = ["users/u1": [.init(status: 204, body: ""), .init(status: 204, body: "")]]
        let r = runner(gate: StubGate(active: nil))
        for method in [GraphRequest.Method.patch, .delete] {
            let action = WriteAction(id: "user.x", title: "X", tier: .confirm, target: ActionTarget(label: "u", id: "u1"),
                                     request: GraphRequest(method: method, path: "/users/u1", scopes: ["S"]), successCopy: "")
            let outcome = await r.run(action)
            XCTAssertTrue(outcome.isRequested, "\(method)")
        }
        XCTAssertEqual(StubProtocol.requests.map(\.httpMethod), ["PATCH", "DELETE"])
    }

    func test_checkRolesAndLogForAWriteMadeElsewhere() async {
        let r = runner(gate: StubGate(active: [], eligible: [eligibleIntune]))
        let action = restart(required: [intuneAdmin])
        let gate = await r.checkRoles(action)
        XCTAssertEqual(gate, .needsActivation(eligible: [eligibleIntune]))
        await r.log(action, outcome: .requested(requestId: "r9"), requestId: "r9")
        let entries = await log.entries(tenantId: tenant)
        XCTAssertEqual(entries.first?.requestId, "r9")
        XCTAssertTrue(StubProtocol.requests.isEmpty, "checking and logging send nothing")
    }

    // MARK: the role check's cost (OPTIMIZATION-PLAN.md, step G)

    func test_aRoleCheckWithoutConsentIsNotTriedAgainUntilTheOptIn() async {
        StubProtocol.replies = ["rebootNow": (0..<3).map { _ in .init(status: 204, body: "") }]
        let gate = CountingGate(error: GraphError.consentRequired)
        let runner = runner(gate: gate)
        let first = await runner.run(restart(required: [intuneAdmin]))
        let second = await runner.run(restart(required: [intuneAdmin]))
        XCTAssertEqual(first, .requested(requestId: nil))
        XCTAssertEqual(second, .requested(requestId: nil), "the same outcome as before: Graph decides")
        XCTAssertEqual(gate.calls, 1, "no silent token attempt for every write")
        await runner.roleCheckMayWork()
        _ = await runner.run(restart(required: [intuneAdmin]))
        XCTAssertEqual(gate.calls, 2, "tried again once the opt-in is granted")
    }

    func test_aRoleCheckThatFailsForAnotherReasonIsTriedAgain() async {
        StubProtocol.replies = ["rebootNow": (0..<2).map { _ in .init(status: 204, body: "") }]
        let gate = CountingGate(error: ActionGateError.gateUnavailable)
        let runner = runner(gate: gate)
        _ = await runner.run(restart(required: [intuneAdmin]))
        _ = await runner.run(restart(required: [intuneAdmin]))
        XCTAssertEqual(gate.calls, 2)
    }

    func test_aWriteInASeriesAlreadyCheckedIsSentOnceAndLoggedWithoutAnotherCheck() async {
        StubProtocol.replies = ["rebootNow": [.init(status: 204, body: "")]]
        let gate = CountingGate(active: [], eligible: [eligibleIntune])
        let outcome = await runner(gate: gate).run(restart(required: [intuneAdmin]), checkingRoles: false)
        XCTAssertEqual(outcome, .requested(requestId: nil))
        XCTAssertEqual(gate.calls, 0)
        XCTAssertEqual(StubProtocol.requests.count, 1)
        let entries = await log.entries(tenantId: tenant)
        XCTAssertEqual(entries.count, 1)
    }

    func test_strictMovesEveryTierUpOne() {
        XCTAssertEqual(ActionTier.none.effective(strict: false), .none)
        XCTAssertEqual(ActionTier.none.effective(strict: true), .confirm)
        XCTAssertEqual(ActionTier.confirm.effective(strict: true), .destructive)
        XCTAssertEqual(ActionTier.destructive.effective(strict: true), .destructive)
    }

    func test_tiersDeclareTheirRequirements() {
        XCTAssertEqual(ActionTier.none.requirements, [])
        XCTAssertEqual(ActionTier.confirm.requirements, [.confirmSheet])
        XCTAssertEqual(ActionTier.destructive.requirements, [.typedName, .appLockReprompt, .undoWindow(seconds: 10)])
    }

    func test_failureCopyNeverPromisesWhatDidNotHappen() {
        for failure in [ActionFailure.serviceUnavailable(status: 503), .transport(status: -1)] {
            XCTAssertTrue(failure.description.contains("Nothing was") , failure.description)
        }
    }
}
