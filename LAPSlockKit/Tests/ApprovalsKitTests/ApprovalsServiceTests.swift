import XCTest
import AuthKit
import ActionGateKit
import PrivilegedAccessKit
@testable import ApprovalsKit

// The live service against a stub network (OPTIMIZATION-PLAN.md, step G): what the lists
// expand, the stage read when the decision sheet opens, and the background check's ids.

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

/// Replies keyed by "METHOD|path suffix", so a stage's GET and its PATCH never share one.
private final class StubProtocol: URLProtocol {
    struct Reply { var status: Int; var body: String }
    nonisolated(unsafe) static var replies: [String: [Reply]] = [:]
    nonisolated(unsafe) static var sent: [(line: String, query: String)] = []
    static let lock = NSLock()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock()
        let line = (request.httpMethod ?? "") + "|" + (request.url?.path ?? "")
        Self.sent.append((line, request.url?.query?.removingPercentEncoding ?? ""))
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
    static func queries(_ suffix: String) -> [String] {
        lock.withLock { sent.filter { $0.line.hasSuffix(suffix) }.map(\.query) }
    }
    static func count(_ prefix: String) -> Int {
        lock.withLock { sent.filter { $0.line.hasPrefix(prefix) }.count }
    }
}

private struct OpenGate: RoleGateChecking {
    func activeRoleTemplateIds() async throws -> Set<String> { [] }
    func eligibleAccess() async -> [EligibleAccess] { [] }
}

private final class Clock: @unchecked Sendable {
    var now = Date(timeIntervalSince1970: 1_800_000_000)
}

final class ApprovalsServiceTests: XCTestCase {

    private let roles = "roleAssignmentScheduleRequests/filterByCurrentUser(on='approver')"
    private let groups = "group/assignmentScheduleRequests/filterByCurrentUser(on='approver')"
    private let clock = Clock()

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
    }

    private func service() -> ApprovalsService {
        let graph = GraphClient(auth: RecordingAuth(), session: StubProtocol.session(), retryPolicy: .none, tracer: GraphResponseTracer(), sleep: { _ in })
        let log = InMemoryShiftLog()
        let runner = ActionRunner(graph: graph, gate: OpenGate(), log: log, tenantId: { "t" })
        return ApprovalsService(graph: graph, runner: runner, log: log, tenantId: { "t" }, now: { [clock] in clock.now })
    }

    private let roleList = #"{"value":[{"id":"req-1","approvalId":"ap-1","status":"PendingApproval","principal":{"displayName":"Sam Reyes"},"roleDefinition":{"displayName":"Exchange Administrator"}},{"id":"req-9","status":"PendingApproval"}]}"#
    private let groupList = #"{"value":[{"id":"req-2","approvalId":"ap-2","status":"PendingApproval","accessId":"member","principal":{"displayName":"Priya"},"group":{"displayName":"Ops On-Call"}}]}"#
    private let myStage = #"{"value":[{"id":"st-other","assignedToMe":false,"status":"InProgress"},{"id":"st1","assignedToMe":true,"status":"InProgress"}]}"#

    private var groupRequest: PendingApproval {
        PendingApproval(id: "req-2", kind: .group, approvalId: "ap-2", requester: "Priya", requesterUPN: nil, target: "Ops On-Call",
                        access: "member", justification: nil, ticket: nil, requested: nil, start: nil, duration: nil)
    }

    func test_theListsBringTheRoleAndGroupWithTheirNamesOnly() async throws {
        StubProtocol.replies = ["GET|" + roles: [.init(status: 200, body: roleList)], "GET|" + groups: [.init(status: 200, body: groupList)]]
        let pending = try await service().pending()
        XCTAssertEqual(Set(pending.map(\.target)), ["Exchange Administrator", "Ops On-Call"])
        XCTAssertTrue(StubProtocol.queries(roles).first?.contains("$expand=principal,roleDefinition($select=id,displayName)") == true, "\(StubProtocol.queries(roles))")
        XCTAssertTrue(StubProtocol.queries(groups).first?.contains("$expand=principal,group($select=id,displayName)") == true, "\(StubProtocol.queries(groups))")
    }

    func test_aRefusedTrimmedExpandIsNotSentAgain() async throws {
        let refused = StubProtocol.Reply(status: 400, body: #"{"error":{"code":"BadRequest"}}"#)
        StubProtocol.replies = [
            "GET|" + roles: [refused, .init(status: 200, body: roleList), .init(status: 200, body: roleList)],
            "GET|" + groups: [.init(status: 200, body: groupList), .init(status: 200, body: groupList)],
        ]
        let service = service()
        let first = try await service.pending()
        XCTAssertEqual(first.count, 2)
        _ = try await service.pending()
        let roleQueries = StubProtocol.queries(roles)
        XCTAssertEqual(roleQueries.count, 3)
        XCTAssertTrue(roleQueries[1].contains("$expand=principal,roleDefinition") && !roleQueries[1].contains("$select"), roleQueries[1])
        XCTAssertFalse(roleQueries[2].contains("$select"), "not tried again this session")
        XCTAssertFalse(StubProtocol.queries(groups).last?.contains("$select") ?? true)
    }

    func test_theStageFoundWhenTheSheetOpenedIsUsedAtTheTap() async {
        StubProtocol.replies = ["GET|ap-2/stages": [.init(status: 200, body: myStage)], "PATCH|ap-2/stages/st1": [.init(status: 204, body: "")]]
        let service = service()
        let ready = await service.prepare(groupRequest)
        XCTAssertNil(ready)
        clock.now += 60
        let outcome = await service.decide(groupRequest, .approve, justification: "Covering the rota")
        XCTAssertEqual(outcome, .requested(requestId: nil))
        XCTAssertEqual(StubProtocol.count("GET|"), 1, "the stage is not read again at the tap")
        XCTAssertEqual(StubProtocol.count("PATCH|"), 1)
    }

    func test_aStageReadMoreThanTwoMinutesAgoIsReadAgain() async {
        StubProtocol.replies = ["GET|ap-2/stages": [.init(status: 200, body: myStage), .init(status: 200, body: myStage)],
                                "PATCH|ap-2/stages/st1": [.init(status: 204, body: "")]]
        let service = service()
        _ = await service.prepare(groupRequest)
        clock.now += 121
        let outcome = await service.decide(groupRequest, .deny, justification: "Not on the rota")
        XCTAssertEqual(outcome, .requested(requestId: nil))
        XCTAssertEqual(StubProtocol.count("GET|"), 2)
    }

    func test_aRequestThatNoLongerNeedsMeSaysSoWhenTheSheetOpens() async {
        StubProtocol.replies = ["GET|ap-2/stages": [.init(status: 200, body: #"{"value":[{"id":"st1","assignedToMe":true,"status":"Completed"}]}"#)]]
        let found = await service().prepare(groupRequest)
        XCTAssertEqual(found, .nothingToDecide)
        XCTAssertEqual(StubProtocol.count("PATCH|"), 0)
    }

    func test_aDecisionWithoutASheetStillFindsTheStage() async {
        StubProtocol.replies = ["GET|ap-2/stages": [.init(status: 200, body: myStage)], "PATCH|ap-2/stages/st1": [.init(status: 204, body: "")]]
        let outcome = await service().decide(groupRequest, .approve, justification: "From the watch")
        XCTAssertEqual(outcome, .requested(requestId: nil))
        XCTAssertEqual(StubProtocol.count("GET|"), 1)
    }

    func test_theBackgroundIdsAreTheFullReadsIdsWithNothingExpanded() async throws {
        StubProtocol.replies = [
            "GET|" + roles: [.init(status: 200, body: roleList), .init(status: 200, body: roleList)],
            "GET|" + groups: [.init(status: 200, body: groupList), .init(status: 200, body: groupList)],
        ]
        let service = service()
        let ids = try await service.pendingIds()
        let full = try await service.pending()
        XCTAssertEqual(ids, Set(full.map(\.id)))
        XCTAssertEqual(ids, ["req-1", "req-2"], "a request without an approval is left out, as the full read leaves it out")
        let first = StubProtocol.queries(roles).first ?? ""
        XCTAssertTrue(first.contains("$select=id,approvalId,status") && !first.contains("$expand"), first)
    }

    func test_aRefusedIdReadFallsBackToTheFullList() async throws {
        StubProtocol.replies = [
            "GET|" + roles: [.init(status: 400, body: "{}"), .init(status: 200, body: roleList)],
            "GET|" + groups: [.init(status: 200, body: groupList)],
        ]
        let ids = try await service().pendingIds()
        XCTAssertEqual(ids, ["req-1", "req-2"])
    }
}
