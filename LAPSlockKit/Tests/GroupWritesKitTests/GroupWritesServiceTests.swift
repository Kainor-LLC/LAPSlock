import XCTest
import AuthKit
import ActionGateKit
import PrivilegedAccessKit
@testable import GroupWritesKit

private final class StaticAuth: AuthManaging, @unchecked Sendable {
    var currentAccount: AdminAccount? { get async { AdminAccount(id: "a.b", tenantId: "t", username: "admin@example.com", objectId: "a") } }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String { "token" }
    func signIn() async throws -> AdminAccount { AdminAccount(id: "a.b", tenantId: "t", username: "admin@example.com", objectId: "a") }
    func signOut(account: AdminAccount) async throws {}
}

/// Answers by path: the PIM read with a chosen status, everything else empty.
private final class RouteStub: URLProtocol {
    nonisolated(unsafe) static var pimStatus = 200
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let path = request.url?.path ?? ""
        var status = 200
        var body = #"{"value":[]}"#
        if path.contains("eligibilitySchedules") {
            status = Self.pimStatus
            if status != 200 { body = #"{"error":{"code":"x","message":"x"}}"# }
        } else if path.hasSuffix("$count") {
            body = "4"
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
    static func session() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [RouteStub.self]
        return URLSession(configuration: cfg)
    }
}

/// The Graph change watch's second live run: PIM for groups answers 404 when it has nothing
/// for a group. That is "not managed by PIM", or every group would demand the typed name.
final class GroupWritesServiceTests: XCTestCase {

    private func facts(pimStatus: Int) async -> GroupFacts {
        RouteStub.pimStatus = pimStatus
        let graph = GraphClient(auth: StaticAuth(), session: RouteStub.session(), retryPolicy: .none, tracer: GraphResponseTracer(), sleep: { _ in })
        let log = InMemoryShiftLog()
        let runner = ActionRunner(graph: graph, gate: NoRoleGate(), log: log, tenantId: { "t" }, now: { Date() })
        let service = GroupWritesService(graph: graph, runner: runner, log: log, tenantId: { "t" })
        return await service.facts(for: DirectoryGroup(id: "g1", displayName: "HD-VPN"), in: GroupWriteContext())
    }

    func testPIMNotFoundMeansNotManaged() async {
        let found = await facts(pimStatus: 404)
        XCTAssertEqual(found.pim, .none)
        XCTAssertEqual(found.memberCount, 4)
        XCTAssertEqual(found.grantsAppAccess, false)
    }

    func testPIMRefusedStaysUnknown() async {
        let found = await facts(pimStatus: 403)
        XCTAssertEqual(found.pim, .unknown)
    }

    func testPIMEmptyMeansNotManaged() async {
        let found = await facts(pimStatus: 200)
        XCTAssertEqual(found.pim, .none)
    }
}

// MARK: - the context and the reads around it (OPTIMIZATION-PLAN.md, step G)

/// Records every request. The administrative unit's answer is held until the owned groups
/// and the policies have been asked for, or two seconds pass, so the test can tell whether
/// the three reads really start together.
private final class ContextStub: URLProtocol {
    nonisolated(unsafe) static var sent: [String] = []
    nonisolated(unsafe) static var unitWaitedForTheOthers: Bool?
    static let lock = NSLock()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    static func reset() { lock.withLock { sent = []; unitWaitedForTheOthers = nil } }
    static func count(_ fragment: String) -> Int { lock.withLock { sent.filter { $0.contains(fragment) }.count } }
    static var total: Int { lock.withLock { sent.count } }
    override func startLoading() {
        let url = request.url?.absoluteString ?? ""
        Self.lock.withLock { Self.sent.append(url.removingPercentEncoding ?? url) }
        let body: String
        if url.contains("administrativeUnits?") || (url.contains("administrativeUnits") && !url.contains("/members")) {
            body = #"{"value":[{"id":"au1"}]}"#
            let deadline = Date().addingTimeInterval(2)
            DispatchQueue.global().async {
                while Date() < deadline, !(Self.count("ownedObjects") > 0 && Self.count("conditionalAccess") > 0) { usleep(5_000) }
                let together = Self.count("ownedObjects") > 0 && Self.count("conditionalAccess") > 0
                Self.lock.withLock { if Self.unitWaitedForTheOthers == nil { Self.unitWaitedForTheOthers = together } }
                self.answer(body)
            }
            return
        }
        if url.contains("/members") { body = #"{"value":[{"id":"g-unit"}]}"# }
        else if url.contains("ownedObjects") { body = #"{"value":[{"id":"g-owned"}]}"# }
        else if url.contains("conditionalAccess") { body = #"{"value":[{"displayName":"Pilot","state":"enabled","conditions":{"users":{"includeGroups":["g-ca"]}}}]}"# }
        else { body = #"{"value":[]}"# }
        answer(body)
    }
    private func answer(_ body: String) {
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
    static func session() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [ContextStub.self]
        return URLSession(configuration: cfg)
    }
}

private final class Clock: @unchecked Sendable {
    var now = Date(timeIntervalSince1970: 1_800_000_000)
}

private final class CountingGate: RoleGateChecking, @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var calls: Int { lock.withLock { count } }
    func activeRoleTemplateIds() async throws -> Set<String> {
        lock.withLock { count += 1 }
        return []
    }
    func eligibleAccess() async -> [EligibleAccess] { [] }
}

final class GroupWritesContextTests: XCTestCase {

    private let clock = Clock()

    override func setUp() {
        super.setUp()
        ContextStub.reset()
    }

    private func service(gate: any RoleGateChecking = NoRoleGate()) -> GroupWritesService {
        let graph = GraphClient(auth: StaticAuth(), session: ContextStub.session(), retryPolicy: .none, tracer: GraphResponseTracer(), sleep: { _ in })
        let log = InMemoryShiftLog()
        let runner = ActionRunner(graph: graph, gate: gate, log: log, tenantId: { "t" }, now: { Date() })
        return GroupWritesService(graph: graph, runner: runner, log: log, tenantId: { "t" }, now: { [clock] in clock.now })
    }

    func test_theThreeContextReadsStartTogether() async {
        let context = await service().context(administrativeUnit: "Helpdesk")
        XCTAssertEqual(ContextStub.unitWaitedForTheOthers, true, "owned groups and policies were asked for while the unit was still answering")
        XCTAssertTrue(context.administrativeUnitFound)
        XCTAssertEqual(context.administrativeUnitGroupIds, ["g-unit"])
        XCTAssertEqual(context.ownedGroupIds, ["g-owned"])
        XCTAssertEqual(context.conditionalAccessIncludes["g-ca"], ["Pilot"])
        XCTAssertTrue(context.conditionalAccessKnown)
    }

    func test_theContextLastsTenMinutes() async {
        let service = service()
        _ = await service.context(administrativeUnit: "Helpdesk")
        let afterFirst = ContextStub.total
        XCTAssertEqual(afterFirst, 4, "the unit, its groups, owned groups and the policies")
        clock.now += 9 * 60
        _ = await service.context(administrativeUnit: "Helpdesk")
        XCTAssertEqual(ContextStub.total, afterFirst, "used again within ten minutes")
        clock.now += 2 * 60
        _ = await service.context(administrativeUnit: "Helpdesk")
        XCTAssertEqual(ContextStub.total, afterFirst * 2, "read again after ten")
    }

    func test_aPersonsGroupsAreOneRequestOf999() async throws {
        _ = try await service().groups(of: GroupMember(userId: "u-1", label: "Jane"))
        let sent = ContextStub.sent.filter { $0.contains("memberOf") }
        XCTAssertEqual(sent.count, 1)
        XCTAssertTrue(sent.first?.contains("$top=999") == true, sent.first ?? "")
    }

    func test_theReviewSheetsRoleCheckIsTheRunnersCheck() async {
        let gate = CountingGate()
        let policy = GroupWritePolicy(mode: .all, prefix: nil, administrativeUnit: "Helpdesk")
        let group = DirectoryGroup(id: "g1", displayName: "HD-VPN")
        let decision = policy.decide(group, GroupWriteContext().facts(for: group, pim: .none, grantsAppAccess: false, memberCount: 3), adding: false)
        let action = GroupWriteKind.remove.action(group: group, member: GroupMember(userId: "u-1", label: "Jane"), decision: decision, strict: false)
        XCTAssertFalse(action.requiredRoleTemplateIds.isEmpty, "a group the person does not own needs a groups role")
        _ = await service(gate: gate).checkRoles(action)
        XCTAssertEqual(gate.calls, 1)
        XCTAssertTrue(ContextStub.sent.isEmpty, "a check sends nothing to the group")
    }
}
