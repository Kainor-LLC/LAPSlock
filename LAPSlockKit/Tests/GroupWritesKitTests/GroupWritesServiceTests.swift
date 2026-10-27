import XCTest
import AuthKit
import ActionGateKit
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
