import XCTest
import AuthKit
import ActionGateKit
@testable import UserActionsKit

private final class StaticAuth: AuthManaging, @unchecked Sendable {
    var currentAccount: AdminAccount? { get async { AdminAccount(id: "a.b", tenantId: "t", username: "admin@example.com", objectId: "a") } }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String { "token" }
    func signIn() async throws -> AdminAccount { AdminAccount(id: "a.b", tenantId: "t", username: "admin@example.com", objectId: "a") }
    func signOut(account: AdminAccount) async throws {}
}

private final class DevicesStub: URLProtocol {
    nonisolated(unsafe) static var status = 200
    nonisolated(unsafe) static var body = "{}"
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let response = HTTPURLResponse(url: request.url!, statusCode: Self.status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(Self.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
    static func session() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [DevicesStub.self]
        return URLSession(configuration: cfg)
    }
}

/// The Graph change watch found this on its first live run: Intune answers 404 for a person
/// it does not know, such as one whose Intune license is gone, which is common for a leaver.
final class UserDevicesServiceTests: XCTestCase {

    private func service() -> UserActionsService {
        let graph = GraphClient(auth: StaticAuth(), session: DevicesStub.session(), retryPolicy: .none, tracer: GraphResponseTracer(), sleep: { _ in })
        let log = InMemoryShiftLog()
        let runner = ActionRunner(graph: graph, gate: NoRoleGate(), log: log, tenantId: { "t" }, now: { Date() })
        return UserActionsService(graph: graph, runner: runner, log: log, tenantId: { "t" })
    }

    private let target = UserActionTarget(userId: "u1", userPrincipalName: "leaver@example.com", displayName: "Leaver")

    func testAPersonIntuneDoesNotKnowHasNoDevices() async throws {
        DevicesStub.status = 404
        DevicesStub.body = #"{"error":{"code":"ResourceNotFound","message":"not found"}}"#
        let devices = try await service().devices(of: target)
        XCTAssertEqual(devices, [])
    }

    func testOtherFailuresStillThrow() async {
        DevicesStub.status = 403
        DevicesStub.body = #"{"error":{"code":"Forbidden","message":"no"}}"#
        do {
            _ = try await service().devices(of: target)
            XCTFail("a 403 is not the same as no devices")
        } catch {}
    }
}
