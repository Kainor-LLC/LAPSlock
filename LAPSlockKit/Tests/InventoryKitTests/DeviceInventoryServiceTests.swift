import XCTest
import AuthKit
@testable import InventoryKit

/// Answers inventory requests from a script: the first page, then the pages its next links
/// name, each after an optional delay so a reset can land while one is out.
private final class InventoryStub: URLProtocol, @unchecked Sendable {
    struct Reply { var body: String; var delay: TimeInterval = 0 }
    nonisolated(unsafe) static var replies: [Reply] = []
    nonisolated(unsafe) static var requested: [URL] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requested.append(request.url!)
        let reply = Self.replies.isEmpty ? Reply(body: #"{"value":[]}"#) : Self.replies.removeFirst()
        DispatchQueue.global().asyncAfter(deadline: .now() + reply.delay) { [self] in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(reply.body.utf8))
            client?.urlProtocolDidFinishLoading(self)
        }
    }
    override func stopLoading() {}

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [InventoryStub.self]
        return URLSession(configuration: config)
    }
}

private actor SwitchableAuth: AuthManaging {
    var operating: String
    init(operating: String) { self.operating = operating }
    func move(to tenant: String) { operating = tenant }
    var currentAccount: AdminAccount? {
        AdminAccount(id: "a.t", tenantId: "home", username: "admin@example.com")
    }
    var operatingTenantId: String? { operating }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String { "t" }
    func signIn() async throws -> AdminAccount { throw AuthError.userCancelled }
    func signOut(account: AdminAccount) async throws {}
}

final class DeviceInventoryServiceTests: XCTestCase {

    private let nextLink = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=p2"

    override func setUp() {
        InventoryStub.replies = []
        InventoryStub.requested = []
    }

    private func page(_ ids: [String], next: String? = nil) -> String {
        let devices = ids.map { #"{"id":"\#($0)","deviceName":"\#($0)","operatingSystem":"Windows"}"# }
        let link = next.map { #","@odata.nextLink":"\#($0)""# } ?? ""
        return #"{"value":["# + devices.joined(separator: ",") + "]" + link + "}"
    }

    func test_theCacheIsKeyedByTheOperatingTenantNotTheHomeTenant() async throws {
        let auth = SwitchableAuth(operating: "Customer")
        let service = DeviceInventoryService(auth: auth, session: InventoryStub.session())
        InventoryStub.replies = [.init(body: page(["d1", "d2"]))]
        try await service.loadFirstPage()
        let inCustomer = try await service.cachedDevices()
        XCTAssertEqual(inCustomer.map(\.id), ["d1", "d2"])

        await auth.move(to: "home")
        let atHome = try await service.cachedDevices()
        XCTAssertTrue(atHome.isEmpty, "the customer's devices are not the home tenant's")
    }

    func test_aPageThatLandsAfterAResetIsDropped() async throws {
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), session: InventoryStub.session())
        InventoryStub.replies = [.init(body: page(["d1"], next: nextLink)),
                                 .init(body: page(["late"]), delay: 0.3)]
        try await service.loadFirstPage()
        let late = Task { try await service.loadNextPage() }
        try await Task.sleep(for: .milliseconds(50))
        await service.reset()
        do {
            _ = try await late.value
            XCTFail("expected the stale page to be dropped")
        } catch is CancellationError {
        }
        let devices = try await service.cachedDevices()
        XCTAssertTrue(devices.isEmpty)
        let more = try await service.hasMore()
        XCTAssertFalse(more)
    }

    func test_aFirstPageOvertakenByARefreshDoesNotReplaceIt() async throws {
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), session: InventoryStub.session())
        InventoryStub.replies = [.init(body: page(["old"], next: nextLink), delay: 0.3),
                                 .init(body: page(["new"]))]
        let slow = Task { try await service.loadFirstPage() }
        try await Task.sleep(for: .milliseconds(50))
        try await service.loadFirstPage()
        _ = try await slow.value
        let devices = try await service.cachedDevices()
        XCTAssertEqual(devices.map(\.id), ["new"])
        let more = try await service.hasMore()
        XCTAssertFalse(more, "the overtaken load's next link is not kept either")
    }

    func test_aNextLinkToAnotherHostIsNeverFollowed() async throws {
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), session: InventoryStub.session())
        InventoryStub.replies = [.init(body: page(["d1"], next: "https://graph.microsoft.com.example.net/v1.0/x"))]
        try await service.loadFirstPage()
        do {
            _ = try await service.loadNextPage()
            XCTFail("expected refusal")
        } catch {
            XCTAssertEqual(error as? InventoryError, .decodeFailure)
        }
        XCTAssertEqual(InventoryStub.requested.count, 1)
    }
}
