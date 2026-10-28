import XCTest
import AuthKit
@testable import InventoryKit

/// Answers inventory requests from a script: the first page, then the pages its next links
/// name, each after an optional delay so a reset can land while one is out.
private final class InventoryStub: URLProtocol, @unchecked Sendable {
    struct Reply { var body: String; var delay: TimeInterval = 0; var status: Int = 200 }
    nonisolated(unsafe) static var replies: [Reply] = []
    /// Answers for any request whose decoded URL contains the key, ahead of `replies`, for
    /// requests sent at once in no fixed order.
    nonisolated(unsafe) static var byQuery: [String: Reply] = [:]
    nonisolated(unsafe) static var requested: [URL] = []
    static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.requested.append(request.url!)
        let decoded = request.url?.absoluteString.removingPercentEncoding ?? ""
        let reply: Reply
        if let match = Self.byQuery.first(where: { decoded.contains($0.key) }) {
            reply = match.value
        } else {
            reply = Self.replies.isEmpty ? Reply(body: #"{"value":[]}"#) : Self.replies.removeFirst()
        }
        Self.lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + reply.delay) { [self] in
            let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: nil, headerFields: nil)!
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
        InventoryStub.byQuery = [:]
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
        // Pages of one size, so the second page follows the first page's link.
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), pageSize: 100, fillPageSize: 100,
                                             session: InventoryStub.session())
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

    // MARK: - the large walk

    func test_afterASmallFirstPageTheFillWalksInLargePagesAndSkipsWhatIsShown() async throws {
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), session: InventoryStub.session())
        let second = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=big2"
        InventoryStub.replies = [
            .init(body: page(["d1", "d2"], next: nextLink)),
            .init(body: page(["d1", "d2", "d3", "d4"], next: second)),
            .init(body: page(["d5"])),
        ]
        let first = try await service.loadFirstPage()
        XCTAssertEqual(first.devices.map(\.id), ["d1", "d2"])

        let walkStart = try await service.loadNextPage()
        XCTAssertEqual(walkStart?.devices.map(\.id), ["d3", "d4"], "the devices already shown are not handed over twice")
        let startURL = InventoryStub.requested[1].absoluteString.removingPercentEncoding ?? ""
        XCTAssertTrue(startURL.contains("$top=1000"), startURL)
        XCTAssertFalse(startURL.contains("skiptoken"), "the large walk starts from the beginning, not from the small page's link")

        let last = try await service.loadNextPage()
        XCTAssertEqual(last?.devices.map(\.id), ["d5"])
        XCTAssertEqual(InventoryStub.requested[2].absoluteString, second)

        let all = try await service.cachedDevices()
        XCTAssertEqual(all.map(\.id), ["d1", "d2", "d3", "d4", "d5"])
        let more = try await service.hasMore()
        XCTAssertFalse(more)
        let none = try await service.loadNextPage()
        XCTAssertNil(none)
    }

    func test_theLargeWalksOwnNextLinkIsCheckedToo() async throws {
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), session: InventoryStub.session())
        InventoryStub.replies = [
            .init(body: page(["d1"], next: nextLink)),
            .init(body: page(["d1", "d2"], next: "https://graph.microsoft.com.example.net/v1.0/x")),
        ]
        try await service.loadFirstPage()
        try await service.loadNextPage()
        do {
            _ = try await service.loadNextPage()
            XCTFail("expected refusal")
        } catch {
            XCTAssertEqual(error as? InventoryError, .decodeFailure)
        }
        XCTAssertEqual(InventoryStub.requested.count, 2)
    }

    func test_aFirstPageThatIsEverythingStartsNoWalk() async throws {
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), session: InventoryStub.session())
        InventoryStub.replies = [.init(body: page(["d1", "d2"]))]
        try await service.loadFirstPage()
        let more = try await service.hasMore()
        XCTAssertFalse(more)
        let next = try await service.loadNextPage()
        XCTAssertNil(next)
        XCTAssertEqual(InventoryStub.requested.count, 1)
    }

    // MARK: - asking Graph directly

    func test_aLookupKeepsOnlyRealMatchesWhateverGraphSendsBack() async throws {
        // A filter Graph does not understand can come back ignored, with the first devices
        // of the tenant. Those are not matches and must not appear as if they were.
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), session: InventoryStub.session())
        InventoryStub.byQuery = [
            "deviceName eq": .init(body: page(["LT-FIELD-207", "WS-1"])),
            "serialNumber eq": .init(body: page(["WS-2"])),
            "startswith": .init(body: page(["LT-FIELD-207", "WS-3"])),
        ]
        let found = await service.lookup("lt-field-207")
        XCTAssertEqual(found.map(\.id), ["LT-FIELD-207"], "one copy, and nothing that does not match")
    }

    func test_aRefusedStartsWithIsNotAskedAgain() async throws {
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), session: InventoryStub.session())
        InventoryStub.byQuery = ["startswith": .init(body: "{}", status: 400)]
        _ = await service.lookup("WS")
        let firstRound = InventoryStub.requested.filter { ($0.absoluteString.removingPercentEncoding ?? "").contains("startswith") }
        XCTAssertEqual(firstRound.count, 1)

        InventoryStub.requested = []
        _ = await service.lookup("WS")
        let secondRound = InventoryStub.requested.map { $0.absoluteString.removingPercentEncoding ?? "" }
        XCTAssertFalse(secondRound.contains { $0.contains("startswith") }, "refused once, not tried again this session")
        XCTAssertTrue(secondRound.contains { $0.contains("deviceName eq 'WS'") })
    }

    func test_aLookupQuotesWhatWasTyped() async throws {
        let service = DeviceInventoryService(auth: SwitchableAuth(operating: "t"), session: InventoryStub.session())
        _ = await service.lookup("o'brien")
        let urls = InventoryStub.requested.map { $0.absoluteString.removingPercentEncoding ?? "" }
        XCTAssertTrue(urls.contains { $0.contains("deviceName eq 'o''brien'") }, urls.joined(separator: "\n"))
    }
}
