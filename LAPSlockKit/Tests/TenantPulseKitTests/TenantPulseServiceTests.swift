import XCTest
import AuthKit
@testable import TenantPulseKit

private final class RecordingAuth: AuthManaging, @unchecked Sendable {
    var account = AdminAccount(id: "a.b", tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73", username: "admin@example.com", objectId: "a")
    var failures: [String: AuthError] = [:]
    private(set) var calls: [[String]] = []
    var currentAccount: AdminAccount? { get async { account } }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        calls.append(scopes)
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

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requests.append(request)
        let url = request.url?.absoluteString ?? ""
        let key = Self.replies.keys.first { url.lowercased().contains($0.lowercased()) }
        let reply = key.flatMap { k -> Reply? in
            guard var queue = Self.replies[k], !queue.isEmpty else { return nil }
            let next = queue.removeFirst()
            Self.replies[k] = queue
            return next
        } ?? Reply(status: 599, body: "{}")
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
    static func urls(containing fragment: String) -> [String] {
        requests.compactMap { $0.url?.absoluteString }.filter { $0.contains(fragment) }
    }
}

final class TenantPulseServiceTests: XCTestCase {

    private var auth: RecordingAuth!
    private var service: TenantPulseService!

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
        auth = RecordingAuth()
        let graph = GraphClient(auth: auth, session: StubProtocol.session(), retryPolicy: .none, tracer: GraphResponseTracer(), sleep: { _ in })
        service = TenantPulseService(graph: graph)
    }

    override func tearDown() {
        StubProtocol.reset()
        super.tearDown()
    }

    // MARK: health

    func test_healthReadsOverviewsAndUnresolvedIssuesWithTheHealthScope() async throws {
        StubProtocol.replies = [
            "healthOverviews": [.init(status: 200, body: #"{"value":[{"id":"Exchange","service":"Exchange Online","status":"serviceDegradation"},{"id":"Intune","service":"Microsoft Intune","status":"serviceOperational"}]}"#)],
            "serviceAnnouncement/issues": [.init(status: 200, body: #"{"value":[{"id":"EX1","title":"Mail","service":"Exchange Online","classification":"incident","status":"serviceDegradation","isResolved":false,"lastModifiedDateTime":"2026-10-25T12:00:00Z"},{"id":"EX0","title":"Old","service":"Exchange Online","classification":"incident","status":"serviceRestored","isResolved":true,"lastModifiedDateTime":"2026-10-20T12:00:00Z"}]}"#)],
        ]
        let report = try await service.health()
        XCTAssertEqual(report.degraded.map(\.service), ["Exchange Online"])
        XCTAssertEqual(report.operationalCount, 1)
        XCTAssertEqual(report.activeIssues.map(\.id), ["EX1"])
        XCTAssertTrue(StubProtocol.urls(containing: "issues").first?.removingPercentEncoding?.contains("isResolved eq false") == true)
        XCTAssertTrue(auth.calls.allSatisfy { $0 == ["ServiceHealth.Read.All"] })
    }

    func test_aRefusedIssueFilterFallsBackToTheUnfilteredList() async throws {
        StubProtocol.replies = [
            "healthOverviews": [.init(status: 200, body: #"{"value":[]}"#)],
            "serviceAnnouncement/issues": [
                .init(status: 400, body: #"{"error":{"code":"Request_UnsupportedQuery","message":"x"}}"#),
                .init(status: 200, body: #"{"value":[{"id":"A","isResolved":false,"lastModifiedDateTime":"2026-10-25T12:00:00Z"},{"id":"B","isResolved":true}]}"#),
            ],
        ]
        let report = try await service.health()
        XCTAssertEqual(report.activeIssues.map(\.id), ["A"])
        XCTAssertEqual(StubProtocol.urls(containing: "issues").count, 2)
    }

    func test_health403IsNotAuthorized() async {
        StubProtocol.replies = ["healthOverviews": [.init(status: 403, body: "{}")], "serviceAnnouncement/issues": [.init(status: 403, body: "{}")]]
        do {
            _ = try await service.health()
            XCTFail("expected notAuthorized")
        } catch {
            XCTAssertEqual(error as? TenantPulseError, .notAuthorized)
        }
    }

    // MARK: messages

    func test_messagesAreFilteredAndOrderedWithTheMessageScope() async throws {
        StubProtocol.replies = ["serviceAnnouncement/messages": [.init(status: 200, body: #"{"value":[{"id":"quiet","title":"Icon","category":"stayInformed","isMajorChange":false,"lastModifiedDateTime":"2026-10-25T00:00:00Z"},{"id":"due","title":"Act","category":"planForChange","isMajorChange":false,"actionRequiredByDateTime":"2026-11-10T00:00:00Z","lastModifiedDateTime":"2026-10-01T00:00:00Z"},{"id":"major","title":"Big","category":"stayInformed","isMajorChange":true,"lastModifiedDateTime":"2026-10-20T00:00:00Z"}]}"#)]]
        let messages = try await service.messages()
        XCTAssertEqual(messages.map(\.id), ["due", "major"])
        XCTAssertEqual(auth.calls.first, ["ServiceMessage.Read.All"])
    }

    // MARK: expiring

    private func seedExpiring() {
        StubProtocol.replies = [
            "v1.0/applications": [.init(status: 200, body: #"{"value":[{"id":"app1","appId":"a1","displayName":"HR Sync","passwordCredentials":[{"keyId":"k1","displayName":"Prod","endDateTime":"2026-11-05T00:00:00Z"},{"keyId":"k2","displayName":"NoEnd","endDateTime":null}],"keyCredentials":[{"keyId":"k3","displayName":"CN=hr","endDateTime":"2027-01-01T00:00:00Z"}]}]}"#)],
            "servicePrincipals": [.init(status: 200, body: #"{"value":[{"id":"sp1","displayName":"Payroll","keyCredentials":[{"keyId":"s1","displayName":"CN=sso","usage":"Sign","endDateTime":"2026-12-01T00:00:00Z"},{"keyId":"s2","displayName":"CN=sso","usage":"Verify","endDateTime":"2026-12-01T00:00:00Z"}]}]}"#)],
            "applePushNotificationCertificate": [.init(status: 200, body: #"{"id":"c1","appleIdentifier":"mdm@contoso.com","expirationDateTime":"2026-11-20T00:00:00Z"}"#)],
            "vppTokens": [.init(status: 200, body: #"{"value":[{"id":"v1","organizationName":"Contoso","appleId":"apps@contoso.com","state":"valid","expirationDateTime":"2027-02-01T00:00:00Z"}]}"#)],
        ]
    }

    func test_expiringItemsCombineEverySourceAndSkipCredentialsWithoutAnEnd() async throws {
        seedExpiring()
        let items = try await service.expiringItems()
        XCTAssertEqual(items.map(\.kind), [.appSecret, .applePushCertificate, .samlCertificate, .appCertificate, .vppToken])
        XCTAssertEqual(items.map(\.owner), ["HR Sync", "mdm@contoso.com", "Payroll", "HR Sync", "Contoso"])
        XCTAssertEqual(items.filter { $0.kind == .samlCertificate }.count, 1, "Sign and Verify share one row")
        let applications = try XCTUnwrap(StubProtocol.urls(containing: "v1.0/applications").first?.removingPercentEncoding)
        XCTAssertTrue(applications.contains("passwordCredentials,keyCredentials"), applications)
        let principals = try XCTUnwrap(StubProtocol.requests.first { $0.url?.absoluteString.contains("servicePrincipals") == true })
        XCTAssertEqual(principals.value(forHTTPHeaderField: "ConsistencyLevel"), "eventual")
        XCTAssertTrue(principals.url?.absoluteString.removingPercentEncoding?.contains("preferredSingleSignOnMode eq 'saml'") == true)
        XCTAssertTrue(auth.calls.contains(["Application.Read.All"]))
        XCTAssertTrue(auth.calls.contains(["DeviceManagementServiceConfig.Read.All"]))
    }

    func test_extrasFailingQuietlyStillReturnTheAppRegistrations() async throws {
        seedExpiring()
        StubProtocol.replies["servicePrincipals"] = [.init(status: 400, body: "{}")]
        StubProtocol.replies["applePushNotificationCertificate"] = [.init(status: 404, body: "{}")]
        StubProtocol.replies["vppTokens"] = [.init(status: 403, body: "{}")]
        let items = try await service.expiringItems()
        XCTAssertEqual(items.map(\.kind), [.appSecret, .appCertificate])
    }

    func test_applicationsFailingFailsTheCard() async {
        seedExpiring()
        StubProtocol.replies["v1.0/applications"] = [.init(status: 401, body: "{}")]
        do {
            _ = try await service.expiringItems()
            XCTFail("expected consentRequired")
        } catch {
            XCTAssertEqual(error as? TenantPulseError, .consentRequired)
        }
    }

    // MARK: Secure Score

    func test_secureScoreReadsTenSnapshotsWithTheSecurityScope() async throws {
        StubProtocol.replies = ["secureScores": [.init(status: 200, body: #"{"value":[{"id":"s0","createdDateTime":"2026-10-25T00:00:00Z","currentScore":612,"maxScore":1176,"controlScores":[]},{"id":"s7","createdDateTime":"2026-10-18T00:00:00Z","currentScore":598,"maxScore":1176,"controlScores":[]}]}"#)]]
        let summary = try await service.secureScore()
        XCTAssertEqual(summary?.latest.currentScore, 612)
        XCTAssertEqual(summary?.change, 14)
        XCTAssertTrue(StubProtocol.urls(containing: "secureScores").first?.contains("top=31") == true)
        XCTAssertEqual(auth.calls.first, ["SecurityEvents.Read.All"])
    }

    func test_errorMappingCoversEveryGraphCase() {
        XCTAssertEqual(TenantPulseError(.throttled(retryAfter: 2)), .throttled(retryAfter: 2))
        XCTAssertEqual(TenantPulseError(.serviceUnavailable(status: 502)), .serviceUnavailable(status: 502))
        XCTAssertEqual(TenantPulseError(.notFound), .transport(status: 404))
        XCTAssertEqual(TenantPulseError(.badRequest(code: nil)), .transport(status: 400))
        XCTAssertEqual(TenantPulseError(.decodeFailure), .decodeFailure)
        XCTAssertEqual(TenantPulseError(.cancelled), .cancelled)
    }
}
