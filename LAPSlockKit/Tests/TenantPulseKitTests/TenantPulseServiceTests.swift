import XCTest
import AuthKit
@testable import TenantPulseKit

private final class RecordingAuth: AuthManaging, @unchecked Sendable {
    var account = AdminAccount(id: "a.b", tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73", username: "admin@example.com", objectId: "a")
    var failures: [String: AuthError] = [:]
    private(set) var calls: [[String]] = []
    private let lock = NSLock()
    var currentAccount: AdminAccount? { get async { account } }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        lock.lock(); calls.append(scopes); lock.unlock()
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
    /// URLSession calls startLoading on its own threads, and the services under test send
    /// requests concurrently; unguarded, the shared state above corrupts the heap now and then.
    static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.requests.append(request)
        let url = request.url?.absoluteString ?? ""
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
                .init(status: 400, body: #"{"error":{"code":"Request_UnsupportedQuery","message":"x"}}"#),
                .init(status: 200, body: #"{"value":[{"id":"A","isResolved":false,"lastModifiedDateTime":"2026-10-25T12:00:00Z"},{"id":"B","isResolved":true}]}"#),
            ],
        ]
        let report = try await service.health()
        XCTAssertEqual(report.activeIssues.map(\.id), ["A"])
        let urls = StubProtocol.urls(containing: "issues").map { $0.removingPercentEncoding ?? $0 }
        XCTAssertEqual(urls.count, 3, "the fields and filter, the filter alone, then the plain list")
        XCTAssertTrue(urls[0].contains("$select=") && urls[0].contains("isResolved eq false"), urls[0])
        XCTAssertTrue(!urls[1].contains("$select=") && urls[1].contains("isResolved eq false"), urls[1])
        XCTAssertTrue(!urls[2].contains("isResolved") && urls[2].contains("$top=100"), urls[2])
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

    func test_aCredentialWithoutAKeyIdKeepsTheSameIdOnEveryRead() async throws {
        let end = Date(timeIntervalSince1970: 1_800_000_000)
        XCTAssertEqual(TenantPulseService.credentialKey("k1", end: end, name: "x", index: 3), "k1")
        let first = TenantPulseService.credentialKey(nil, end: end, name: "Deploy", index: 0)
        XCTAssertEqual(first, TenantPulseService.credentialKey(nil, end: end, name: "Deploy", index: 0))
        XCTAssertEqual(first, TenantPulseService.credentialKey("", end: end, name: "Deploy", index: 0))
        XCTAssertNotEqual(first, TenantPulseService.credentialKey(nil, end: end, name: "Deploy", index: 1))

        seedExpiring()
        let a = try await service.expiringItems().map(\.id)
        seedExpiring()
        let b = try await service.expiringItems().map(\.id)
        XCTAssertEqual(a, b)
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

    func test_secureScoreReadsThirtyOneSnapshotsWithTheSecurityScope() async throws {
        StubProtocol.replies = [
            "secureScores?": [.init(status: 200, body: #"{"value":[{"id":"s0","createdDateTime":"2026-10-25T00:00:00Z","currentScore":612,"maxScore":1176},{"id":"s7","createdDateTime":"2026-10-18T00:00:00Z","currentScore":598,"maxScore":1176}]}"#)],
            "secureScores/s0": [.init(status: 200, body: #"{"id":"s0","createdDateTime":"2026-10-25T00:00:00Z","currentScore":612,"maxScore":1176,"controlScores":[]}"#)],
            "secureScores/s7": [.init(status: 200, body: #"{"id":"s7","createdDateTime":"2026-10-18T00:00:00Z","currentScore":598,"maxScore":1176,"controlScores":[]}"#)],
        ]
        let summary = try await service.secureScore()
        XCTAssertEqual(summary?.latest.currentScore, 612)
        XCTAssertEqual(summary?.change, 14)
        XCTAssertTrue(StubProtocol.urls(containing: "secureScores?").first?.contains("top=31") == true)
        XCTAssertTrue(auth.calls.allSatisfy { $0 == ["SecurityEvents.Read.All"] })
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

// MARK: - lean reads (OPTIMIZATION-PLAN.md, step F)

extension TenantPulseServiceTests {

    private var issuesBody: String {
        #"{"value":[{"id":"EX1","title":"Mail","service":"Exchange Online","classification":"incident","status":"serviceDegradation","isResolved":false,"lastModifiedDateTime":"2026-10-25T12:00:00Z"},{"id":"EX0","title":"Old","service":"Exchange Online","classification":"incident","status":"serviceRestored","isResolved":true,"lastModifiedDateTime":"2026-10-20T12:00:00Z"}]}"#
    }

    func test_issueStampsAskForTheKeyFieldsOnlyAndFindWhatHealthFinds() async throws {
        StubProtocol.replies = ["serviceAnnouncement/issues": [.init(status: 200, body: issuesBody)]]
        let stamps = try await service.activeIssueStamps()
        XCTAssertEqual(stamps.map(\.id), ["EX1"], "the same active issues health() reports")
        XCTAssertEqual(stamps.first?.lastModifiedDateTime, ISO8601DateFormatter().date(from: "2026-10-25T12:00:00Z"))
        let url = StubProtocol.urls(containing: "issues").first?.removingPercentEncoding ?? ""
        XCTAssertTrue(url.contains("$select=id,classification,isResolved,lastModifiedDateTime"), url)
        XCTAssertTrue(url.contains("isResolved eq false"), url)
        XCTAssertTrue(StubProtocol.urls(containing: "healthOverviews").isEmpty, "no service statuses for a key that needs none")
    }

    func test_aRefusedIssueSelectFallsBackToTheFullRead() async throws {
        StubProtocol.replies = [
            "serviceAnnouncement/issues": [.init(status: 400, body: #"{"error":{"code":"BadRequest"}}"#), .init(status: 200, body: issuesBody)],
            "healthOverviews": [.init(status: 200, body: #"{"value":[]}"#)],
        ]
        let stamps = try await service.activeIssueStamps()
        XCTAssertEqual(stamps.map(\.id), ["EX1"])
    }

    func test_messageDeadlinesAskForTheWindowWithTheIdAndDateOnly() async throws {
        StubProtocol.replies = ["serviceAnnouncement/messages": [.init(status: 200, body: #"{"value":[{"id":"due","actionRequiredByDateTime":"2026-11-10T00:00:00Z"}]}"#)]]
        let now = ISO8601DateFormatter().date(from: "2026-11-01T00:00:00Z")!
        let found = try await service.messageDeadlines(from: now, through: now.addingTimeInterval(14 * 86_400))
        XCTAssertEqual(found.map(\.id), ["due"])
        let url = StubProtocol.urls(containing: "messages").first?.removingPercentEncoding ?? ""
        XCTAssertTrue(url.contains("actionRequiredByDateTime ge 2026-11-01T00:00:00Z and actionRequiredByDateTime le 2026-11-15T00:00:00Z"), url)
        XCTAssertTrue(url.contains("$select=id,actionRequiredByDateTime"), url)
    }

    func test_aRefusedDeadlineFilterFallsBackToTheFullRead() async throws {
        StubProtocol.replies = ["serviceAnnouncement/messages": [
            .init(status: 400, body: #"{"error":{"code":"BadRequest"}}"#),
            .init(status: 200, body: #"{"value":[{"id":"due","title":"Act","category":"planForChange","actionRequiredByDateTime":"2026-11-10T00:00:00Z"}]}"#),
        ]]
        let now = ISO8601DateFormatter().date(from: "2026-11-01T00:00:00Z")!
        let found = try await service.messageDeadlines(from: now, through: now.addingTimeInterval(14 * 86_400))
        XCTAssertEqual(found.map(\.id), ["due"])
    }

    func test_secureScoreAsksForAsManySnapshotsAsItNeeds() async throws {
        StubProtocol.replies = ["secureScores": [.init(status: 200, body: #"{"value":[{"id":"s2","createdDateTime":"2026-10-26T00:00:00Z","currentScore":60,"maxScore":100},{"id":"s1","createdDateTime":"2026-10-25T00:00:00Z","currentScore":62,"maxScore":100}]}"#)]]
        let summary = try await service.secureScore(snapshots: 2)
        XCTAssertEqual(summary?.latest.id, "s2")
        XCTAssertEqual(summary?.change(overDays: 1), -2, "yesterday's drop, from two snapshots")
        XCTAssertTrue(StubProtocol.urls(containing: "secureScores").first?.contains("$top=2") == true)
    }
}

// MARK: - the screen's lean reads (OPTIMIZATION-PLAN.md, step G)

extension TenantPulseServiceTests {

    private var refused: StubProtocol.Reply { .init(status: 400, body: #"{"error":{"code":"BadRequest"}}"#) }

    func test_issuesAskForTheFieldsTheModelDecodes() async throws {
        StubProtocol.replies = [
            "healthOverviews": [.init(status: 200, body: #"{"value":[]}"#)],
            "serviceAnnouncement/issues": [.init(status: 200, body: issuesBody)],
        ]
        _ = try await service.health()
        let url = StubProtocol.urls(containing: "issues").first?.removingPercentEncoding ?? ""
        XCTAssertTrue(url.contains("$select=" + TenantPulseService.issueFields), url)
        XCTAssertFalse(TenantPulseService.issueFields.contains("posts"))
    }

    func test_aFormTheTenantRefusedIsNotSentAgain() async throws {
        StubProtocol.replies = [
            "healthOverviews": [.init(status: 200, body: #"{"value":[]}"#), .init(status: 200, body: #"{"value":[]}"#)],
            "serviceAnnouncement/issues": [refused, .init(status: 200, body: issuesBody), .init(status: 200, body: issuesBody)],
        ]
        _ = try await service.health()
        let second = try await service.health()
        XCTAssertEqual(second.activeIssues.map(\.id), ["EX1"])
        let urls = StubProtocol.urls(containing: "issues").map { $0.removingPercentEncoding ?? $0 }
        XCTAssertEqual(urls.count, 3, "one refusal, then the accepted form twice")
        XCTAssertFalse(urls[2].contains("$select="), "the refused form is not tried on the second load")
    }

    func test_messagesAskGraphForTheCardsRuleWithTheModelsFields() async throws {
        StubProtocol.replies = ["serviceAnnouncement/messages": [.init(status: 200, body: #"{"value":[{"id":"due","title":"Act","category":"planForChange","actionRequiredByDateTime":"2026-11-10T00:00:00Z"},{"id":"quiet","title":"Icon","category":"stayInformed","isMajorChange":false}]}"#)]]
        let messages = try await service.messages()
        XCTAssertEqual(messages.map(\.id), ["due"], "the phone still applies the rule")
        let url = StubProtocol.urls(containing: "messages").first?.removingPercentEncoding ?? ""
        XCTAssertTrue(url.contains("$filter=" + TenantPulseService.worthShowingFilter), url)
        XCTAssertTrue(url.contains("$select=" + TenantPulseService.messageFields), url)
    }

    func test_aRefusedMessageFilterKeepsTheFields() async throws {
        StubProtocol.replies = ["serviceAnnouncement/messages": [refused, .init(status: 200, body: #"{"value":[{"id":"major","category":"stayInformed","isMajorChange":true}]}"#)]]
        let messages = try await service.messages()
        XCTAssertEqual(messages.map(\.id), ["major"])
        let urls = StubProtocol.urls(containing: "messages").map { $0.removingPercentEncoding ?? $0 }
        XCTAssertEqual(urls.count, 2)
        XCTAssertTrue(urls[1].contains("$select=") && !urls[1].contains("$filter="), urls[1])
    }

    /// Thirty-one lean snapshots, and the latest, the week-old and the month-old read whole.
    private func seedScores(weekOld: StubProtocol.Reply? = nil) {
        var days: [String] = []
        for day in 0...30 {
            let date = ISO8601DateFormatter().string(from: ISO8601DateFormatter().date(from: "2026-10-25T00:00:00Z")!.addingTimeInterval(-Double(day) * 86_400))
            days.append(#"{"id":"s"# + String(day) + #"","createdDateTime":""# + date + #"","currentScore":"# + String(600 - day) + #","maxScore":1000}"#)
        }
        func whole(_ day: Int, identity: Int) -> StubProtocol.Reply {
            let date = ISO8601DateFormatter().string(from: ISO8601DateFormatter().date(from: "2026-10-25T00:00:00Z")!.addingTimeInterval(-Double(day) * 86_400))
            return .init(status: 200, body: #"{"id":"s"# + String(day) + #"","createdDateTime":""# + date + #"","currentScore":"# + String(600 - day)
                         + #","maxScore":1000,"controlScores":[{"controlCategory":"Identity","controlName":"MFA","score":"# + String(identity) + #"}]}"#)
        }
        StubProtocol.replies = [
            "secureScores?": [.init(status: 200, body: #"{"value":["# + days.joined(separator: ",") + "]}")],
            "secureScores/s0": [whole(0, identity: 50)],
            "secureScores/s7": [weekOld ?? whole(7, identity: 40)],
            "secureScores/s30": [whole(30, identity: 20)],
        ]
    }

    func test_secureScoreHistoryComesLeanAndTheComparedSnapshotsWhole() async throws {
        seedScores()
        let read = try await service.secureScore()
        let summary = try XCTUnwrap(read)
        XCTAssertEqual(summary.history.count, 31)
        XCTAssertEqual(summary.change(overDays: 7), 7)
        XCTAssertEqual(summary.identityChange(overDays: 7), 10, "the identity score, from the controls read by id")
        XCTAssertEqual(summary.identityChange(overDays: 30), 30)
        let list = StubProtocol.urls(containing: "secureScores?").first?.removingPercentEncoding ?? ""
        XCTAssertTrue(list.contains("$select=" + TenantPulseService.scoreHistoryFields), list)
        let whole = StubProtocol.urls(containing: "secureScores/")
        XCTAssertEqual(Set(whole.compactMap { $0.split(separator: "/").last.map(String.init) }), ["s0", "s7", "s30"])
    }

    func test_aMissingComparedSnapshotFallsBackToTheWholeHistory() async throws {
        seedScores(weekOld: .init(status: 404, body: "{}"))
        StubProtocol.replies["secureScores?"]?.append(.init(status: 200, body: #"{"value":[{"id":"s0","createdDateTime":"2026-10-25T00:00:00Z","currentScore":600,"maxScore":1000,"controlScores":[]}]}"#))
        let summary = try await service.secureScore()
        XCTAssertEqual(summary?.latest.id, "s0")
        let lists = StubProtocol.urls(containing: "secureScores?").map { $0.removingPercentEncoding ?? $0 }
        XCTAssertEqual(lists.count, 2)
        XCTAssertFalse(lists[1].contains("$select="), "the whole snapshots, as before step G")
    }

    func test_aRefusedScoreSelectIsNotSentAgain() async throws {
        let whole = StubProtocol.Reply(status: 200, body: #"{"value":[{"id":"s0","createdDateTime":"2026-10-25T00:00:00Z","currentScore":600,"maxScore":1000,"controlScores":[]}]}"#)
        StubProtocol.replies = ["secureScores?": [refused, whole, whole]]
        _ = try await service.secureScore()
        _ = try await service.secureScore()
        let lists = StubProtocol.urls(containing: "secureScores?").map { $0.removingPercentEncoding ?? $0 }
        XCTAssertEqual(lists.count, 3)
        XCTAssertFalse(lists[2].contains("$select="))
        XCTAssertTrue(StubProtocol.urls(containing: "secureScores/").isEmpty)
    }
}
