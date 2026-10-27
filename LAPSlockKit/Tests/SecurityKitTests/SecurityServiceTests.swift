import XCTest
import AuthKit
@testable import SecurityKit

// MARK: - doubles

private final class RecordingAuth: AuthManaging, @unchecked Sendable {
    var account = AdminAccount(
        id: "aaaaaaaa-1111-2222-3333-444455556666.4470dc21-a4b7-4729-a232-56d4c0eedf73",
        tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73",
        username: "admin@example.com",
        objectId: "aaaaaaaa-1111-2222-3333-444455556666")
    var failures: [String: AuthError] = [:]
    private(set) var calls: [(scopes: [String], interactive: Bool)] = []
    private let lock = NSLock()

    var currentAccount: AdminAccount? { get async { account } }

    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        lock.lock(); calls.append((scopes, allowInteractive)); lock.unlock()
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
    nonisolated(unsafe) static var requests: [(url: String, method: String, body: Data?)] = []
    /// URLSession calls startLoading on its own threads, and the services under test send
    /// requests concurrently; unguarded, the shared state above corrupts the heap now and then.
    static let lock = NSLock()
    nonisolated(unsafe) static var headers: [[String: String]] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let url = request.url?.absoluteString ?? ""
        let body = request.httpBodyStream.flatMap { stream -> Data in
            stream.open()
            var data = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buffer, maxLength: buffer.count)
                if n <= 0 { break }
                data.append(buffer, count: n)
            }
            stream.close()
            return data
        } ?? request.httpBody
        Self.requests.append((url, request.httpMethod ?? "", body))
        Self.headers.append(request.allHTTPHeaderFields ?? [:])
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

    static func reset() { replies = [:]; requests = []; headers = [] }

    static func session() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: cfg)
    }
}

// MARK: - tests

final class SecurityServiceTests: XCTestCase {

    private var auth: RecordingAuth!
    private var service: SecurityService!
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
        auth = RecordingAuth()
        let graph = GraphClient(
            auth: auth, session: StubProtocol.session(), retryPolicy: .none,
            tracer: GraphResponseTracer(), sleep: { _ in })
        service = SecurityService(graph: graph, now: { [now] in now })
    }

    override func tearDown() {
        StubProtocol.reset()
        super.tearDown()
    }

    private var incidentsBody: String {
        ##"{"value":[{"id":"100","displayName":"Older","severity":"low","status":"active","lastUpdateDateTime":"2026-10-01T00:00:00Z","alerts":[]},{"id":"200","displayName":"Newer","severity":"high","status":"inProgress","lastUpdateDateTime":"2026-10-20T10:00:00.1234567Z","alerts":[{"id":"a1","title":"Phish","severity":"high","status":"new","evidence":[{"@odata.type":"#microsoft.graph.security.userEvidence","userAccount":{"userPrincipalName":"j@demo.example"},"roles":["compromised"],"verdict":"suspicious"}]}]}]}"##
    }

    func test_incidentsAreReadOnV1WithExpandWindowTopAndThePreferHeader() async throws {
        StubProtocol.replies = ["security/incidents": [.init(status: 200, body: incidentsBody)]]
        let incidents = try await service.incidents()
        XCTAssertEqual(incidents.map(\.id), ["200", "100"])
        XCTAssertEqual(incidents.first?.alerts.first?.evidence.first?.userPrincipalName, "j@demo.example")
        let sent = try XCTUnwrap(StubProtocol.requests.first)
        XCTAssertTrue(sent.url.hasPrefix("https://graph.microsoft.com/v1.0/security/incidents?"), sent.url)
        XCTAssertTrue(sent.url.contains("$expand=alerts"), sent.url)
        XCTAssertTrue(sent.url.contains("$top=50"), sent.url)
        XCTAssertTrue(sent.url.contains("lastUpdateDateTime%20ge%202026-12-16T"), sent.url)
        XCTAssertEqual(sent.method, "GET")
        XCTAssertEqual(auth.calls.first?.scopes, ["SecurityIncident.Read.All"])
        XCTAssertEqual(auth.calls.first?.interactive, false)
    }

    func test_thePreferHeaderIsSent() async throws {
        StubProtocol.replies = ["security/incidents": [.init(status: 200, body: incidentsBody)]]
        _ = try await service.incidents()
        let sent = try XCTUnwrap(StubProtocol.headers.first)
        XCTAssertEqual(sent["Prefer"], "include-unknown-enum-members")
    }

    func test_incidentByIdGoesToThePathWithExpand() async throws {
        StubProtocol.replies = ["security/incidents/200": [.init(status: 200, body: ##"{"id":"200","displayName":"One","severity":"medium","status":"active","alerts":[]}"##)]]
        let incident = try await service.incident(id: "200")
        XCTAssertEqual(incident.title, "One")
        let sent = try XCTUnwrap(StubProtocol.requests.first)
        XCTAssertTrue(sent.url.hasPrefix("https://graph.microsoft.com/v1.0/security/incidents/200?"), sent.url)
        XCTAssertTrue(sent.url.contains("$expand=alerts"), sent.url)
    }

    func test_aNonNumericIdIsRefusedBeforeAnyRequest() async {
        do {
            _ = try await service.incident(id: "200 or 1=1")
            XCTFail("expected refusal")
        } catch {
            XCTAssertEqual(error as? SecurityError, .transport(status: 400))
        }
        XCTAssertTrue(StubProtocol.requests.isEmpty)
    }

    func test_a401BecomesConsentRequiredAndA403NotAuthorized() async {
        StubProtocol.replies = ["security/incidents": [.init(status: 401, body: "{}"), .init(status: 403, body: "{}")]]
        do { _ = try await service.incidents(); XCTFail("expected consentRequired") }
        catch { XCTAssertEqual(error as? SecurityError, .consentRequired) }
        do { _ = try await service.incidents(); XCTFail("expected notAuthorized") }
        catch { XCTAssertEqual(error as? SecurityError, .notAuthorized) }
    }

    func test_aBrokenBodyIsADecodeFailure() async {
        StubProtocol.replies = ["security/incidents": [.init(status: 200, body: "not json")]]
        do { _ = try await service.incidents(); XCTFail("expected decodeFailure") }
        catch { XCTAssertEqual(error as? SecurityError, .decodeFailure) }
    }

    func test_pagingStopsAtTheBudget() async throws {
        let page1 = ##"{"@odata.nextLink":"https://graph.microsoft.com/v1.0/security/incidents?$skip=50","value":[{"id":"1","severity":"low","status":"active"}]}"##
        let page2 = ##"{"@odata.nextLink":"https://graph.microsoft.com/v1.0/security/incidents?$skip=100","value":[{"id":"2","severity":"low","status":"active"}]}"##
        StubProtocol.replies = ["security/incidents": [.init(status: 200, body: page1), .init(status: 200, body: page2), .init(status: 200, body: page1)]]
        let incidents = try await service.incidents()
        XCTAssertEqual(incidents.count, 2)
        XCTAssertEqual(StubProtocol.requests.count, 2)
    }

    func test_newestFirstTieBreaksOnSeverityThenTitle() {
        let a = SecurityIncident(id: "1", displayName: "b", severity: .low, status: .active)
        let b = SecurityIncident(id: "2", displayName: "a", severity: .high, status: .active)
        let c = SecurityIncident(id: "3", displayName: "a", severity: .low, status: .active)
        XCTAssertEqual([a, b, c].sorted(by: SecurityService.newestFirst).map(\.id), ["2", "3", "1"])
        let dated = SecurityIncident(id: "4", displayName: "z", severity: .unknown, status: .active, lastUpdateDateTime: Date(timeIntervalSince1970: 1))
        XCTAssertEqual([a, dated].sorted(by: SecurityService.newestFirst).first?.id, "4")
    }

    func test_incidentIdRule() {
        XCTAssertTrue(SecurityService.isIncidentId("40211"))
        XCTAssertFalse(SecurityService.isIncidentId(""))
        XCTAssertFalse(SecurityService.isIncidentId("40211/alerts"))
        XCTAssertFalse(SecurityService.isIncidentId(String(repeating: "9", count: 21)))
    }
}
