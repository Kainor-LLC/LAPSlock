import XCTest
@testable import ThreatDigestKit

private final class StubProtocol: URLProtocol {
    struct Reply { var status: Int; var body: String; var redirect: String? = nil }
    nonisolated(unsafe) static var replies: [String: Reply] = [:]
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
        let reply = Self.replies.first { url.contains($0.key) }?.value ?? Reply(status: 599, body: "")
        Self.lock.unlock()
        if let redirect = reply.redirect, let target = URL(string: redirect) {
            let moved = HTTPURLResponse(url: request.url!, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": redirect])!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: moved)
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: nil)!
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

final class ThreatDigestServiceTests: XCTestCase {

    private let now = DigestDates.parse("2026-10-25T12:00:00Z")!
    private var service: ThreatDigestService!

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
        service = ThreatDigestService(session: StubProtocol.session(), now: { [now] in now })
    }

    private let kev = ##"{"count":1,"vulnerabilities":[{"cveID":"CVE-2026-96951","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"Windows Command Injection","dateAdded":"2026-10-13","shortDescription":"x","requiredAction":"y","dueDate":"2026-10-16","knownRansomwareCampaignUse":"Known","notes":"","cwes":[]}]}"##
    private let msrc = ##"{"value":[{"cveNumber":"CVE-2026-96951","cveTitle":"Windows Shell","exploited":"Yes","severity":"Important"}]}"##
    private let rss = ##"<rss><channel><item><title>#StopRansomware: X</title><link>https://www.cisa.gov/a</link><description>d</description><pubDate>Mon, 19 Oct 2026 12:00:00 +0000</pubDate><guid>/node/1</guid></item></channel></rss>"##

    func test_allFourSourcesAreFetchedMergedAndReported() async throws {
        StubProtocol.replies = [
            "known_exploited_vulnerabilities.json": .init(status: 200, body: kev),
            "api.msrc.microsoft.com": .init(status: 200, body: msrc),
            "alerts.xml": .init(status: 200, body: rss),
            "cybersecurity-advisories.xml": .init(status: 200, body: rss)
        ]
        let snapshot = try await service.digest()
        XCTAssertEqual(snapshot.statuses.count, 4)
        XCTAssertTrue(snapshot.unavailable.isEmpty, "\(snapshot.statuses)")
        XCTAssertEqual(snapshot.items.count, 3)
        let merged = try XCTUnwrap(snapshot.items.first { $0.id == "CVE-2026-96951" })
        XCTAssertEqual(merged.sources, [.kev, .msrc])
        XCTAssertEqual(StubProtocol.requests.count, 4)
        for request in StubProtocol.requests {
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
            XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
            XCTAssertTrue(ThreatDigestService.allowedHosts.contains(request.url!.host!), request.url!.absoluteString)
        }
    }

    func test_oneSourceDownLeavesTheOthersStanding() async throws {
        StubProtocol.replies = [
            "known_exploited_vulnerabilities.json": .init(status: 200, body: kev),
            "api.msrc.microsoft.com": .init(status: 403, body: "<html>"),
            "alerts.xml": .init(status: 200, body: rss),
            "cybersecurity-advisories.xml": .init(status: 200, body: "not xml at all")
        ]
        let snapshot = try await service.digest()
        XCTAssertEqual(snapshot.unavailable.map(\.source), [.msrc])
        XCTAssertEqual(snapshot.items.count, 2)
        if case .unavailable(let reason) = snapshot.statuses[1].state {
            XCTAssertTrue(reason.contains("403"), reason)
        } else {
            XCTFail("expected msrc unavailable")
        }
    }

    func test_aBrokenFeedIsReportedNotThrown() async throws {
        StubProtocol.replies = [
            "known_exploited_vulnerabilities.json": .init(status: 200, body: "{nope"),
            "api.msrc.microsoft.com": .init(status: 200, body: msrc),
            "alerts.xml": .init(status: 200, body: rss),
            "cybersecurity-advisories.xml": .init(status: 200, body: rss)
        ]
        let snapshot = try await service.digest()
        XCTAssertEqual(snapshot.unavailable.map(\.source), [.kev])
        if case .unavailable(let reason) = snapshot.statuses[0].state {
            XCTAssertTrue(reason.contains("changed shape"), reason)
        }
    }

    func test_aHostOutsideTheAllowlistIsRefusedBeforeAnyRequest() async {
        do {
            _ = try await service.get(URL(string: "https://evil.example/feed.json")!)
            XCTFail("expected refusal")
        } catch {
            XCTAssertEqual(error as? DigestError, .hostNotAllowed("evil.example"))
        }
        do {
            _ = try await service.get(URL(string: "http://www.cisa.gov/feed.json")!)
            XCTFail("expected refusal of plain http")
        } catch {
            XCTAssertEqual(error as? DigestError, .hostNotAllowed("www.cisa.gov"))
        }
        XCTAssertTrue(StubProtocol.requests.isEmpty)
    }

    func test_aRedirectOffTheAllowlistIsRefusedAndNotFollowed() async {
        StubProtocol.replies = ["known_exploited": .init(status: 200, body: "", redirect: "https://evil.example/kev.json")]
        do {
            _ = try await service.get(URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!)
            XCTFail("expected refusal")
        } catch {
            XCTAssertEqual(error as? DigestError, .hostNotAllowed("evil.example"))
        }
        XCTAssertFalse(StubProtocol.requests.contains { $0.url?.host == "evil.example" })
    }

    func test_aRedirectWithinTheAllowlistIsFollowed() async throws {
        StubProtocol.replies = [
            "old-feed.json": .init(status: 200, body: "", redirect: "https://www.cisa.gov/new-feed.json"),
            "new-feed.json": .init(status: 200, body: "moved")
        ]
        let data = try await service.get(URL(string: "https://www.cisa.gov/old-feed.json")!)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "moved")
    }

    func test_aFeedPastTheCapIsAbandonedWhileReading() async {
        let small = ThreatDigestService(session: StubProtocol.session(), now: { [now] in now }, byteLimit: 10)
        StubProtocol.replies = ["big.json": .init(status: 200, body: String(repeating: "x", count: 11))]
        do {
            _ = try await small.get(URL(string: "https://www.cisa.gov/big.json")!)
            XCTFail("expected too large")
        } catch {
            XCTAssertEqual(error as? DigestError, .tooLarge)
        }
        StubProtocol.replies = ["fits.json": .init(status: 200, body: String(repeating: "x", count: 10))]
        let fits = try? await small.get(URL(string: "https://www.cisa.gov/fits.json")!)
        XCTAssertEqual(fits?.count, 10)
    }

    func test_theSessionSendsNoCookiesAndOnlyAnAcceptHeader() {
        let config = ThreatDigestService.makeSession().configuration
        XCTAssertFalse(config.httpShouldSetCookies)
        XCTAssertEqual(config.httpCookieAcceptPolicy, .never)
        XCTAssertEqual(config.httpAdditionalHeaders?.count, 1)
        XCTAssertNotNil(config.httpAdditionalHeaders?["Accept"])
    }
}
