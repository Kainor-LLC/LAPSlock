import XCTest
import AuthKit
@testable import InventoryKit

// Step E (OPTIMIZATION-PLAN.md): the device list at the size of a large customer. What is
// tested is what a faster path could quietly get wrong: that the precomputed search finds and
// ranks exactly what folding every field on every keystroke did, that merging a page gives
// the same list as sorting everything, and that name lookups are shared and run in parallel.

final class DeviceSearchIndexTests: XCTestCase {

    /// Devices with every searchable field in play, accents and case included.
    private func fleet() -> [ManagedDeviceSummary] {
        let names = ["WS-01", "ws-01-spare", "LAB-WS-01", "Équipe-Mac", "equipe-pc", "KIOSK-2", "kiosk-10", "MBA-7"]
        let people = [("Zoë Márquez", "zoe@contoso.com"), ("Connor Johnson", "cj@contoso.com"), (nil, "tech@contoso.com"), (nil, nil)]
        var out: [ManagedDeviceSummary] = []
        for (i, name) in names.enumerated() {
            let person = people[i % people.count]
            out.append(ManagedDeviceSummary(
                id: "id-\(i)", entraDeviceId: nil, deviceName: name, platform: .windows,
                userPrincipalName: person.1, userDisplayName: person.0,
                emailAddress: person.1.map { "mail." + $0 },
                managedDeviceName: i % 2 == 0 ? name + "_managed" : nil,
                serialNumber: "SN\(1000 + i)", model: i % 3 == 0 ? "OptiPlex 7090" : "MacBook Air"))
        }
        return out
    }

    /// Today's ranking, worked out the old way: every field folded at query time.
    private func referenceRank(_ d: ManagedDeviceSummary, _ query: String) -> Int? {
        let fold = { (s: String) in s.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil) }
        let q = fold(query.trimmingCharacters(in: .whitespacesAndNewlines))
        func strength(_ f: String) -> Int? {
            let f = fold(f)
            if f == q { return 0 }
            if f.hasPrefix(q) { return 1 }
            if f.contains(q) { return 2 }
            return nil
        }
        var best = strength(d.deviceName).map { $0 * 2 }
        if best == 0 { return 0 }
        for field in [d.userDisplayName, d.userPrincipalName, d.emailAddress, d.serialNumber, d.model, d.managedDeviceName].compactMap({ $0 }) {
            if let s = strength(field) {
                let rank = s * 2 + 1
                if best == nil || rank < best! { best = rank }
            }
        }
        return best
    }

    func test_theIndexFindsAndRanksExactlyWhatFoldingEveryFieldDid() {
        let devices = fleet()
        for query in ["ws-01", "WS", "equipe", "ÉQUIPE", "zoe", "zoë márquez", "contoso", "mail.cj", "sn1003", "optiplex",
                      "air", "_managed", "kiosk-1", "e", "nothing-matches", "  ws  "] {
            let found = DeviceSearch.filter(devices, query: query)
            let expected = devices.filter { referenceRank($0, query) != nil }
            XCTAssertEqual(Set(found.map(\.id)), Set(expected.map(\.id)), query)
            let ranks = found.map { referenceRank($0, query)! }
            XCTAssertEqual(ranks, ranks.sorted(), "ranked best first for " + query)
        }
    }

    func test_anEmptyQueryIsEveryDeviceInNameOrder() {
        let out = DeviceSearch.filter(fleet(), query: "").map(\.deviceName)
        // Character order, as the locale-aware comparison it replaced also was: "10" before "2".
        XCTAssertEqual(out, ["Équipe-Mac", "equipe-pc", "kiosk-10", "KIOSK-2", "LAB-WS-01", "MBA-7", "WS-01", "ws-01-spare"])
    }

    func test_mergingAPageGivesTheSameListAsSortingEverything() {
        let all = fleet()
        var list = DeviceSearch.filter(Array(all.prefix(3)), query: "")
        list = DeviceSearch.merged(list, adding: Array(all[3..<6]))
        list = DeviceSearch.merged(list, adding: Array(all[6...]))
        XCTAssertEqual(list, DeviceSearch.filter(all, query: ""))
    }

    func test_mergingAPageIntoSearchResultsGivesWhatAFullSearchWould() {
        let all = fleet()
        for query in ["ws", "contoso", "e", "kiosk", "zzz"] {
            var results = DeviceSearch.filter(Array(all.prefix(4)), query: query)
            results = DeviceSearch.merged(results: results, query: query, adding: Array(all[4...]))
            XCTAssertEqual(results, DeviceSearch.filter(all, query: query), query)
        }
    }

    func test_aLookedUpNameIsFoldedIntoTheSearchKeyToo() {
        let device = ManagedDeviceSummary(id: "1", entraDeviceId: nil, deviceName: "WS-1", platform: .windows,
                                          userPrincipalName: "zm@contoso.com")
        XCTAssertFalse(DeviceSearch.matches(device, query: "marquez"))
        XCTAssertTrue(DeviceSearch.matches(device.withUserDisplayName("Zoë Márquez"), query: "marquez"))
    }
}

// MARK: - name lookups

/// Answers user lookups after a short delay, counting the requests and how many overlap.
private final class UsersStub: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var requests = 0
    nonisolated(unsafe) static var running = 0
    nonisolated(unsafe) static var mostAtOnce = 0
    static let lock = NSLock()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.requests += 1
        Self.running += 1
        Self.mostAtOnce = max(Self.mostAtOnce, Self.running)
        Self.lock.unlock()
        let filter = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?
            .queryItems?.first { $0.name == "$filter" }?.value ?? ""
        let upns = filter.components(separatedBy: "'").enumerated().filter { $0.offset % 2 == 1 }.map(\.element)
        let value = upns.map { #"{"userPrincipalName":"\#($0)","displayName":"Name of \#($0)"}"# }.joined(separator: ",")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { [self] in
            Self.lock.lock(); Self.running -= 1; Self.lock.unlock()
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data((#"{"value":["# + value + "]}").utf8))
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    override func stopLoading() {}

    static func reset() { lock.lock(); requests = 0; running = 0; mostAtOnce = 0; lock.unlock() }

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [UsersStub.self]
        return URLSession(configuration: config)
    }
}

private struct StaticAuth: AuthManaging {
    var currentAccount: AdminAccount? { get async { AdminAccount(id: "a.t", tenantId: "t", username: "admin@example.com") } }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String { "t" }
    func signIn() async throws -> AdminAccount { throw AuthError.userCancelled }
    func signOut(account: AdminAccount) async throws {}
}

final class UserNameResolverLookupTests: XCTestCase {

    override func setUp() { UsersStub.reset() }

    private func upns(_ count: Int) -> [String] { (0..<count).map { "user\($0)@contoso.com" } }

    func test_lookupsRunFourAtATime() async throws {
        let resolver = UserNameResolver(auth: StaticAuth(), session: UsersStub.session())
        let names = try await resolver.displayNames(forUserPrincipalNames: upns(100))
        XCTAssertEqual(names.count, 100)
        XCTAssertEqual(UsersStub.requests, 7, "15 to a request")
        XCTAssertEqual(UsersStub.mostAtOnce, 4, "four at once, not one at a time and not all seven")
    }

    func test_twoCallersAskingForTheSamePeopleShareOneLookup() async throws {
        let resolver = UserNameResolver(auth: StaticAuth(), session: UsersStub.session())
        let wanted = upns(30)
        async let a = resolver.displayNames(forUserPrincipalNames: wanted)
        async let b = resolver.displayNames(forUserPrincipalNames: wanted)
        let (first, second) = try await (a, b)
        XCTAssertEqual(first, second)
        XCTAssertEqual(first.count, 30)
        XCTAssertEqual(UsersStub.requests, 2, "two batches of 15, sent once between both callers")
    }

    func test_whatIsAlreadyKnownIsNotAskedForAgain() async throws {
        let resolver = UserNameResolver(auth: StaticAuth(), session: UsersStub.session())
        _ = try await resolver.displayNames(forUserPrincipalNames: upns(15))
        _ = try await resolver.displayNames(forUserPrincipalNames: upns(20))
        XCTAssertEqual(UsersStub.requests, 2, "the second call asked only for the five it did not know")
    }
}
