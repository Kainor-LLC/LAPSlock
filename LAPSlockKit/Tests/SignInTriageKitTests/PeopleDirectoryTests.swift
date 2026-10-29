import XCTest
@testable import SignInTriageKit

final class PeopleDirectoryTests: XCTestCase {

    private func user(_ id: String, _ name: String?, _ upn: String?, mail: String? = nil) -> DirectoryUser {
        DirectoryUser(id: id, displayName: name, userPrincipalName: upn, mail: mail)
    }

    func test_entriesAreInNameOrderAndGuestsAreMarked() {
        let entries = DirectorySearch.entries([
            user("3", "Zed Ito", "zed@c.example"),
            user("1", "Émile Abbott", "emile@c.example"),
            user("2", nil, "bot@c.example"),
            user("4", "Ana Ruiz (northwind.example)", "ana.ruiz_northwind.example#EXT#@c.example", mail: "ana.ruiz@northwind.example"),
        ])
        XCTAssertEqual(entries.map(\.id), ["4", "2", "1", "3"], "folded names, and the address for someone without one")
        XCTAssertEqual(entries.map(\.isGuest), [true, false, false, false])
        XCTAssertEqual(entries[1].title, "bot@c.example")
        XCTAssertEqual(entries[0].address, "ana.ruiz@northwind.example", "a guest's own address, not the rewritten one")
        XCTAssertEqual(entries[3].address, "zed@c.example")
    }

    func test_searchMatchesEveryWordAnywhereWithPrefixesFirst() {
        let entries = DirectorySearch.entries([
            user("1", "Jane Okafor", "jane.okafor@c.example"),
            user("2", "Marjan Ross", "marjan@c.example"),
            user("3", "José Okafor", "jose@c.example"),
            user("4", "Raj Patel", "raj@c.example", mail: "rpatel@mail.example"),
        ])
        XCTAssertEqual(DirectorySearch.filter(entries, query: "  ").count, 4)
        XCTAssertEqual(DirectorySearch.filter(entries, query: "jan").map(\.id), ["1", "2"], "a prefix first, then inside a word")
        XCTAssertEqual(DirectorySearch.filter(entries, query: "jose okafor").map(\.id), ["3"], "accents fold, every word must match")
        XCTAssertEqual(DirectorySearch.filter(entries, query: "OKAFOR").map(\.id), ["1", "3"])
        XCTAssertEqual(DirectorySearch.filter(entries, query: "rpatel@").map(\.id), ["4"], "mail too")
        XCTAssertTrue(DirectorySearch.filter(entries, query: "nobody").isEmpty)
    }

    func test_mergingAPageGivesWhatFilteringEveryoneGives() {
        let all = (0..<60).map { user("u" + String($0), "Person " + String(format: "%02d", $0) + ($0 % 3 == 0 ? " Ann" : ""), "p" + String($0) + "@c.example") }
        let first = DirectorySearch.entries(Array(all.prefix(25)))
        let rest = Array(all.dropFirst(25)).map(DirectoryEntry.init)
        XCTAssertEqual(DirectorySearch.merged(first, adding: rest), DirectorySearch.entries(all))
        for query in ["", "ann", "person 1", "p4"] {
            let merged = DirectorySearch.merged(results: DirectorySearch.filter(first, query: query), query: query, adding: rest)
            XCTAssertEqual(merged.map(\.id), DirectorySearch.filter(DirectorySearch.entries(all), query: query).map(\.id), query)
        }
    }

    func test_aPersonIsFoundByTheirExactAddress() {
        let entries = DirectorySearch.entries([user("1", "Jane", "jane@c.example", mail: "j.okafor@c.example"), user("2", "Janet", "janet@c.example")])
        XCTAssertEqual(DirectorySearch.person(withAddress: " JANE@c.example ", in: entries)?.id, "1")
        XCTAssertEqual(DirectorySearch.person(withAddress: "j.okafor@c.example", in: entries)?.id, "1")
        XCTAssertNil(DirectorySearch.person(withAddress: "jan", in: entries))
    }

    // MARK: - the fill

    private actor Pages: SignInTriageProviding {
        var script: [Result<DirectoryPage, SignInTriageError>]
        private(set) var asked: [URL?] = []
        init(_ script: [Result<DirectoryPage, SignInTriageError>]) { self.script = script }
        func searchUsers(prefix: String) async throws -> [DirectoryUser] { [] }
        func signIns(_ query: SignInQuery) async throws -> [SignInEvent] { [] }
        func directoryPage(after next: URL?) async throws -> DirectoryPage {
            asked.append(next)
            return try script.removeFirst().get()
        }
    }

    private actor Collected {
        var totals: [Int] = []
        var ids: [String] = []
        func add(_ users: [DirectoryUser], _ total: Int) { totals.append(total); ids += users.map(\.id) }
    }

    private func page(_ ids: [String], next: String?) -> Result<DirectoryPage, SignInTriageError> {
        .success(DirectoryPage(users: ids.map { user($0, $0, $0 + "@c.example") }, next: next.flatMap(URL.init(string:))))
    }

    func test_theFillPagesToTheEndFollowingEachLink() async {
        let provider = Pages([page(["a", "b"], next: "https://graph.microsoft.com/v1.0/users?$skiptoken=1"),
                              page(["c"], next: nil)])
        let collected = Collected()
        let outcome = await DirectoryFill.run(provider, sleep: { _ in }) { users, total in await collected.add(users, total) }
        XCTAssertEqual(outcome, .complete)
        let totals = await collected.totals
        let asked = await provider.asked
        XCTAssertEqual(totals, [2, 3])
        XCTAssertEqual(asked.map { $0?.absoluteString }, [nil, "https://graph.microsoft.com/v1.0/users?$skiptoken=1"])
    }

    func test_theFillStopsAtTheCapAndSaysSo() async {
        let provider = Pages([page(["a", "b"], next: "https://graph.microsoft.com/v1.0/users?$skiptoken=1"),
                              page(["c", "d"], next: "https://graph.microsoft.com/v1.0/users?$skiptoken=2")])
        let outcome = await DirectoryFill.run(provider, maxPeople: 3, sleep: { _ in }) { _, _ in }
        XCTAssertEqual(outcome, .capped)
    }

    func test_oneThrottleIsWaitedOutAndASecondStopsTheFill() async {
        let next = "https://graph.microsoft.com/v1.0/users?$skiptoken=1"
        let once = Pages([page(["a"], next: next), .failure(.throttled(retryAfter: 90)), page(["b"], next: nil)])
        let waits = Collected()
        let outcome = await DirectoryFill.run(once, sleep: { await waits.add([], Int($0)) }) { _, _ in }
        XCTAssertEqual(outcome, .complete)
        let waited = await waits.totals
        XCTAssertEqual(waited, [30], "the wait is capped")

        let twice = Pages([page(["a"], next: next), .failure(.throttled(retryAfter: 1)), .failure(.throttled(retryAfter: 1))])
        let stopped = await DirectoryFill.run(twice, sleep: { _ in }) { _, _ in }
        XCTAssertEqual(stopped, .failed(.throttled(retryAfter: 1)))
    }

    func test_aFirstPageRefusedIsAFailureWithNothingLoaded() async {
        let collected = Collected()
        let outcome = await DirectoryFill.run(Pages([.failure(.consentRequired)]), sleep: { _ in }) { users, total in await collected.add(users, total) }
        XCTAssertEqual(outcome, .failed(.consentRequired))
        let totals = await collected.totals
        XCTAssertTrue(totals.isEmpty)
    }

    // MARK: - the demo

    func test_theDemoDirectoryPagesAndHoldsTheFourWithSignIns() async {
        let provider = DemoSignInTriageProvider(latency: .milliseconds(1))
        let collected = Collected()
        let outcome = await DirectoryFill.run(provider, sleep: { _ in }) { users, total in await collected.add(users, total) }
        XCTAssertEqual(outcome, .complete)
        let ids = await collected.ids
        let totals = await collected.totals
        XCTAssertEqual(totals, [25, 40])
        XCTAssertEqual(Set(ids).count, 40)
        XCTAssertTrue(Set(DemoSignInTriageProvider.users.map(\.id)).isSubset(of: Set(ids)))
        XCTAssertEqual(DemoSignInTriageProvider.directory.map(DirectoryEntry.init).filter(\.isGuest).count, 2)
    }

    func test_theLargeDemoIsFiveThousandPeopleAndFiftyGuests() {
        let large = DemoSignInTriageProvider.largeDirectory()
        XCTAssertEqual(large.count, 5_050)
        XCTAssertEqual(Set(large.map(\.id)).count, 5_050)
        XCTAssertEqual(Set(large.compactMap(\.userPrincipalName)).count, 5_050)
        XCTAssertEqual(Set(large.compactMap(\.displayName)).count, 5_050, "no two people share a name")
        XCTAssertEqual(large.map(DirectoryEntry.init).filter(\.isGuest).count, 50)
        XCTAssertEqual(large[42].userPrincipalName, "user0042@demo.example", "the address the large Security demo names")
    }

    func test_theQuietCustomerHasOnlyItsOwnPeople() async throws {
        let provider = DemoSignInTriageProvider(latency: .milliseconds(1), quiet: true)
        let page = try await provider.directoryPage(after: nil)
        XCTAssertEqual(page.users.count, 6)
        XCTAssertNil(page.next)
        XCTAssertTrue(Set(page.users.map(\.id)).isDisjoint(with: Set(DemoSignInTriageProvider.directory.map(\.id))))
        let jane = try await provider.searchUsers(prefix: "jane")
        XCTAssertTrue(jane.isEmpty)
    }
}
