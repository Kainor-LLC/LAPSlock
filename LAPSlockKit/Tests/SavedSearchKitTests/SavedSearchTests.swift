import XCTest
@testable import SavedSearchKit

final class SavedSearchListTests: XCTestCase {

    private func search(_ name: String, _ scope: SavedSearch.Scope = .devices, query: String = "q") -> SavedSearch {
        SavedSearch(name: name, scope: scope, query: query)
    }

    func test_addingTrimsTheNameAndRefusesAnEmptyOne() throws {
        let list = try SavedSearchList.adding(search("  Sales laptops  "), to: [])
        XCTAssertEqual(list.map(\.name), ["Sales laptops"])
        XCTAssertThrowsError(try SavedSearchList.adding(search("   "), to: list)) { error in
            XCTAssertEqual(error as? SavedSearchList.Problem, .emptyName)
        }
    }

    func test_theSameNameOnTheSameScreenReplacesButOnAnotherScreenDoesNot() throws {
        var list = try SavedSearchList.adding(search("Mine", query: "old"), to: [])
        list = try SavedSearchList.adding(search("mine", query: "new"), to: list)
        XCTAssertEqual(list.count, 1)
        XCTAssertEqual(list.first?.query, "new")
        list = try SavedSearchList.adding(search("Mine", .people), to: list)
        XCTAssertEqual(list.count, 2)
    }

    func test_theListStopsAtTheLimitButAReplacementStillFits() throws {
        var list: [SavedSearch] = []
        for index in 0..<SavedSearchList.limit { list = try SavedSearchList.adding(search("S" + String(index)), to: list) }
        XCTAssertThrowsError(try SavedSearchList.adding(search("One more"), to: list)) { error in
            XCTAssertEqual(error as? SavedSearchList.Problem, .full)
        }
        let replaced = try SavedSearchList.adding(search("S0", query: "changed"), to: list)
        XCTAssertEqual(replaced.count, SavedSearchList.limit)
    }

    func test_aLongNameIsCut() throws {
        let list = try SavedSearchList.adding(search(String(repeating: "x", count: 200)), to: [])
        XCTAssertEqual(list.first?.name.count, SavedSearchList.nameLimit)
    }

    func test_oneScreensSearchesAlphabetically() throws {
        var list: [SavedSearch] = []
        for (name, scope) in [("b", SavedSearch.Scope.devices), ("A", .devices), ("c", .people)] {
            list = try SavedSearchList.adding(search(name, scope), to: list)
        }
        XCTAssertEqual(SavedSearchList.searches(in: .devices, from: list).map(\.name), ["A", "b"])
        let gone = SavedSearchList.removing(list[0].id, from: list)
        XCTAssertEqual(gone.count, 2)
    }

    func test_theFileStoreRoundTripsAndClears() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).appendingPathComponent("saved.json")
        let store = FileSavedSearchStore(url: url)
        XCTAssertEqual(try store.load(), [])
        let saved = [SavedSearch(name: "Open high", scope: .incidents, query: "", options: ["openOnly": "true", "severity": "highOnly"],
                                 savedAt: Date(timeIntervalSince1970: 1_800_000_000))]
        try store.save(saved)
        XCTAssertEqual(try store.load(), saved)
        let values = try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
        try store.clear()
        XCTAssertEqual(try store.load(), [])
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }

    func test_anUnknownOptionFromANewerVersionDecodesAndIsKept() throws {
        let json = #"[{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","name":"x","scope":"devices","query":"q","options":{"future":"1"},"savedAt":"2027-01-15T08:00:00Z"}]"#
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let list = try decoder.decode([SavedSearch].self, from: Data(json.utf8))
        XCTAssertEqual(list.first?.options["future"], "1")
    }

    func test_theDemoExamplesAreValidAndOnePerScreen() throws {
        var list: [SavedSearch] = []
        for example in SavedSearch.demoExamples { list = try SavedSearchList.adding(example, to: list) }
        XCTAssertEqual(list.count, 3)
        XCTAssertEqual(Set(list.map(\.scope)).count, 3)
    }
}
