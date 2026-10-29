import XCTest
@testable import ThreatDigestKit

final class DigestAlertPlannerTests: XCTestCase {

    private func kev(_ id: String, vendor: String, day: Double) -> DigestItem {
        DigestItem(id: id, kind: .vulnerability, title: vendor + " flaw", summary: "", vendor: vendor, product: "x",
                   sources: [.kev], published: Date(timeIntervalSince1970: day * 86_400))
    }

    private let windows = DigestItem(id: "CVE-1", kind: .vulnerability, title: "Windows flaw", summary: "", vendor: "Microsoft", product: "Windows", sources: [.kev])
    private let fortinet = DigestItem(id: "CVE-2", kind: .vulnerability, title: "FortiOS flaw", summary: "", vendor: "Fortinet", product: "FortiOS", sources: [.kev])
    private let advisory = DigestItem(id: "cisaAdvisory:1", kind: .advisory, title: "#StopRansomware: X", summary: "", sources: [.cisaAdvisory])
    private let story = DigestItem(id: "sansISC:1", kind: .news, title: "Windows story", summary: "", sources: [.sansISC])
    private let unexploited = DigestItem(id: "CVE-3", kind: .vulnerability, title: "Windows thing", summary: "", vendor: "Microsoft", sources: [.msrc])

    func test_theFirstRunOnlyRemembers() {
        let result = DigestAlertPlanner.plan(items: [windows, fortinet, advisory], seen: nil, categories: [.microsoft])
        XCTAssertTrue(result.announce.isEmpty, "the baseline posts nothing")
        XCTAssertEqual(Set(result.remember), ["CVE-1", "CVE-2", "cisaAdvisory:1"])
    }

    func test_onlyNewItemsInTheChosenCategoriesAreAnnounced() {
        let result = DigestAlertPlanner.plan(items: [windows, fortinet, advisory], seen: ["CVE-1"], categories: [.microsoft, .advisories])
        XCTAssertEqual(result.announce.map(\.id).sorted(), ["cisaAdvisory:1"], "the Windows one was seen; Fortinet is not chosen")
        XCTAssertEqual(Set(result.remember), ["CVE-1", "CVE-2", "cisaAdvisory:1"], "Fortinet is remembered anyway")
    }

    func test_choosingACategoryLaterDoesNotAnnounceTheBacklog() {
        let first = DigestAlertPlanner.plan(items: [windows, fortinet], seen: [], categories: [.microsoft])
        let later = DigestAlertPlanner.plan(items: [windows, fortinet], seen: first.remember, categories: [.microsoft, .networkAccess])
        XCTAssertTrue(later.announce.isEmpty)
    }

    func test_newsAndUnexploitedItemsNeverAlert() {
        let result = DigestAlertPlanner.plan(items: [story, unexploited], seen: [], categories: Set(DigestCategory.allCases))
        XCTAssertTrue(result.announce.isEmpty)
        XCTAssertTrue(result.remember.isEmpty)
    }

    func test_newestFirstAndTheCopy() {
        let older = kev("CVE-10", vendor: "Microsoft", day: 1), newer = kev("CVE-11", vendor: "Microsoft", day: 2)
        let result = DigestAlertPlanner.plan(items: [older, newer], seen: [], categories: [.microsoft])
        XCTAssertEqual(result.announce.map(\.id), ["CVE-11", "CVE-10"])
        let copy = DigestAlertPlanner.copy(for: result.announce)
        XCTAssertEqual(copy?.title, "Threat Digest")
        XCTAssertEqual(copy?.body, "2 new in your categories: Microsoft flaw, and 1 more.")
        XCTAssertEqual(DigestAlertPlanner.copy(for: [windows])?.body, "New exploited vulnerability: Windows flaw")
        XCTAssertEqual(DigestAlertPlanner.copy(for: [advisory])?.body, "New CISA advisory: #StopRansomware: X")
        XCTAssertNil(DigestAlertPlanner.copy(for: []))
    }

    func test_whatIsRememberedIsBounded() {
        let seen = (0..<DigestAlertPlanner.rememberedLimit).map { "old-\($0)" }
        let result = DigestAlertPlanner.plan(items: [windows], seen: seen, categories: [.microsoft])
        XCTAssertEqual(result.remember.count, DigestAlertPlanner.rememberedLimit)
        XCTAssertEqual(result.remember.last, "CVE-1", "the newest stays")
        XCTAssertFalse(result.remember.contains("old-0"), "the oldest goes")
    }
}
