import XCTest
@testable import ThreatDigestKit

final class DigestRankerTests: XCTestCase {

    private let now = DigestDates.parse("2026-10-25T12:00:00Z")!
    private var ranker: DigestRanker { DigestRanker(now: now) }

    private func item(_ id: String = "CVE-2026-1", sources: Set<DigestSource> = [.msrc], kind: DigestItem.Kind = .vulnerability, vendor: String? = "Microsoft", title: String = "x", published: Date? = nil, due: Date? = nil, ransomware: Bool = false, exploited: Bool = false, disclosed: Bool = false, exploitability: String? = nil, severity: String? = nil, cvss: Double? = nil) -> DigestItem {
        DigestItem(id: id, kind: kind, title: title, summary: "", vendor: vendor, sources: sources, published: published, kevDueDate: due, kevRansomware: ransomware, msrcSeverity: severity, msrcExploited: exploited, msrcPubliclyDisclosed: disclosed, msrcExploitability: exploitability, cvssBase: cvss)
    }

    func test_sourcesListCatalogFirst() {
        XCTAssertEqual(Set<DigestSource>([.cisaAlert, .msrc, .kev]).sorted(), [.kev, .msrc, .cisaAlert])
    }

    func test_wordsPadsAndSplits() {
        XCTAssertEqual(DigestVocabulary.words("ONLYOFFICE Docs/Server (x)"), " onlyoffice docs server x ")
        XCTAssertEqual(DigestVocabulary.words("ASP.NET Core, Hyper-V"), " asp.net core hyper-v ")
    }

    func test_kevPresenceOrMSRCExploitedIsExploited() {
        XCTAssertTrue(ranker.rank(item(sources: [.kev], vendor: "Fortinet")).signals.contains(.exploited))
        XCTAssertTrue(ranker.rank(item(exploited: true)).signals.contains(.exploited))
        XCTAssertFalse(ranker.rank(item()).signals.contains(.exploited))
    }

    func test_ransomwareFlag() {
        XCTAssertTrue(ranker.rank(item(ransomware: true)).signals.contains(.ransomware))
    }

    func test_dueSoonOverdueAndLongPast() {
        XCTAssertTrue(ranker.rank(item(due: now.addingTimeInterval(5 * 86_400))).signals.contains(.dueSoon))
        XCTAssertFalse(ranker.rank(item(due: now.addingTimeInterval(20 * 86_400))).signals.contains(.dueSoon))
        XCTAssertTrue(ranker.rank(item(due: now.addingTimeInterval(-3 * 86_400))).signals.contains(.overdue))
        let longPast = ranker.rank(item(due: now.addingTimeInterval(-40 * 86_400))).signals
        XCTAssertFalse(longPast.contains(.overdue))
        XCTAssertFalse(longPast.contains(.dueSoon))
    }

    func test_msrcFlags() {
        XCTAssertTrue(ranker.rank(item(exploitability: "Exploitation More Likely")).signals.contains(.moreLikely))
        XCTAssertFalse(ranker.rank(item(exploitability: "Exploitation Less Likely")).signals.contains(.moreLikely))
        XCTAssertTrue(ranker.rank(item(disclosed: true)).signals.contains(.publiclyDisclosed))
        XCTAssertTrue(ranker.rank(item(severity: "Critical")).signals.contains(.critical))
        XCTAssertTrue(ranker.rank(item(cvss: 9.1)).signals.contains(.critical))
        XCTAssertFalse(ranker.rank(item(severity: "Important", cvss: 8.9)).signals.contains(.critical))
    }

    func test_microsoftByVendorSourceOrWords() {
        XCTAssertTrue(ranker.rank(item(sources: [.kev], vendor: "Microsoft")).signals.contains(.microsoft))
        XCTAssertTrue(ranker.rank(item(sources: [.msrc], vendor: nil)).signals.contains(.microsoft))
        XCTAssertTrue(ranker.rank(item(sources: [.kev], vendor: "Contoso", title: "Exchange Server bug")).signals.contains(.microsoft))
        XCTAssertFalse(ranker.rank(item(sources: [.kev], vendor: "Fortinet", title: "FortiOS bug")).signals.contains(.microsoft))
    }

    func test_advisoryAndNew() {
        XCTAssertTrue(ranker.rank(item("a", sources: [.cisaAdvisory], kind: .advisory, vendor: nil)).signals.contains(.advisory))
        XCTAssertFalse(ranker.rank(item("a", sources: [.cisaAlert], kind: .advisory, vendor: nil)).signals.contains(.advisory))
        XCTAssertTrue(ranker.rank(item(published: now.addingTimeInterval(-2 * 86_400))).signals.contains(.new))
        XCTAssertFalse(ranker.rank(item(published: now.addingTimeInterval(-10 * 86_400))).signals.contains(.new))
    }

    func test_scoreIsTheSumOfTheWeightsAndSignalsAreOrdered() {
        let r = ranker.rank(item(sources: [.kev, .msrc], published: now, due: now.addingTimeInterval(86_400), ransomware: true, exploited: true))
        XCTAssertEqual(r.signals, [.exploited, .ransomware, .dueSoon, .microsoft, .new])
        XCTAssertEqual(r.score, r.signals.reduce(0) { $0 + DigestRanker.weights[$1]! })
    }

    func test_aKEVListedMicrosoftCVEOutranksTheLoudestUnexploitedOne() {
        let listed = ranker.rank(item(sources: [.kev], vendor: "Microsoft", title: "Windows bug", published: now)).score
        let loud = ranker.rank(item(published: now, disclosed: true, exploitability: "Exploitation More Likely", severity: "Critical", cvss: 9.8)).score
        XCTAssertGreaterThan(listed, loud)
        let listedOther = ranker.rank(item(sources: [.kev], vendor: "Fortinet", title: "FortiOS bug", published: now)).score
        XCTAssertGreaterThanOrEqual(listedOther, DigestRanker.cardThreshold, "an exploited CVE is always a card when the filter lets it through")
    }

    func test_microsoftMatchesWholeWordsOnly() {
        XCTAssertFalse(ranker.rank(item(sources: [.kev], vendor: "ONLYOFFICE", title: "ONLYOFFICE Docs Server Path Traversal Vulnerability")).signals.contains(.microsoft))
        XCTAssertTrue(ranker.rank(item(sources: [.kev], vendor: "Contoso", title: "Office macro bug")).signals.contains(.microsoft))
        XCTAssertFalse(ranker.rank(item(sources: [.kev], vendor: "Contoso", title: "Knowledge base bug")).signals.contains(.microsoft), "edge inside knowledge")
        XCTAssertTrue(ranker.rank(item(sources: [.kev], vendor: "Contoso", title: "Problem in ASP.NET Core")).signals.contains(.microsoft))
    }

    func test_republishedThirdPartyCVEsAreNotMicrosoft() {
        let chromium = item(sources: [.msrc], vendor: "Microsoft", title: "Google: CVE-2026-111497 Buffer overflow in Brotli")
        XCTAssertTrue(chromium.isRepublishedThirdParty)
        XCTAssertFalse(chromium.isMicrosoft)
        var mariner = item(sources: [.msrc], vendor: "Microsoft", title: "Some CVE")
        mariner.product = "Mariner"
        XCTAssertFalse(mariner.isMicrosoft)
        let edge = item(sources: [.msrc], vendor: "Microsoft", title: "Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability")
        XCTAssertTrue(edge.isMicrosoft)
        let inKEV = item(sources: [.msrc, .kev], vendor: "Microsoft", title: "Google: CVE-2026-1 something exploited")
        XCTAssertTrue(inKEV.isMicrosoft, "once CISA lists it, it is everybody's business")
    }

    func test_rankedOrdersByScoreThenNewest() {
        let a = item("a", published: now.addingTimeInterval(-30 * 86_400))
        let b = item("b", published: now.addingTimeInterval(-1 * 86_400))
        let c = item("c", published: now.addingTimeInterval(-30 * 86_400), ransomware: true)
        XCTAssertEqual(ranker.ranked([a, b, c]).map(\.item.id), ["c", "b", "a"])
    }

    func test_splitUsesTheThresholdAndTheCap() {
        let strong = (0..<12).map { item("s\($0)", ransomware: true, exploited: true) }
        let weak = [item("w", sources: [.cisaAlert], kind: .advisory, vendor: nil)]
        let (cards, rest) = ranker.split(ranker.ranked(strong + weak))
        XCTAssertEqual(cards.count, DigestRanker.maxCards)
        XCTAssertEqual(rest.count, 12 - DigestRanker.maxCards + 1)
        XCTAssertTrue(rest.contains { $0.item.id == "w" })
    }
}
