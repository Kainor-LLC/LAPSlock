import XCTest
@testable import ThreatDigestKit

final class DigestCategoryTests: XCTestCase {

    private func vulnerability(_ vendor: String, _ product: String, _ title: String = "x") -> DigestItem {
        DigestItem(id: "CVE-1", kind: .vulnerability, title: title, summary: "", vendor: vendor, product: product, sources: [.kev])
    }

    private func news(_ title: String) -> DigestItem {
        DigestItem(id: "n", kind: .news, title: title, summary: "", sources: [.bleepingComputer])
    }

    func test_vulnerabilitiesByVendor() {
        XCTAssertEqual(vulnerability("Fortinet", "FortiOS").categories, [.networkAccess])
        XCTAssertEqual(vulnerability("Citrix", "NetScaler").categories, [.networkAccess])
        XCTAssertEqual(vulnerability("PHP Group", "PHP").categories, [.webServers])
        XCTAssertEqual(vulnerability("Atlassian", "Multiple Products").categories, [.webServers])
        XCTAssertEqual(vulnerability("Linux", "Kernel").categories, [.endpointsBrowsers])
        XCTAssertEqual(vulnerability("Broadcom", "VMware ESX").categories, [.endpointsBrowsers])
        XCTAssertEqual(vulnerability("Microsoft", "Windows").categories, [.microsoft])
        XCTAssertEqual(vulnerability("Plex", "Media Server").categories, [.otherVendors], "a vendor no category names")
    }

    func test_anItemCanBeInSeveral() {
        let story = news("Microsoft releases Windows OOB updates to distrust eMudhra certificates")
        XCTAssertEqual(story.categories, [.news, .microsoft, .endpointsBrowsers])
    }

    func test_advisoriesAndNewsCarryTheirOwnCategory() {
        let alert = DigestItem(id: "a", kind: .advisory, title: "Critical Vulnerabilities in PHP Require Immediate Patching", summary: "", sources: [.cisaAlert])
        XCTAssertEqual(alert.categories, [.advisories, .webServers])
        XCTAssertEqual(news("A quiet week").categories, [.news], "news that names nothing is News only")
    }

    func test_headlinesUseTheStricterMicrosoftWords() {
        XCTAssertFalse(news("Attackers hit edge devices from three vendors").isMicrosoft, "edge devices is not Microsoft Edge")
        XCTAssertTrue(news("Attackers hit edge devices from three vendors").categories.contains(.networkAccess))
        XCTAssertFalse(news("How red teams test office printers").isMicrosoft)
        XCTAssertFalse(news("Crypto exchange loses funds").isMicrosoft)
        XCTAssertTrue(news("Patch Tuesday fixes 60 flaws").isMicrosoft)
        XCTAssertTrue(news("Exchange Server zero-day exploited").isMicrosoft)
    }
}

final class DigestNewsTests: XCTestCase {

    private let feed = ##"""
    <rss xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>
    <item><title>PHP Vulnerability Wrap-Up, (Fri, Oct 23rd)</title><link>https://isc.sans.edu/diary/32400</link>
    <description><![CDATA[<p>Two PHP flaws, CVE-2026-109618 and CVE-2026-109619, are being exploited.</p><p>Patch now:<br>8.3.27<br>8.4.14</p><ul><li>Check logs</li><li>Update</li></ul>]]></description>
    <dc:creator>Johannes Ullrich</dc:creator><pubDate>Fri, 23 Oct 2026 14:00:00 +0000</pubDate><guid>https://isc.sans.edu/diary/32400</guid></item>
    <item><title>No link here</title><description>x</description></item>
    </channel></rss>
    """##

    func test_aDiaryBecomesNewsWithItsAuthorTextAndCVEs() throws {
        let items = NewsFeeds.items(RSSReader.read(Data(feed.utf8), descriptionCap: NewsFeeds.textCap), source: .sansISC, fullText: true)
        XCTAssertEqual(items.count, 1, "an item without a link is dropped")
        let diary = try XCTUnwrap(items.first)
        XCTAssertEqual(diary.kind, .news)
        XCTAssertEqual(diary.title, "PHP Vulnerability Wrap-Up", "the date suffix goes; the card shows the date")
        XCTAssertEqual(diary.author, "Johannes Ullrich")
        XCTAssertEqual(diary.subtitle, "SANS Internet Storm Center, Johannes Ullrich")
        XCTAssertEqual(diary.cves, ["CVE-2026-109618", "CVE-2026-109619"])
        XCTAssertEqual(diary.links.first?.url.absoluteString, "https://isc.sans.edu/diary/32400")
        XCTAssertEqual(diary.articleText, "Two PHP flaws, CVE-2026-109618 and CVE-2026-109619, are being exploited.\n\nPatch now:\n8.3.27\n8.4.14\n\n\u{2022} Check logs\n\u{2022} Update")
        XCTAssertTrue(diary.summary.hasPrefix("Two PHP flaws"))
    }

    func test_withoutFullTextOnlyTheSummaryIsKept() throws {
        let items = NewsFeeds.items(RSSReader.read(Data(feed.utf8), descriptionCap: NewsFeeds.textCap), source: .bleepingComputer, fullText: false)
        let story = try XCTUnwrap(items.first)
        XCTAssertNil(story.articleText, "the article stays on the publisher's site")
        XCTAssertFalse(story.summary.isEmpty)
        XCTAssertEqual(story.title, "PHP Vulnerability Wrap-Up, (Fri, Oct 23rd)", "only SANS titles carry the date suffix")
    }

    func test_aStoryLinksTheCardForTheCVEItNames() {
        let kev = DigestItem(id: "CVE-2026-109618", kind: .vulnerability, title: "PHP", summary: "", vendor: "PHP Group", product: "PHP", sources: [.kev])
        let story = DigestItem(id: "sansISC:1", kind: .news, title: "PHP", summary: "", sources: [.sansISC],
                               links: [DigestLink(source: .sansISC, url: URL(string: "https://isc.sans.edu/diary/32400")!)],
                               cves: ["CVE-2026-109618"])
        let merged = DigestMerge.merge(kev: [kev], msrc: [], alerts: [], advisories: [], news: [story])
        XCTAssertEqual(merged.count, 2, "the story stays its own item")
        let card = merged.first { $0.id == kev.id }
        XCTAssertEqual(card?.links.map(\.source), [.sansISC])
    }

    func test_theReleasePolicyReadsNoNewsUntilAPublisherAgrees() {
        // A publisher's written agreement is what adds a source here (DIGEST-AND-PEOPLE-PLAN.md).
        XCTAssertTrue(DigestNewsPolicy.agreed.isEmpty)
        XCTAssertTrue(DigestNewsPolicy.agreedFullText.isEmpty)
        XCTAssertTrue(DigestNewsPolicy.agreedFullText.isSubset(of: DigestNewsPolicy.agreed))
    }

    func test_aNewsHostIsAllowedOnlyWhileItsSourceIsOn() {
        for source in DigestSource.allCases where source.isNews {
            XCTAssertEqual(ThreatDigestService.allowedHosts.contains(source.host), DigestNewsPolicy.enabled.contains(source), source.title)
        }
        for source in DigestSource.feeds {
            XCTAssertTrue(ThreatDigestService.allowedHosts.contains(source.host))
        }
    }
}
