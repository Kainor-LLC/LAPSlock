import XCTest
@testable import ThreatDigestKit

final class DigestParserTests: XCTestCase {

    private let now = DigestDates.parse("2026-10-25T12:00:00Z")!

    // MARK: dates

    func test_everyDateSpellingTheFeedsUse() {
        XCTAssertNotNil(DigestDates.parse("2026-10-23"))
        XCTAssertNotNil(DigestDates.parse("2026-10-23T19:30:18.9209Z"))
        XCTAssertNotNil(DigestDates.parse("2026-10-25T07:00:00-07:00"))
        XCTAssertNotNil(DigestDates.parse("Fri, 23 Oct 26 12:00:00 +0000"))
        XCTAssertNotNil(DigestDates.parse("Mon, 19 Oct 2026 12:00:00 +0000"))
        XCTAssertNotNil(DigestDates.parse("Sun, 25 Oct 2026 07:00:00 -0700"))
        XCTAssertNil(DigestDates.parse(nil))
        XCTAssertNil(DigestDates.parse("yesterday"))
        let two = DigestDates.parse("Fri, 23 Oct 26 12:00:00 +0000")!
        let four = DigestDates.parse("Fri, 23 Oct 2026 12:00:00 +0000")!
        XCTAssertEqual(two, four)
    }

    // MARK: text

    func test_plainStripsTagsDecodesEntitiesAndTruncatesOnAWord() {
        let html = "<p>CISA has added one&nbsp;new vulnerability to its <a href=\"x\">Known Exploited</a> Catalog, based on evidence.</p>\n<p>It&#39;s urgent &amp; real.</p>"
        XCTAssertEqual(DigestText.plain(html), "CISA has added one new vulnerability to its Known Exploited Catalog, based on evidence. It's urgent & real.")
        let long = String(repeating: "word ", count: 300)
        let cut = DigestText.plain(long, limit: 50)
        XCTAssertTrue(cut.hasSuffix("\u{2026}"))
        XCTAssertLessThanOrEqual(cut.count, 51)
        XCTAssertFalse(cut.contains("wor\u{2026}"))
    }

    func test_cveExtractionFindsEachOnce() {
        let text = "Adds CVE-2026-41107, cve-2026-41107 and CVE-2019-1068; not CVE-12-3 or CVE-2026-12."
        XCTAssertEqual(DigestText.cves(in: text), ["CVE-2026-41107", "CVE-2019-1068"])
        XCTAssertEqual(DigestText.cves(in: "nothing here"), [])
    }

    // MARK: KEV

    private let kevJSON = """
    {"title":"CISA Catalog of Known Exploited Vulnerabilities","catalogVersion":"2026.10.23","dateReleased":"2026-10-23T19:30:18.9209Z","count":2,
     "vulnerabilities":[
      {"cveID":"CVE-2026-96951","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"Microsoft Windows Command Injection Vulnerability","dateAdded":"2026-10-13","shortDescription":"Microsoft Windows contains a command injection vulnerability.","requiredAction":"Apply mitigations per vendor instructions.","dueDate":"2026-10-16","knownRansomwareCampaignUse":"Known","notes":"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-96951 ; BOD 26-04","cwes":["CWE-77"]},
      {"cveID":"CVE-2019-1068","vendorProject":"Microsoft","product":"SQL Server","vulnerabilityName":"Old one","dateAdded":"2026-06-01","shortDescription":"Old.","requiredAction":"Apply.","dueDate":"2026-06-10","knownRansomwareCampaignUse":"Unknown","notes":"","cwes":[]}
     ]}
    """

    func test_kevWindowAndFields() throws {
        let catalog = try JSONDecoder().decode(KEVCatalog.self, from: Data(kevJSON.utf8))
        XCTAssertEqual(catalog.count, 2)
        let items = catalog.items(addedWithinDays: 60, now: now)
        XCTAssertEqual(items.count, 1)
        let item = try XCTUnwrap(items.first)
        XCTAssertEqual(item.id, "CVE-2026-96951")
        XCTAssertEqual(item.kind, .vulnerability)
        XCTAssertTrue(item.kevRansomware)
        XCTAssertEqual(item.kevDueDate, DigestDates.parse("2026-10-16"))
        XCTAssertEqual(item.links.first?.url.absoluteString, "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-96951")
        XCTAssertEqual(item.subtitle, "Microsoft Windows")
        XCTAssertTrue(item.isMicrosoft)
        XCTAssertEqual(catalog.items(addedWithinDays: 365, now: now).count, 2)
    }

    func test_kevWithoutAUsableNoteLinksToTheCatalogPage() throws {
        let catalog = try JSONDecoder().decode(KEVCatalog.self, from: Data(kevJSON.utf8))
        let old = catalog.items(addedWithinDays: 365, now: now).first { $0.id == "CVE-2019-1068" }
        XCTAssertEqual(old?.links.first?.url, KEVCatalog.catalogPage)
    }

    // MARK: MSRC

    private let msrcJSON = """
    {"@odata.context":"x","@odata.count":2,"value":[
     {"id":"1","releaseDate":"2026-10-25T07:00:00-07:00","cveNumber":"CVE-2026-114148","cveTitle":"ASP.NET Core Elevation of Privilege Vulnerability","releaseNumber":"2026-Oct","description":"<p>Incorrect default permissions in ASP.NET Core allows an authorized attacker to elevate privileges locally.</p>\\n","publiclyDisclosed":"No","exploited":"No","latestSoftwareRelease":"Exploitation Less Likely","tag":"ASP.NET Core","severity":"Important","impact":"Elevation of Privilege","baseScore":"7.8","articles":[{"title":"x"}],"revisions":[]},
     {"id":"2","releaseDate":"2026-10-14T07:00:00-07:00","cveNumber":"CVE-2026-114148","cveTitle":"Duplicate row for another product","tag":"Visual Studio","severity":"Important"},
     {"id":"3","releaseDate":"2026-10-14T07:00:00-07:00","cveNumber":"CVE-2026-96951","cveTitle":"Windows Shell Command Injection","description":"<p>Command injection.</p>","publiclyDisclosed":"Yes","exploited":"Yes","latestSoftwareRelease":"Exploitation Detected","tag":"Windows Shell","severity":"Important","impact":"Remote Code Execution","baseScore":"8.8"}
    ]}
    """

    func test_msrcKeepsOneRowPerCVEAndReadsTheFlags() throws {
        let page = try JSONDecoder().decode(MSRCPage.self, from: Data(msrcJSON.utf8))
        let items = page.items.sorted { $0.id < $1.id }
        XCTAssertEqual(items.map(\.id), ["CVE-2026-114148", "CVE-2026-96951"])
        let aspnet = items[0]
        XCTAssertEqual(aspnet.title, "ASP.NET Core Elevation of Privilege Vulnerability")
        XCTAssertEqual(aspnet.summary, "Incorrect default permissions in ASP.NET Core allows an authorized attacker to elevate privileges locally.")
        XCTAssertEqual(aspnet.product, "ASP.NET Core")
        XCTAssertEqual(aspnet.cvssBase, 7.8)
        XCTAssertFalse(aspnet.msrcExploited)
        let shell = items[1]
        XCTAssertTrue(shell.msrcExploited)
        XCTAssertTrue(shell.msrcPubliclyDisclosed)
        XCTAssertEqual(shell.msrcExploitability, "Exploitation Detected")
        XCTAssertEqual(shell.links.first?.url.absoluteString, "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96951")
    }

    func test_msrcQueryCarriesTheFilterTheServiceAccepts() {
        let url = MSRCPage.url(since: now, top: 200)
        let s = url.absoluteString
        XCTAssertTrue(s.hasPrefix("https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?"), s)
        XCTAssertTrue(s.contains("exploited%20eq%20'Yes'"), s)
        XCTAssertTrue(s.contains("releaseDate%20ge%202026-10-25T12:00:00Z"), s)
        XCTAssertTrue(s.contains("$top=200"), s)
        XCTAssertFalse(s.contains("$select"), "the service answers 403 to $select")
    }

    // MARK: RSS

    private let rss = """
    <?xml version="1.0" encoding="utf-8"?>
    <rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>All CISA Advisories</title>
    <item><title>CISA Adds One Known Exploited Vulnerability to Catalog</title><link>https://www.cisa.gov/news-events/alerts/2026/10/23/cisa-adds-one</link>
    <description>&lt;p&gt;CISA has added one new vulnerability: &lt;a href="x"&gt;CVE-2026-96951&lt;/a&gt; Microsoft Windows Command Injection Vulnerability.&lt;/p&gt;</description>
    <pubDate>Fri, 23 Oct 26 12:00:00 +0000</pubDate><dc:creator>CISA</dc:creator><guid>/node/25710</guid></item>
    <item><title>#StopRansomware: SafePay Ransomware</title><link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a</link>
    <description><![CDATA[<h2>Summary</h2><p>\(String(repeating: "Long advisory text. ", count: 2000))</p>]]></description>
    <pubDate>Mon, 19 Oct 2026 12:00:00 +0000</pubDate><guid>/node/25600</guid></item>
    <item><title>No link</title><link>ftp://nope</link><description>x</description><pubDate>Mon, 19 Oct 2026 12:00:00 +0000</pubDate></item>
    </channel></rss>
    """

    func test_rssReaderBoundsDescriptionsAndKeepsTheRest() {
        let items = RSSReader.read(Data(rss.utf8), descriptionCap: 500)
        XCTAssertEqual(items.count, 3)
        XCTAssertEqual(items[0].title, "CISA Adds One Known Exploited Vulnerability to Catalog")
        XCTAssertEqual(items[0].guid, "/node/25710")
        XCTAssertTrue(items[0].description.contains("CVE-2026-96951"))
        XCTAssertLessThan(items[1].description.count, 600, "the cap holds even for CDATA")
        XCTAssertTrue(items[1].description.hasPrefix("<h2>Summary</h2>"))
    }

    func test_feedItemsBecomeAdvisoriesWithCVEsAndDropBadLinks() {
        let items = CISAFeeds.items(RSSReader.read(Data(rss.utf8)), source: .cisaAlert)
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(items[0].id, "cisaAlert:/node/25710")
        XCTAssertEqual(items[0].cves, ["CVE-2026-96951"])
        XCTAssertEqual(items[0].kind, .advisory)
        XCTAssertEqual(items[0].summary, "CISA has added one new vulnerability: CVE-2026-96951 Microsoft Windows Command Injection Vulnerability.")
        XCTAssertEqual(items[0].published, DigestDates.parse("2026-10-23T12:00:00Z"))
        XCTAssertEqual(items[0].links.first?.source, .cisaAlert)
    }

    // MARK: merge

    func test_mergeJoinsKEVAndMSRCByCVEAndDissolvesKEVAnnouncements() throws {
        let catalog = try JSONDecoder().decode(KEVCatalog.self, from: Data(kevJSON.utf8))
        let kev = catalog.items(addedWithinDays: 60, now: now)
        let msrc = try JSONDecoder().decode(MSRCPage.self, from: Data(msrcJSON.utf8)).items
        let alerts = CISAFeeds.items(RSSReader.read(Data(rss.utf8)), source: .cisaAlert)
        let merged = DigestMerge.merge(kev: kev, msrc: msrc, alerts: alerts, advisories: [])
        let shell = try XCTUnwrap(merged.first { $0.id == "CVE-2026-96951" })
        XCTAssertEqual(shell.sources, [.kev, .msrc, .cisaAlert])
        XCTAssertEqual(shell.links.count, 3)
        XCTAssertTrue(shell.kevRansomware)
        XCTAssertTrue(shell.msrcExploited)
        XCTAssertEqual(shell.title, "Microsoft Windows Command Injection Vulnerability", "KEV's name wins when both have one")
        XCTAssertNil(merged.first { $0.id == "cisaAlert:/node/25710" }, "the KEV announcement dissolved into its CVE")
        XCTAssertNotNil(merged.first { $0.id == "cisaAlert:/node/25600" }, "an advisory stays a card")
        XCTAssertNotNil(merged.first { $0.id == "CVE-2026-114148" }, "an MSRC-only CVE stays")
    }

    func test_kevAnnouncementWithUnknownCVEsStaysACard() {
        let alert = DigestItem(id: "cisaAlert:x", kind: .advisory, title: "CISA Adds Three Known Exploited Vulnerabilities to Catalog", summary: "", sources: [.cisaAlert], cves: ["CVE-2026-1"])
        let merged = DigestMerge.merge(kev: [], msrc: [], alerts: [alert], advisories: [])
        XCTAssertEqual(merged.map(\.id), ["cisaAlert:x"])
    }
}
