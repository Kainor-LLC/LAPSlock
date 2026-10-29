import Foundation

// Demo digest. Powers previews, development offline, and App Store review, so a reviewer
// never depends on four live feeds. Shaped to exercise every signal chip, a merged
// KEV-plus-MSRC card, a ransomware flag, an overdue due date, a due-soon one, a
// non-Microsoft vulnerability the default filter hides, a standalone CISA alert, two
// advisories, and one source reported as unavailable so that row is seen too.

public actor DemoThreatDigestProvider: ThreatDigestProviding {

    private let latency: Duration
    private let now: Date
    private let msrcUnavailable: Bool

    public init(latency: Duration = .milliseconds(500), now: Date = Date(), msrcUnavailable: Bool = false) {
        self.latency = latency
        self.now = now
        self.msrcUnavailable = msrcUnavailable
    }

    public func digest() async throws -> DigestSnapshot {
        try await Task.sleep(for: latency)
        return Self.snapshot(now: now, msrcUnavailable: msrcUnavailable)
    }

    public static let mergedCVE = "CVE-2026-41107"
    public static let ransomwareCVE = "CVE-2026-33820"
    public static let overdueCVE = "CVE-2026-28811"
    public static let otherVendorCVE = "CVE-2026-50233"
    public static let disclosedCVE = "CVE-2026-44190"

    public static func snapshot(now: Date, msrcUnavailable: Bool = false) -> DigestSnapshot {
        func day(_ n: Double) -> Date { now.addingTimeInterval(-n * 86_400) }
        let kev: [DigestItem] = [
            DigestItem(id: mergedCVE, kind: .vulnerability,
                       title: "Microsoft Windows SMB Client Elevation of Privilege Vulnerability",
                       summary: "Microsoft Windows SMB Client contains an improper access control vulnerability that allows an attacker to elevate privileges by coercing a connection to a malicious server.",
                       vendor: "Microsoft", product: "Windows", sources: [.kev],
                       links: [DigestLink(source: .kev, url: URL(string: "https://msrc.microsoft.com/update-guide/vulnerability/" + mergedCVE)!)],
                       published: day(2), cves: [mergedCVE], kevDateAdded: day(2), kevDueDate: day(-12), kevRansomware: false,
                       kevRequiredAction: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable."),
            DigestItem(id: ransomwareCVE, kind: .vulnerability,
                       title: "Microsoft SharePoint Server Deserialization of Untrusted Data Vulnerability",
                       summary: "Microsoft SharePoint Server contains a deserialization of untrusted data vulnerability that allows an unauthenticated attacker to execute code over a network.",
                       vendor: "Microsoft", product: "SharePoint Server", sources: [.kev],
                       links: [DigestLink(source: .kev, url: URL(string: "https://msrc.microsoft.com/update-guide/vulnerability/" + ransomwareCVE)!)],
                       published: day(9), cves: [ransomwareCVE], kevDateAdded: day(9), kevDueDate: day(-5), kevRansomware: true,
                       kevRequiredAction: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable."),
            DigestItem(id: overdueCVE, kind: .vulnerability,
                       title: "Microsoft Exchange Server Improper Input Validation Vulnerability",
                       summary: "Microsoft Exchange Server contains an improper input validation vulnerability that allows an authenticated attacker to run arbitrary code with SYSTEM privileges.",
                       vendor: "Microsoft", product: "Exchange Server", sources: [.kev],
                       links: [DigestLink(source: .kev, url: URL(string: "https://msrc.microsoft.com/update-guide/vulnerability/" + overdueCVE)!)],
                       published: day(24), cves: [overdueCVE], kevDateAdded: day(24), kevDueDate: day(3), kevRansomware: false,
                       kevRequiredAction: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable."),
            DigestItem(id: otherVendorCVE, kind: .vulnerability,
                       title: "Fortinet FortiOS Out-of-Bounds Write Vulnerability",
                       summary: "Fortinet FortiOS and FortiProxy contain an out-of-bounds write vulnerability that allows a remote unauthenticated attacker to execute code via crafted requests.",
                       vendor: "Fortinet", product: "FortiOS", sources: [.kev],
                       links: [DigestLink(source: .kev, url: URL(string: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")!)],
                       published: day(4), cves: [otherVendorCVE], kevDateAdded: day(4), kevDueDate: day(-17), kevRansomware: false,
                       kevRequiredAction: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.")
        ]
        let msrc: [DigestItem] = msrcUnavailable ? [] : [
            DigestItem(id: mergedCVE, kind: .vulnerability,
                       title: "Windows SMB Client Elevation of Privilege Vulnerability",
                       summary: "Improper access control in Windows SMB Client allows an authorized attacker to elevate privileges over a network.",
                       vendor: "Microsoft", product: "Windows SMB Client", sources: [.msrc],
                       links: [DigestLink(source: .msrc, url: MSRCPage.guidePage(mergedCVE))],
                       published: day(11), cves: [mergedCVE],
                       msrcSeverity: "Important", msrcImpact: "Elevation of Privilege", msrcExploited: true, msrcPubliclyDisclosed: true,
                       msrcExploitability: "Exploitation Detected", cvssBase: 8.8),
            DigestItem(id: disclosedCVE, kind: .vulnerability,
                       title: "Windows Kerberos Elevation of Privilege Vulnerability",
                       summary: "Improper authentication in Windows Kerberos allows an unauthorized attacker to elevate privileges over a network.",
                       vendor: "Microsoft", product: "Windows Kerberos", sources: [.msrc],
                       links: [DigestLink(source: .msrc, url: MSRCPage.guidePage(disclosedCVE))],
                       published: day(11), cves: [disclosedCVE],
                       msrcSeverity: "Critical", msrcImpact: "Elevation of Privilege", msrcExploited: false, msrcPubliclyDisclosed: true,
                       msrcExploitability: "Exploitation More Likely", cvssBase: 9.8),
            DigestItem(id: "CVE-2026-44301", kind: .vulnerability,
                       title: "Microsoft Office Remote Code Execution Vulnerability",
                       summary: "Use after free in Microsoft Office allows an unauthorized attacker to execute code locally. The Preview Pane is an attack vector.",
                       vendor: "Microsoft", product: "Microsoft Office", sources: [.msrc],
                       links: [DigestLink(source: .msrc, url: MSRCPage.guidePage("CVE-2026-44301"))],
                       published: day(11), cves: ["CVE-2026-44301"],
                       msrcSeverity: "Critical", msrcImpact: "Remote Code Execution", msrcExploited: false, msrcPubliclyDisclosed: false,
                       msrcExploitability: "Exploitation Less Likely", cvssBase: 8.4)
        ]
        let alerts: [DigestItem] = [
            DigestItem(id: "cisaAlert:/node/90101", kind: .advisory,
                       title: "CISA Adds Two Known Exploited Vulnerabilities to Catalog",
                       summary: "CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities Catalog, based on evidence of active exploitation. " + mergedCVE + " Microsoft Windows SMB Client Elevation of Privilege Vulnerability; " + otherVendorCVE + " Fortinet FortiOS Out-of-Bounds Write Vulnerability.",
                       sources: [.cisaAlert],
                       links: [DigestLink(source: .cisaAlert, url: URL(string: "https://www.cisa.gov/news-events/alerts/2026/10/23/cisa-adds-two-known-exploited-vulnerabilities-catalog")!)],
                       published: day(2), cves: [mergedCVE, otherVendorCVE]),
            DigestItem(id: "cisaAlert:/node/90088", kind: .advisory,
                       title: "Critical Vulnerabilities in a Widely Used Remote Support Tool Require Immediate Patching",
                       summary: "CISA urges organizations to apply the vendor's patches for two critical vulnerabilities in a remote support product that are being chained for unauthenticated remote code execution.",
                       sources: [.cisaAlert],
                       links: [DigestLink(source: .cisaAlert, url: URL(string: "https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-remote-support-tool")!)],
                       published: day(4), cves: ["CVE-2026-50980", "CVE-2026-50981"])
        ]
        let advisories: [DigestItem] = [
            DigestItem(id: "cisaAdvisory:aa26-293a", kind: .advisory,
                       title: "#StopRansomware: SafePay Ransomware",
                       summary: "This joint advisory details the tactics, techniques and procedures of SafePay ransomware actors, including initial access through VPN appliances with weak MFA, credential dumping, and exfiltration before encryption. Indicators of compromise and mitigations are included.",
                       sources: [.cisaAdvisory],
                       links: [DigestLink(source: .cisaAdvisory, url: URL(string: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a")!)],
                       published: day(6), cves: []),
            DigestItem(id: "cisaAdvisory:aa26-281a", kind: .advisory,
                       title: "State-Sponsored Actors Combine Automated and Hands-on Tools Against Cloud Identity",
                       summary: "Joint advisory on a campaign that pairs automated credential spraying against Entra ID with hands-on follow-up, including consent phishing for OAuth applications and token theft. Mitigations include phishing-resistant MFA and Conditional Access on device compliance.",
                       sources: [.cisaAdvisory],
                       links: [DigestLink(source: .cisaAdvisory, url: URL(string: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a")!)],
                       published: day(19), cves: [])
        ]
        // Invented stories, not any publisher's words, under the same policy as the real
        // feeds: a build that may not read a publisher does not show its name either.
        let news: [DigestItem] = [
            DigestItem(id: "sansISC:demo-1", kind: .news,
                       title: "Scans for a New FortiOS Flaw Pick Up",
                       summary: "Sensors saw a jump in requests aimed at the FortiOS flaw CISA added this week. Most come from a small set of addresses.",
                       sources: [.sansISC],
                       links: [DigestLink(source: .sansISC, url: URL(string: "https://isc.sans.edu/diary/")!)],
                       published: day(1), cves: [otherVendorCVE], author: "Demo Handler",
                       articleText: "Sensors saw a jump in requests aimed at the FortiOS flaw CISA added this week. Most come from a small set of addresses.\n\nWhat to check:\n\u{2022} Firewall logs for the request pattern\n\u{2022} The version on every FortiGate you run\n\nThis is demo text, not a real diary."),
            DigestItem(id: "bleepingComputer:demo-2", kind: .news,
                       title: "Windows Update Distrusts a Certificate Authority's Roots",
                       summary: "An out-of-band update removes a certificate authority from the Windows root store after browsers did the same. This is demo text, not a real article.",
                       sources: [.bleepingComputer],
                       links: [DigestLink(source: .bleepingComputer, url: URL(string: "https://www.bleepingcomputer.com/")!)],
                       published: day(3), author: "Demo Reporter")
        ].filter { story in story.sources.allSatisfy { DigestNewsPolicy.enabled.contains($0) } }

        let items = DigestMerge.merge(kev: kev, msrc: msrc, alerts: alerts, advisories: advisories, news: news)
        var statuses: [DigestSourceStatus] = [
            DigestSourceStatus(source: .kev, state: .ok(itemCount: kev.count)),
            DigestSourceStatus(source: .msrc, state: msrcUnavailable ? .unavailable(reason: "The feed did not answer.") : .ok(itemCount: msrc.count)),
            DigestSourceStatus(source: .cisaAlert, state: .ok(itemCount: alerts.count)),
            DigestSourceStatus(source: .cisaAdvisory, state: .ok(itemCount: advisories.count))
        ]
        for source in DigestNewsPolicy.enabled.sorted() {
            statuses.append(DigestSourceStatus(source: source, state: .ok(itemCount: news.filter { $0.sources.contains(source) }.count)))
        }
        return DigestSnapshot(items: items, statuses: statuses, fetchedAt: now)
    }
}
