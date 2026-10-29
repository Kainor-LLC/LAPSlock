import Foundation

// The Threat Digest. Spec section 3.14.
//
// Public feeds, merged by CVE and ranked for a Microsoft shop, for an administrator who
// gets notification fatigue and wants the few things that matter this week. The app has
// no model and no server, so it ranks and quotes; it never writes a summary of its own.
// Every summary on a card is the source's own text, trimmed.
//
// This target imports Foundation and nothing else. It never sees a token, a tenant id or
// a credential, and the isolation guard keeps it that way: the only thing it sends is a
// GET for a public file.

/// Where an item came from. One item can come from several.
public enum DigestSource: String, Codable, Sendable, CaseIterable, Comparable {
    case kev
    case msrc
    case cisaAlert
    case cisaAdvisory
    /// News, read only where DigestNewsPolicy allows it.
    case sansISC
    case bleepingComputer

    public var title: String {
        switch self {
        case .kev:              return "CISA KEV"
        case .msrc:             return "Microsoft MSRC"
        case .cisaAlert:        return "CISA Alert"
        case .cisaAdvisory:     return "CISA Advisory"
        case .sansISC:          return "SANS Internet Storm Center"
        case .bleepingComputer: return "BleepingComputer"
        }
    }

    public var host: String {
        switch self {
        case .kev, .cisaAlert, .cisaAdvisory: return "www.cisa.gov"
        case .msrc:                           return "api.msrc.microsoft.com"
        case .sansISC:                        return "isc.sans.edu"
        case .bleepingComputer:               return "www.bleepingcomputer.com"
        }
    }

    public var isNews: Bool { self == .sansISC || self == .bleepingComputer }

    /// The four sources every build reads.
    public static let feeds: [DigestSource] = [.kev, .msrc, .cisaAlert, .cisaAdvisory]

    /// Catalog first, then Microsoft, then the two CISA feeds: the order a card lists them.
    public static func < (a: DigestSource, b: DigestSource) -> Bool {
        (Self.allCases.firstIndex(of: a) ?? 0) < (Self.allCases.firstIndex(of: b) ?? 0)
    }
}

/// The signals the ranker found on an item. Shown as chips so the reader sees why a
/// card is where it is.
public enum DigestSignal: String, Codable, Sendable, CaseIterable, Comparable {
    case exploited
    case ransomware
    case overdue
    case dueSoon
    case moreLikely
    case publiclyDisclosed
    case critical
    case microsoft
    case advisory
    case new

    public var label: String {
        switch self {
        case .exploited:         return "Exploited in the wild"
        case .ransomware:        return "Ransomware use"
        case .overdue:           return "Past CISA due date"
        case .dueSoon:           return "CISA due soon"
        case .moreLikely:        return "Exploitation more likely"
        case .publiclyDisclosed: return "Publicly disclosed"
        case .critical:          return "Critical"
        case .microsoft:         return "Microsoft"
        case .advisory:          return "CISA advisory"
        case .new:               return "New"
        }
    }

    public static func < (a: DigestSignal, b: DigestSignal) -> Bool { a.order < b.order }

    private var order: Int { Self.allCases.firstIndex(of: self) ?? 0 }
}

public struct DigestLink: Codable, Sendable, Equatable, Identifiable {
    public let source: DigestSource
    public let url: URL
    public var id: String { source.rawValue + "|" + url.absoluteString }
    public init(source: DigestSource, url: URL) {
        self.source = source
        self.url = url
    }
}

/// One card. A vulnerability (keyed by CVE, merged across sources) or an advisory.
public struct DigestItem: Codable, Sendable, Equatable, Identifiable {

    public enum Kind: String, Codable, Sendable {
        case vulnerability
        case advisory
        case news
    }

    public let id: String
    public let kind: Kind
    public var title: String
    /// The source's own words, HTML stripped and trimmed. Never written by the app.
    public var summary: String
    public var vendor: String?
    public var product: String?
    public var sources: Set<DigestSource>
    public var links: [DigestLink]
    /// The newest date any source gave: KEV date added, MSRC release, feed publish date.
    public var published: Date?
    /// CVEs this item names, for an advisory that mentions several.
    public var cves: [String]

    // KEV
    public var kevDateAdded: Date?
    public var kevDueDate: Date?
    public var kevRansomware: Bool
    public var kevRequiredAction: String?

    // MSRC
    public var msrcSeverity: String?
    public var msrcImpact: String?
    public var msrcExploited: Bool
    public var msrcPubliclyDisclosed: Bool
    public var msrcExploitability: String?
    public var cvssBase: Double?

    // News
    public var author: String?
    /// The article in paragraphs, where the publisher allows full text. Never written by
    /// the app.
    public var articleText: String?

    public init(
        id: String,
        kind: Kind,
        title: String,
        summary: String,
        vendor: String? = nil,
        product: String? = nil,
        sources: Set<DigestSource>,
        links: [DigestLink] = [],
        published: Date? = nil,
        cves: [String] = [],
        kevDateAdded: Date? = nil,
        kevDueDate: Date? = nil,
        kevRansomware: Bool = false,
        kevRequiredAction: String? = nil,
        msrcSeverity: String? = nil,
        msrcImpact: String? = nil,
        msrcExploited: Bool = false,
        msrcPubliclyDisclosed: Bool = false,
        msrcExploitability: String? = nil,
        cvssBase: Double? = nil,
        author: String? = nil,
        articleText: String? = nil
    ) {
        self.id = id
        self.kind = kind
        self.title = title
        self.summary = summary
        self.vendor = vendor
        self.product = product
        self.sources = sources
        self.links = links
        self.published = published
        self.cves = cves
        self.kevDateAdded = kevDateAdded
        self.kevDueDate = kevDueDate
        self.kevRansomware = kevRansomware
        self.kevRequiredAction = kevRequiredAction
        self.msrcSeverity = msrcSeverity
        self.msrcImpact = msrcImpact
        self.msrcExploited = msrcExploited
        self.msrcPubliclyDisclosed = msrcPubliclyDisclosed
        self.msrcExploitability = msrcExploitability
        self.cvssBase = cvssBase
        self.author = author
        self.articleText = articleText
    }

    /// Whether this is about a Microsoft product, by vendor, by source, or by the
    /// product words a Microsoft shop cares about. Whole words only: the first live run
    /// put "ONLYOFFICE" under Microsoft because it contains "office".
    public var isMicrosoft: Bool {
        if isRepublishedThirdParty { return false }
        if sources.contains(.msrc) { return true }
        if let vendor, vendor.localizedCaseInsensitiveContains("microsoft") { return true }
        let haystack = DigestVocabulary.words([title, product ?? "", vendor ?? ""].joined(separator: " "))
        // A headline is loose prose: "edge devices", "red teams" and "crypto exchange" are not
        // Microsoft, so news is matched on the stricter list.
        let words = kind == .news ? DigestVocabulary.microsoftNewsWords : DigestVocabulary.microsoftWords
        return DigestVocabulary.contains(words, in: haystack)
    }

    /// The filter categories this item belongs to; one item can be in several. A
    /// vulnerability in a product no category names is Other Vendors.
    public var categories: Set<DigestCategory> {
        var found: Set<DigestCategory> = []
        if isMicrosoft { found.insert(.microsoft) }
        let haystack = DigestVocabulary.words([title, product ?? "", vendor ?? ""].joined(separator: " "))
        if DigestVocabulary.contains(DigestVocabulary.networkWords, in: haystack) { found.insert(.networkAccess) }
        if DigestVocabulary.contains(DigestVocabulary.webWords, in: haystack) { found.insert(.webServers) }
        if DigestVocabulary.contains(DigestVocabulary.endpointWords, in: haystack) { found.insert(.endpointsBrowsers) }
        switch kind {
        case .vulnerability:
            if found.isEmpty { found.insert(.otherVendors) }
        case .advisory:
            found.insert(.advisories)
        case .news:
            found.insert(.news)
        }
        return found
    }

    /// MSRC republishes third-party CVEs that ship inside Edge (Chromium) and Azure Linux
    /// (Mariner), hundreds a month, titled "Google: CVE-..." or "Chromium: CVE-...". They
    /// are patched by the browser's own updater and are not what an admin opens this
    /// digest for, so they do not count as Microsoft and the default filter hides them.
    public var isRepublishedThirdParty: Bool {
        guard sources.contains(.msrc), !sources.contains(.kev) else { return false }
        if let product, product.localizedCaseInsensitiveContains("mariner") { return true }
        let lower = title.lowercased()
        for prefix in ["google:", "chromium:", "mariner:", "azure linux:"] where lower.hasPrefix(prefix) { return true }
        return false
    }

    /// The one line under the title: vendor and product, the sources for an advisory, or
    /// the publication and author for news.
    public var subtitle: String {
        switch kind {
        case .vulnerability:
            let parts = [vendor, product].compactMap { $0 }.filter { !$0.isEmpty }
            if parts.isEmpty { return id }
            if parts.count == 2, parts[1].localizedCaseInsensitiveContains(parts[0]) { return parts[1] }
            return parts.joined(separator: " ")
        case .advisory:
            return sources.sorted().map(\.title).joined(separator: ", ")
        case .news:
            let source = sources.sorted().first?.title ?? ""
            guard let author, !author.isEmpty else { return source }
            return source + ", " + author
        }
    }
}

/// What the Digest's filter and its notifications choose by. Several can be on at once.
public enum DigestCategory: String, Codable, Sendable, CaseIterable, Identifiable, Comparable {
    case microsoft
    case networkAccess
    case webServers
    case endpointsBrowsers
    case advisories
    case news
    case otherVendors

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .microsoft:         return "Microsoft"
        case .networkAccess:     return "Network and Remote Access"
        case .webServers:        return "Web and Servers"
        case .endpointsBrowsers: return "Endpoints and Browsers"
        case .advisories:        return "CISA Advisories"
        case .news:              return "News"
        case .otherVendors:      return "Other Vendors"
        }
    }

    /// What the category takes in, for the line under it in a menu or a setting.
    public var detail: String {
        switch self {
        case .microsoft:         return "Windows, Microsoft 365, Azure and the rest of Microsoft"
        case .networkAccess:     return "Firewalls, VPNs, routers and remote support tools"
        case .webServers:        return "PHP, WordPress, Apache, Atlassian, GitLab and other server software"
        case .endpointsBrowsers: return "Apple, Android, Chrome, Firefox, Linux, VMware and certificates"
        case .advisories:        return "CISA alerts and joint advisories"
        case .news:              return "Security news from the publications the app reads"
        case .otherVendors:      return "Exploited vulnerabilities in anything else"
        }
    }

    public static func < (a: DigestCategory, b: DigestCategory) -> Bool {
        (allCases.firstIndex(of: a) ?? 0) < (allCases.firstIndex(of: b) ?? 0)
    }
}

/// One source's outcome on a fetch, so a feed that is down shows as one row and the
/// others still render.
public struct DigestSourceStatus: Sendable, Equatable {
    public enum State: Sendable, Equatable {
        case ok(itemCount: Int)
        case unavailable(reason: String)
    }
    public let source: DigestSource
    public let state: State
    public init(source: DigestSource, state: State) {
        self.source = source
        self.state = state
    }
    public var isAvailable: Bool {
        if case .ok = state { return true }
        return false
    }
}

/// Everything the screen needs from one refresh.
public struct DigestSnapshot: Sendable, Equatable {
    public var items: [DigestItem]
    public var statuses: [DigestSourceStatus]
    public var fetchedAt: Date
    public init(items: [DigestItem], statuses: [DigestSourceStatus], fetchedAt: Date) {
        self.items = items
        self.statuses = statuses
        self.fetchedAt = fetchedAt
    }
    public var unavailable: [DigestSourceStatus] { statuses.filter { !$0.isAvailable } }
}

public enum DigestError: Error, Sendable, Equatable {
    case hostNotAllowed(String)
    case transport(status: Int)
    case tooLarge
    case decodeFailure
    case offline
}

/// Words that mark an item as Microsoft's business even when the vendor field does not.
public enum DigestVocabulary {
    public static let microsoftWords: [String] = [
        "microsoft", "windows", "office", "outlook", "exchange", "sharepoint", "entra",
        "azure", "intune", "defender", "active directory", "sql server", "hyper-v",
        "edge", "teams", "onedrive", ".net", "asp.net", "visual studio", "iis", "smb",
        "ntlm", "kerberos", "bitlocker", "power platform", "dynamics"
    ]

    /// For headlines: only words that cannot mean anything but Microsoft.
    public static let microsoftNewsWords: [String] = [
        "microsoft", "windows", "outlook", "exchange server", "exchange online", "sharepoint", "entra",
        "azure", "intune", "active directory", "hyper-v", "onedrive", "bitlocker", "office 365",
        "microsoft 365", "m365", "msrc", "patch tuesday", "kerberos", "ntlm"
    ]

    public static let networkWords: [String] = [
        "fortinet", "fortigate", "fortios", "fortimail", "fortiweb", "fortiproxy", "fortimanager",
        "citrix", "netscaler", "ivanti", "pulse secure", "connect secure", "palo alto", "pan-os",
        "globalprotect", "cisco", "sonicwall", "f5", "big-ip", "check point", "juniper", "junos",
        "zyxel", "mikrotik", "routeros", "arista", "velocloud", "sophos", "watchguard", "barracuda",
        "beyondtrust", "connectwise", "screenconnect", "n-able", "kaseya", "anydesk", "teamviewer",
        "splashtop", "openvpn", "vpn", "vpns", "firewall", "firewalls", "router", "routers",
        "ubiquiti", "d-link", "tp-link", "netgear", "draytek", "sd-wan", "edge devices"
    ]

    public static let webWords: [String] = [
        "php", "wordpress", "drupal", "joomla", "apache", "struts", "tomcat", "nginx", "magento",
        "adobe commerce", "atlassian", "confluence", "jira", "bitbucket", "gitlab", "jfrog",
        "artifactory", "jenkins", "strapi", "zammad", "collabora", "onlyoffice", "papercut",
        "liferay", "weblogic", "oracle", "sap", "redis", "mysql", "postgresql", "mongodb",
        "elasticsearch", "kubernetes", "docker", "web server", "web servers", "cms"
    ]

    public static let endpointWords: [String] = [
        "apple", "ios", "ipados", "macos", "safari", "webkit", "chrome", "chromium", "v8",
        "android", "pixel", "firefox", "mozilla", "thunderbird", "linux", "vmware", "esxi",
        "vcenter", "broadcom", "samsung", "qualcomm", "openssl", "openssh", "tls", "ssl",
        "certificate", "certificates", "certificate authority", "root store", "browser", "browsers"
    ]

    /// Whether any of the words or phrases stands as whole words in a haystack from `words`.
    public static func contains(_ list: [String], in haystack: String) -> Bool {
        list.contains { haystack.contains(" " + $0 + " ") }
    }

    /// Lowercased, every run of punctuation other than the ones inside product names
    /// turned into a space, padded with a space at each end, so " office " matches the
    /// word and not the middle of "onlyoffice".
    public static func words(_ text: String) -> String {
        var out = " "
        var lastWasSpace = true
        for ch in text.lowercased() {
            let keep = ch.isLetter || ch.isNumber || ch == "." || ch == "-"
            if keep {
                out.append(ch)
                lastWasSpace = false
            } else if !lastWasSpace {
                out.append(" ")
                lastWasSpace = true
            }
        }
        if !lastWasSpace { out.append(" ") }
        return out
    }
}
