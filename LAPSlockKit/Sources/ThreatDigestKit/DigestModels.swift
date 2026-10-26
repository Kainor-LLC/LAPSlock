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

    public var title: String {
        switch self {
        case .kev:          return "CISA KEV"
        case .msrc:         return "Microsoft MSRC"
        case .cisaAlert:    return "CISA Alert"
        case .cisaAdvisory: return "CISA Advisory"
        }
    }

    public var host: String {
        switch self {
        case .kev, .cisaAlert, .cisaAdvisory: return "www.cisa.gov"
        case .msrc:                           return "api.msrc.microsoft.com"
        }
    }

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
        cvssBase: Double? = nil
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
    }

    /// Whether this is about a Microsoft product, by vendor, by source, or by the
    /// product words a Microsoft shop cares about. Whole words only: the first live run
    /// put "ONLYOFFICE" under Microsoft because it contains "office".
    public var isMicrosoft: Bool {
        if isRepublishedThirdParty { return false }
        if sources.contains(.msrc) { return true }
        if let vendor, vendor.localizedCaseInsensitiveContains("microsoft") { return true }
        let haystack = DigestVocabulary.words([title, product ?? "", vendor ?? ""].joined(separator: " "))
        return DigestVocabulary.microsoftWords.contains { haystack.contains(" " + $0 + " ") }
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

    /// The one line under the title: vendor and product, or the sources for an advisory.
    public var subtitle: String {
        switch kind {
        case .vulnerability:
            let parts = [vendor, product].compactMap { $0 }.filter { !$0.isEmpty }
            if parts.isEmpty { return id }
            if parts.count == 2, parts[1].localizedCaseInsensitiveContains(parts[0]) { return parts[1] }
            return parts.joined(separator: " ")
        case .advisory:
            return sources.sorted().map(\.title).joined(separator: ", ")
        }
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
