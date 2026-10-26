import Foundation

// Parsers for the three feed shapes, each tested against a small fixture. Dates arrive
// in four spellings across the feeds, so one helper parses them all.

public enum DigestDates {
    /// `2026-10-23`
    static let day: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()
    /// `Fri, 23 Oct 2026 12:00:00 +0000` and the two-digit-year form CISA's alerts use.
    static let rfc822FourDigit: [DateFormatter] = ["EEE, dd MMM yyyy HH:mm:ss Z", "EEE, dd MMM yyyy HH:mm:ss zzz"].map(formatter)
    static let rfc822TwoDigit: [DateFormatter] = ["EEE, dd MMM yy HH:mm:ss Z", "EEE, dd MMM yy HH:mm:ss zzz"].map(formatter)

    static func formatter(_ pattern: String) -> DateFormatter {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = pattern
        return f
    }

    /// A lenient formatter reads "26" with a four-digit pattern as the year 26, so the
    /// year token's width picks the pattern.
    static func rfc822(for raw: String) -> [DateFormatter] {
        let tokens = raw.split(separator: " ")
        if tokens.count >= 4, tokens[3].count == 2 { return rfc822TwoDigit }
        return rfc822FourDigit
    }
    static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()
    static let isoFractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    public static func parse(_ raw: String?) -> Date? {
        guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else { return nil }
        if raw.count == 10, let d = day.date(from: raw) { return d }
        if let d = iso.date(from: raw) { return d }
        if let dot = raw.firstIndex(of: ".") {
            let digits = raw[raw.index(after: dot)...].prefix { $0.isNumber }
            let rest = raw[raw.index(after: dot)...].dropFirst(digits.count)
            let three = String(digits.prefix(3)).padding(toLength: 3, withPad: "0", startingAt: 0)
            if let d = isoFractional.date(from: String(raw[..<dot]) + "." + three + String(rest)) { return d }
        }
        for f in rfc822(for: raw) {
            if let d = f.date(from: raw) { return d }
        }
        return nil
    }
}

public enum DigestText {
    /// Drops tags, decodes the entities feeds actually use, collapses whitespace.
    public static func plain(_ html: String, limit: Int = 600) -> String {
        var out = ""
        var inTag = false
        var budget = limit * 4
        for ch in html {
            if ch == "<" { inTag = true; continue }
            if ch == ">" { inTag = false; out.append(" "); continue }
            if !inTag {
                out.append(ch)
                budget -= 1
                if budget <= 0 { break }
            }
        }
        let entities: [(String, String)] = [
            ("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""),
            ("&#39;", "'"), ("&apos;", "'"), ("&rsquo;", "\u{2019}"), ("&lsquo;", "\u{2018}"),
            ("&rdquo;", "\u{201D}"), ("&ldquo;", "\u{201C}"), ("&ndash;", "\u{2013}"), ("&mdash;", "\u{2014}"),
            ("&hellip;", "\u{2026}"), ("&#160;", " ")
        ]
        for (entity, replacement) in entities {
            out = out.replacingOccurrences(of: entity, with: replacement)
        }
        let collapsed = out.split(whereSeparator: \.isWhitespace).joined(separator: " ")
        return truncate(collapsed, to: limit)
    }

    public static func truncate(_ text: String, to limit: Int) -> String {
        guard text.count > limit else { return text }
        let cut = text.index(text.startIndex, offsetBy: limit)
        let head = text[..<cut]
        if let space = head.lastIndex(of: " ") {
            return String(head[..<space]) + "\u{2026}"
        }
        return String(head) + "\u{2026}"
    }

    /// Every CVE id in a text, in order, without duplicates.
    public static func cves(in text: String) -> [String] {
        var found: [String] = []
        var seen = Set<String>()
        let scalars = Array(text.uppercased())
        var i = 0
        while i < scalars.count {
            if i + 9 <= scalars.count, String(scalars[i..<i+4]) == "CVE-" {
                var j = i + 4
                var year = ""
                while j < scalars.count, scalars[j].isNumber, year.count < 4 { year.append(scalars[j]); j += 1 }
                if year.count == 4, j < scalars.count, scalars[j] == "-" {
                    j += 1
                    var seq = ""
                    while j < scalars.count, scalars[j].isNumber { seq.append(scalars[j]); j += 1 }
                    if seq.count >= 4 {
                        let id = "CVE-" + year + "-" + seq
                        if seen.insert(id).inserted { found.append(id) }
                        i = j
                        continue
                    }
                }
            }
            i += 1
        }
        return found
    }
}

// MARK: - KEV

public struct KEVCatalog: Decodable, Sendable {
    public struct Entry: Decodable, Sendable {
        public let cveID: String
        public let vendorProject: String
        public let product: String
        public let vulnerabilityName: String
        public let dateAdded: String
        public let shortDescription: String
        public let requiredAction: String?
        public let dueDate: String?
        public let knownRansomwareCampaignUse: String?
        public let notes: String?
    }
    public let catalogVersion: String?
    public let dateReleased: String?
    public let count: Int?
    public let vulnerabilities: [Entry]

    public static let url = URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!
    public static let catalogPage = URL(string: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")!

    /// Entries added inside the window, as items.
    public func items(addedWithinDays days: Int, now: Date) -> [DigestItem] {
        let since = now.addingTimeInterval(-TimeInterval(days) * 86_400)
        return vulnerabilities.compactMap { entry -> DigestItem? in
            guard let added = DigestDates.parse(entry.dateAdded), added >= since else { return nil }
            let firstNote = entry.notes?.components(separatedBy: " ; ").first?.trimmingCharacters(in: .whitespaces)
            let noted = firstNote.flatMap { URL(string: $0) }
            let link = noted?.scheme == "https" ? noted : nil
            return DigestItem(
                id: entry.cveID.uppercased(),
                kind: .vulnerability,
                title: entry.vulnerabilityName,
                summary: DigestText.plain(entry.shortDescription),
                vendor: entry.vendorProject,
                product: entry.product,
                sources: [.kev],
                links: [DigestLink(source: .kev, url: link ?? Self.catalogPage)],
                published: added,
                cves: [entry.cveID.uppercased()],
                kevDateAdded: added,
                kevDueDate: DigestDates.parse(entry.dueDate),
                kevRansomware: entry.knownRansomwareCampaignUse?.lowercased() == "known",
                kevRequiredAction: entry.requiredAction.map { DigestText.plain($0, limit: 300) })
        }
    }
}

// MARK: - MSRC Security Update Guide

public struct MSRCPage: Decodable, Sendable {
    public struct Record: Decodable, Sendable {
        public let cveNumber: String
        public let cveTitle: String?
        public let releaseDate: String?
        public let releaseNumber: String?
        public let description: String?
        public let publiclyDisclosed: String?
        public let exploited: String?
        public let latestSoftwareRelease: String?
        public let tag: String?
        public let severity: String?
        public let impact: String?
        public let baseScore: String?
    }
    public let value: [Record]

    public static let host = "api.msrc.microsoft.com"

    /// The query that keeps the download to the records worth a card: exploited,
    /// publicly disclosed, critical, or rated exploitation more likely, inside the window.
    /// `$select` is refused by the service, so the records arrive whole.
    public static func url(since: Date, top: Int = 200) -> URL {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.path = "/sug/v2.0/en-US/vulnerability"
        let stamp = DigestDates.iso.string(from: since)
        components.queryItems = [
            URLQueryItem(name: "$filter", value: "(exploited eq 'Yes' or publiclyDisclosed eq 'Yes' or severity eq 'Critical' or latestSoftwareRelease eq 'Exploitation More Likely') and releaseDate ge " + stamp),
            URLQueryItem(name: "$orderby", value: "releaseDate desc"),
            URLQueryItem(name: "$top", value: String(top))
        ]
        return components.url!
    }

    public static func guidePage(_ cve: String) -> URL {
        URL(string: "https://msrc.microsoft.com/update-guide/vulnerability/" + cve)!
    }

    public var items: [DigestItem] {
        var byCVE: [String: DigestItem] = [:]
        for record in value {
            let cve = record.cveNumber.uppercased()
            guard !cve.isEmpty else { continue }
            let item = DigestItem(
                id: cve,
                kind: .vulnerability,
                title: record.cveTitle ?? cve,
                summary: DigestText.plain(record.description ?? ""),
                vendor: "Microsoft",
                product: record.tag,
                sources: [.msrc],
                links: [DigestLink(source: .msrc, url: Self.guidePage(cve))],
                published: DigestDates.parse(record.releaseDate),
                cves: [cve],
                msrcSeverity: record.severity,
                msrcImpact: record.impact,
                msrcExploited: record.exploited?.lowercased() == "yes",
                msrcPubliclyDisclosed: record.publiclyDisclosed?.lowercased() == "yes",
                msrcExploitability: record.latestSoftwareRelease,
                cvssBase: record.baseScore.flatMap(Double.init))
            // The guide lists one row per affected product; keep the first, which is the newest.
            if byCVE[cve] == nil { byCVE[cve] = item }
        }
        return Array(byCVE.values)
    }
}

// MARK: - RSS

/// A streaming RSS reader that keeps a bounded slice of each description, because one
/// CISA advisory item carries its whole report as HTML and the feed is megabytes.
public final class RSSReader: NSObject, XMLParserDelegate {
    public struct Item: Sendable, Equatable {
        public var title = ""
        public var link = ""
        public var description = ""
        public var pubDate = ""
        public var guid = ""
    }

    private var items: [Item] = []
    private var current: Item?
    private var element = ""
    private let descriptionCap: Int
    private var descriptionLength = 0

    public init(descriptionCap: Int = 4000) {
        self.descriptionCap = descriptionCap
    }

    public static func read(_ data: Data, descriptionCap: Int = 4000) -> [Item] {
        let reader = RSSReader(descriptionCap: descriptionCap)
        let parser = XMLParser(data: data)
        parser.delegate = reader
        parser.shouldResolveExternalEntities = false
        parser.parse()
        return reader.items
    }

    public func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        if elementName == "item" {
            current = Item()
            descriptionLength = 0
        }
        element = elementName
    }

    public func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard current != nil else { return }
        switch element {
        case "title":       current?.title += string
        case "link":        current?.link += string
        case "pubDate":     current?.pubDate += string
        case "guid":        current?.guid += string
        case "description":
            let remaining = descriptionCap - descriptionLength
            guard remaining > 0 else { return }
            let slice = string.count > remaining ? String(string.prefix(remaining)) : string
            current?.description += slice
            descriptionLength += slice.count
        default: break
        }
    }

    public func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        self.parser(parser, foundCharacters: String(decoding: CDATABlock, as: UTF8.self))
    }

    public func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if elementName == "item", let item = current {
            items.append(item)
            current = nil
        }
        element = ""
    }
}

public enum CISAFeeds {
    public static let alerts = URL(string: "https://www.cisa.gov/cybersecurity-advisories/alerts.xml")!
    public static let advisories = URL(string: "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml")!

    /// Feed items as digest advisories. A "CISA adds N vulnerabilities" alert is not a
    /// card of its own: its CVEs are attached to the KEV items it names by the merge.
    public static func items(_ feed: [RSSReader.Item], source: DigestSource) -> [DigestItem] {
        feed.compactMap { entry -> DigestItem? in
            let title = entry.title.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !title.isEmpty,
                  let url = URL(string: entry.link.trimmingCharacters(in: .whitespacesAndNewlines)),
                  url.scheme == "https" else { return nil }
            let guid = entry.guid.trimmingCharacters(in: .whitespacesAndNewlines)
            return DigestItem(
                id: source.rawValue + ":" + (guid.isEmpty ? url.absoluteString : guid),
                kind: .advisory,
                title: title,
                summary: DigestText.plain(entry.description),
                sources: [source],
                links: [DigestLink(source: source, url: url)],
                published: DigestDates.parse(entry.pubDate),
                cves: DigestText.cves(in: entry.description))
        }
    }
}

// MARK: - merge

public enum DigestMerge {

    /// Vulnerabilities merge by CVE. An alert that only announces KEV additions dissolves
    /// into the vulnerabilities it names, carrying its link; any other advisory stays a
    /// card of its own.
    public static func merge(kev: [DigestItem], msrc: [DigestItem], alerts: [DigestItem], advisories: [DigestItem]) -> [DigestItem] {
        var byCVE: [String: DigestItem] = [:]
        for item in kev { byCVE[item.id] = item }
        for item in msrc {
            if var existing = byCVE[item.id] {
                existing.sources.formUnion(item.sources)
                existing.links.append(contentsOf: item.links)
                existing.published = latest(existing.published, item.published)
                existing.msrcSeverity = item.msrcSeverity
                existing.msrcImpact = item.msrcImpact
                existing.msrcExploited = item.msrcExploited
                existing.msrcPubliclyDisclosed = item.msrcPubliclyDisclosed
                existing.msrcExploitability = item.msrcExploitability
                existing.cvssBase = item.cvssBase
                if existing.product == nil { existing.product = item.product }
                if existing.summary.isEmpty { existing.summary = item.summary }
                byCVE[item.id] = existing
            } else {
                byCVE[item.id] = item
            }
        }
        var standalone: [DigestItem] = []
        for alert in alerts {
            let named = alert.cves.filter { byCVE[$0] != nil }
            if isKEVAnnouncement(alert.title), !named.isEmpty {
                for cve in named {
                    byCVE[cve]?.links.append(contentsOf: alert.links)
                    byCVE[cve]?.sources.insert(.cisaAlert)
                }
            } else {
                standalone.append(alert)
            }
        }
        return Array(byCVE.values) + standalone + advisories
    }

    static func isKEVAnnouncement(_ title: String) -> Bool {
        let t = title.lowercased()
        return t.contains("known exploited vulnerabilit") && (t.contains("adds") || t.contains("add "))
    }

    static func latest(_ a: Date?, _ b: Date?) -> Date? {
        switch (a, b) {
        case let (x?, y?): return max(x, y)
        case let (x?, nil): return x
        case let (nil, y?): return y
        default: return nil
        }
    }
}
