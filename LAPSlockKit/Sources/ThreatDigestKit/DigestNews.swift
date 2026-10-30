import Foundation

// Security news in the digest: SANS Internet Storm Center's diaries and BleepingComputer.
//
// Their words are theirs, as with every other source, but unlike CISA's (public domain)
// and Microsoft's (published for exactly this) they belong to publishers who decide where
// they appear. SANS publishes under CC BY-NC-SA 4.0, and BleepingComputer's terms require
// written permission to redistribute. So a source is read only where its publisher has
// agreed (DIGEST-AND-PEOPLE-PLAN.md, step K), and its full text only where that was agreed
// too. Both agreed in writing to full text, with no conditions, on 2026-10-29; the replies
// are kept with Kainor's records. A source still waiting for an answer can be listed for
// Debug builds only, so it can be built and checked first.

/// Which news sources this build may read, and which may show their full text.
public enum DigestNewsPolicy {

    /// Sources a publisher has agreed to in writing, for every build.
    public static let agreed: Set<DigestSource> = [.sansISC, .bleepingComputer]
    /// Sources whose publisher agreed to full text, not just the headline and summary.
    public static let agreedFullText: Set<DigestSource> = [.sansISC, .bleepingComputer]

    public static var enabled: Set<DigestSource> { agreed }

    public static var fullText: Set<DigestSource> { agreedFullText }
}

public enum NewsFeeds {
    /// The full-text diary feed.
    public static let sansISC = URL(string: "https://isc.sans.edu/rssfeed_full.xml")!
    /// Headlines and a short summary; the articles themselves stay on the site. Full text was
    /// agreed too, but the feed does not carry it, and the summary with a link to the article
    /// is the choice (Connor, 2026-10-29): no article page is ever fetched.
    public static let bleepingComputer = URL(string: "https://www.bleepingcomputer.com/feed/")!

    public static func url(_ source: DigestSource) -> URL? {
        switch source {
        case .sansISC:          return sansISC
        case .bleepingComputer: return bleepingComputer
        default:                return nil
        }
    }

    /// A diary is a few thousand words at most; this bounds a feed that changed shape.
    public static let textCap = 60_000

    /// Feed items as news. The article's text is kept only where the publisher allowed full
    /// text; otherwise the item carries the feed's own summary and the link.
    public static func items(_ feed: [RSSReader.Item], source: DigestSource, fullText: Bool) -> [DigestItem] {
        feed.compactMap { entry -> DigestItem? in
            let title = cleanTitle(entry.title, source: source)
            guard !title.isEmpty,
                  let url = URL(string: entry.link.trimmingCharacters(in: .whitespacesAndNewlines)),
                  url.scheme == "https" else { return nil }
            let guid = entry.guid.trimmingCharacters(in: .whitespacesAndNewlines)
            let body = entry.content.isEmpty ? entry.description : entry.content
            let author = DigestText.plain(entry.author, limit: 80)
            let article = fullText ? DigestText.paragraphs(body) : nil
            return DigestItem(
                id: source.rawValue + ":" + (guid.isEmpty ? url.absoluteString : guid),
                kind: .news,
                title: title,
                summary: DigestText.plain(entry.description),
                sources: [source],
                links: [DigestLink(source: source, url: url)],
                published: DigestDates.parse(entry.pubDate),
                cves: DigestText.cves(in: title + " " + body),
                author: author.isEmpty ? nil : author,
                articleText: article?.isEmpty == true ? nil : article)
        }
    }

    /// SANS ends every diary title with its date, "PHP Vulnerability Wrap-Up, (Fri, Oct 23rd)";
    /// the card shows the date itself, so the suffix goes.
    static func cleanTitle(_ raw: String, source: DigestSource) -> String {
        let title = DigestText.plain(raw, limit: 300)
        guard source == .sansISC,
              let range = title.range(of: #",?\s*\((Mon|Tue|Wed|Thu|Fri|Sat|Sun), [A-Za-z]{3} \d{1,2}(st|nd|rd|th)\)\s*$"#, options: .regularExpression)
        else { return title }
        return String(title[..<range.lowerBound]).trimmingCharacters(in: .whitespaces)
    }
}
