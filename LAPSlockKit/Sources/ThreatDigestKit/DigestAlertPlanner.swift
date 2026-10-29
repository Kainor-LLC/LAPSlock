import Foundation

/// What the background run announces from the digest: a new exploited vulnerability, or a
/// new CISA alert or advisory, in the categories the admin chose (DIGEST-AND-PEOPLE-PLAN.md,
/// step K). News never alerts: there are dozens of stories a day.
///
/// Every eligible item the run sees is remembered, whatever its category, so choosing
/// another category later does not announce the backlog. The first run only remembers.
public enum DigestAlertPlanner {

    /// How many ids are kept, newest last. Far more than the feeds' windows hold.
    public static let rememberedLimit = 3000

    public static func isEligible(_ item: DigestItem) -> Bool {
        switch item.kind {
        case .vulnerability: return item.sources.contains(.kev) || item.msrcExploited
        case .advisory:      return true
        case .news:          return false
        }
    }

    /// - seen: the ids remembered by earlier runs, oldest first; nil on the first run.
    /// - Returns: what to announce, newest first, and the ids to remember.
    public static func plan(items: [DigestItem], seen: [String]?, categories: Set<DigestCategory>) -> (announce: [DigestItem], remember: [String]) {
        let eligible = items.filter(isEligible)
        guard let seen else {
            return ([], Array(eligible.map(\.id).sorted().suffix(rememberedLimit)))
        }
        let known = Set(seen)
        let fresh = eligible.filter { !known.contains($0.id) }
        let announce = fresh
            .filter { !$0.categories.isDisjoint(with: categories) }
            .sorted { ($0.published ?? .distantPast) > ($1.published ?? .distantPast) }
        let remember = Array((seen + fresh.map(\.id).sorted()).suffix(rememberedLimit))
        return (announce, remember)
    }

    /// The notification's title and body. Public data only: the item's own title. Nil when
    /// there is nothing to say.
    public static func copy(for items: [DigestItem]) -> (title: String, body: String)? {
        guard let first = items.first else { return nil }
        let title = "Threat Digest"
        if items.count == 1 {
            return (title, lead(for: first) + ": " + first.title)
        }
        return (title, "\(items.count) new in your categories: " + first.title + ", and \(items.count - 1) more.")
    }

    static func lead(for item: DigestItem) -> String {
        switch item.kind {
        case .vulnerability: return "New exploited vulnerability"
        case .advisory:      return item.sources.contains(.cisaAdvisory) ? "New CISA advisory" : "New CISA alert"
        case .news:          return "New story"
        }
    }
}
