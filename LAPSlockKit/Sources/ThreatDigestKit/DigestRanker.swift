import Foundation

// The ranking rules, as data, with one test per rule. The digest is these rules and
// nothing else: no model, no server, no prose.

public struct DigestRanking: Sendable, Equatable {
    public let signals: [DigestSignal]
    public let score: Int
    public init(signals: [DigestSignal], score: Int) {
        self.signals = signals
        self.score = score
    }
}

public struct DigestRanker: Sendable {

    /// What each signal is worth. Exploitation in the wild outranks everything else on
    /// its own, because it is the one fact that turns "patch soon" into "patch today";
    /// the first live run had a critical-but-unexploited browser CVE tie with exploited
    /// Windows ones, and that is the wrong order for an on-call admin. CISA due dates
    /// under BOD 26-04 are days after listing, so "overdue" is the usual state of a KEV
    /// entry, not a sign of neglect, and weighs less than it reads. A joint advisory is a
    /// card while it is new and drops to the rest after a week.
    public static let weights: [DigestSignal: Int] = [
        .exploited: 6,
        .ransomware: 4,
        .overdue: 2,
        .dueSoon: 2,
        .moreLikely: 2,
        .publiclyDisclosed: 1,
        .critical: 2,
        .microsoft: 3,
        .advisory: 5,
        .new: 2
    ]

    /// Days inside which a KEV due date counts as soon.
    public static let dueSoonDays = 14
    /// Days inside which an item counts as new.
    public static let newDays = 7
    /// Minimum score for a card above the fold.
    public static let cardThreshold = 7
    /// At most this many cards above the fold, whatever the scores.
    public static let maxCards = 8

    public let now: Date

    public init(now: Date = Date()) {
        self.now = now
    }

    public func rank(_ item: DigestItem) -> DigestRanking {
        var signals: [DigestSignal] = []
        if item.sources.contains(.kev) || item.msrcExploited { signals.append(.exploited) }
        if item.kevRansomware { signals.append(.ransomware) }
        if let due = item.kevDueDate {
            let days = Calendar.current.dateComponents([.day], from: now, to: due).day ?? 0
            if due < now, now.timeIntervalSince(due) <= 30 * 86_400 {
                signals.append(.overdue)
            } else if due >= now, days <= Self.dueSoonDays {
                signals.append(.dueSoon)
            }
        }
        if item.msrcExploitability?.localizedCaseInsensitiveContains("more likely") == true {
            signals.append(.moreLikely)
        }
        if item.msrcPubliclyDisclosed { signals.append(.publiclyDisclosed) }
        if item.msrcSeverity?.localizedCaseInsensitiveCompare("critical") == .orderedSame
            || (item.cvssBase ?? 0) >= 9.0 {
            signals.append(.critical)
        }
        if item.isMicrosoft { signals.append(.microsoft) }
        if item.kind == .advisory, item.sources.contains(.cisaAdvisory) { signals.append(.advisory) }
        if let published = item.published, now.timeIntervalSince(published) <= TimeInterval(Self.newDays) * 86_400 {
            signals.append(.new)
        }
        let score = signals.reduce(0) { $0 + (Self.weights[$1] ?? 0) }
        return DigestRanking(signals: signals.sorted(), score: score)
    }

    /// Items with their ranking, best first; ties go to the newest.
    public func ranked(_ items: [DigestItem]) -> [(item: DigestItem, ranking: DigestRanking)] {
        items.map { ($0, rank($0)) }.sorted { a, b in
            if a.1.score != b.1.score { return a.1.score > b.1.score }
            switch (a.0.published, b.0.published) {
            case let (x?, y?) where x != y: return x > y
            case (nil, _?):                 return false
            case (_?, nil):                 return true
            default:                        return a.0.title < b.0.title
            }
        }
    }

    /// Splits a ranked list into the cards above the fold and the rest.
    public func split(_ ranked: [(item: DigestItem, ranking: DigestRanking)]) -> (cards: [(item: DigestItem, ranking: DigestRanking)], rest: [(item: DigestItem, ranking: DigestRanking)]) {
        var cards: [(item: DigestItem, ranking: DigestRanking)] = []
        var rest: [(item: DigestItem, ranking: DigestRanking)] = []
        for entry in ranked {
            if cards.count < Self.maxCards, entry.ranking.score >= Self.cardThreshold {
                cards.append(entry)
            } else {
                rest.append(entry)
            }
        }
        return (cards, rest)
    }
}
