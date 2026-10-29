import Foundation

// People as a directory (DIGEST-AND-PEOPLE-PLAN.md, step L): the whole directory loaded the
// way the device list loads the fleet, so an admin can scroll to a person as well as search.
//
//   GET /users?$select=id,displayName,userPrincipalName,mail&$top=999   User.ReadBasic.All
//
// The scope People already holds. The first page shows at once and the rest pages in behind
// it; search filters what is loaded on every keystroke, and while the directory is still
// arriving asks Graph (`searchUsers`) for anyone not loaded yet, so "nobody matches" is never
// said about a person who exists. Kept in memory only, by the shell, which is rebuilt on
// sign-out and on a switch of organization.

/// One page of the directory, and where the next one is. Nil at the end.
public struct DirectoryPage: Sendable {
    public let users: [DirectoryUser]
    public let next: URL?

    public init(users: [DirectoryUser], next: URL?) {
        self.users = users
        self.next = next
    }
}

/// A person in the list, with what search and the order need folded once, when the page
/// arrives, rather than on every keystroke.
public struct DirectoryEntry: Sendable, Identifiable, Equatable {
    public let user: DirectoryUser
    public var id: String { user.id }
    /// A B2B guest. Their sign-in address carries `#EXT#`; `userType` is not in the basic
    /// profile `User.ReadBasic.All` reads (verify), so the address is the mark.
    public let isGuest: Bool
    /// The folded name, or the address for someone without one: the list's order.
    let sortKey: String
    /// Name, sign-in address and mail, folded.
    let fields: [String]

    public init(_ user: DirectoryUser) {
        self.user = user
        let upn = user.userPrincipalName ?? ""
        isGuest = upn.range(of: "#EXT#", options: .caseInsensitive) != nil
        let name = DirectorySearch.fold(user.displayName ?? "")
        sortKey = name.isEmpty ? DirectorySearch.fold(upn) : name
        fields = [name, DirectorySearch.fold(upn), DirectorySearch.fold(user.mail ?? "")].filter { !$0.isEmpty }
    }

    /// What the row shows as the name.
    public var title: String { user.displayName ?? user.userPrincipalName ?? user.id }
    /// The sign-in address, or mail for someone without one. A guest's mail, since their
    /// sign-in address is their own address rewritten with `#EXT#`.
    public var address: String? {
        isGuest ? (user.mail ?? user.userPrincipalName) : (user.userPrincipalName ?? user.mail)
    }
}

public enum DirectorySearch {

    static func fold(_ s: String) -> String {
        s.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
    }

    public static func entries(_ users: [DirectoryUser]) -> [DirectoryEntry] {
        users.map(DirectoryEntry.init).sorted(by: inNameOrder)
    }

    /// Name order: the folded name, then the id, so equal names keep one order everywhere.
    public static func inNameOrder(_ a: DirectoryEntry, _ b: DirectoryEntry) -> Bool {
        if a.sortKey != b.sortKey { return a.sortKey < b.sortKey }
        return a.id < b.id
    }

    /// Adds people to a list already in name order: the newcomers are sorted, then both
    /// are walked once, instead of sorting everything again.
    public static func merged(_ sorted: [DirectoryEntry], adding newcomers: [DirectoryEntry]) -> [DirectoryEntry] {
        merge(sorted, newcomers.sorted(by: inNameOrder), by: inNameOrder)
    }

    /// Everyone matching every word typed, in any of the name, the sign-in address and the
    /// mail. Those with a field or a word of the name starting with what was typed come
    /// first, then the rest, each in name order. An empty query is everyone.
    public static func filter(_ entries: [DirectoryEntry], query: String) -> [DirectoryEntry] {
        let words = fold(query).split(whereSeparator: \.isWhitespace).map(String.init)
        guard !words.isEmpty else { return entries }
        var first: [DirectoryEntry] = []
        var rest: [DirectoryEntry] = []
        for entry in entries {
            guard words.allSatisfy({ word in entry.fields.contains { $0.contains(word) } }) else { continue }
            if startsWith(entry, words[0]) { first.append(entry) } else { rest.append(entry) }
        }
        return first + rest
    }

    /// Adds people to search results already in result order: only the newcomers are
    /// matched, then merged in. The same list `filter` would give for everyone together.
    public static func merged(results: [DirectoryEntry], query: String, adding newcomers: [DirectoryEntry]) -> [DirectoryEntry] {
        let words = fold(query).split(whereSeparator: \.isWhitespace).map(String.init)
        guard let lead = words.first else { return merged(results, adding: newcomers) }
        let hits = filter(newcomers.sorted(by: inNameOrder), query: query)
        guard !hits.isEmpty else { return results }
        let rank = { (entry: DirectoryEntry) in startsWith(entry, lead) ? 0 : 1 }
        return merge(results, hits) { a, b in
            let ra = rank(a), rb = rank(b)
            return ra != rb ? ra < rb : inNameOrder(a, b)
        }
    }

    /// The one person whose sign-in address or mail is exactly this, if loaded.
    public static func person(withAddress address: String, in entries: [DirectoryEntry]) -> DirectoryEntry? {
        let folded = fold(address.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !folded.isEmpty else { return nil }
        return entries.first { entry in
            fold(entry.user.userPrincipalName ?? "") == folded || fold(entry.user.mail ?? "") == folded
        }
    }

    private static func startsWith(_ entry: DirectoryEntry, _ word: String) -> Bool {
        entry.fields.contains { field in
            field.hasPrefix(word) || field.split(separator: " ").contains { $0.hasPrefix(word) }
        }
    }

    private static func merge<T>(_ a: [T], _ b: [T], by before: (T, T) -> Bool) -> [T] {
        guard !b.isEmpty else { return a }
        guard !a.isEmpty else { return b }
        var out: [T] = []
        out.reserveCapacity(a.count + b.count)
        var i = 0
        var j = 0
        while i < a.count, j < b.count {
            if before(b[j], a[i]) {
                out.append(b[j])
                j += 1
            } else {
                out.append(a[i])
                i += 1
            }
        }
        out.append(contentsOf: a[i...])
        out.append(contentsOf: b[j...])
        return out
    }
}

/// Pages the directory to the end, or to the cap, calling back after every page.
///
/// Throttling is honoured once, as the device fill does: a second 429 stops the fill, what
/// is loaded stays, and search says the list is incomplete and asks Graph instead.
public enum DirectoryFill {

    /// People before stopping. Beyond this the list says it is not everyone, and search
    /// asks Graph for anyone not loaded.
    public static let defaultMaxPeople = 50_000

    static let maxRetryWait: TimeInterval = 30
    static let defaultRetryWait: TimeInterval = 5

    public enum Outcome: Sendable, Equatable {
        case complete
        /// Stopped at the cap with pages remaining.
        case capped
        case cancelled
        /// A page failed after any retry. What loaded is kept. The first page failing is
        /// this too, with nothing loaded.
        case failed(SignInTriageError)
    }

    public static func run(
        _ provider: any SignInTriageProviding,
        maxPeople: Int = defaultMaxPeople,
        sleep: @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) },
        onPage: @Sendable (_ added: [DirectoryUser], _ total: Int) async -> Void
    ) async -> Outcome {
        var next: URL?
        var total = 0
        var throttledOnce = false
        var started = false
        while total < maxPeople {
            if Task.isCancelled { return .cancelled }
            if started && next == nil { return .complete }
            do {
                let page = try await provider.directoryPage(after: next)
                started = true
                next = page.next
                total += page.users.count
                await onPage(page.users, total)
            } catch SignInTriageError.throttled(let retryAfter) where !throttledOnce {
                throttledOnce = true
                do {
                    try await sleep(min(retryAfter ?? defaultRetryWait, maxRetryWait))
                } catch {
                    return .cancelled
                }
            } catch is CancellationError {
                return .cancelled
            } catch let error as SignInTriageError {
                return error == .cancelled ? .cancelled : .failed(error)
            } catch {
                return .failed(.transport(status: -1))
            }
        }
        return next == nil ? .complete : .capped
    }
}
