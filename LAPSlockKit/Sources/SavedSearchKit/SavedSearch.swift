import Foundation

// Saved searches, phase 5 step C. A name, the screen it belongs to, the text typed and that
// screen's filters, so an admin's usual searches are one tap away in every customer.
//
// Not bound to a tenant on purpose: an MSP's playbook ("open high-severity incidents",
// "failed sign-ins today for this person") is the same in every customer they work in.
//
// What a search holds can include a person's sign-in address or a sender's address, so it
// is kept like the rest of the account's working data: on this device only, in one file
// with complete file protection, excluded from backup, never synced and never sent, and
// removed on sign-out. It is not a Keychain item; the Keychain's six-item rule stands.
//
// Foundation only. Nothing here can reach a token, a credential or Graph.

public struct SavedSearch: Codable, Sendable, Equatable, Identifiable {
    /// The screen a search belongs to and is recalled on.
    public enum Scope: String, Codable, Sendable, CaseIterable {
        case devices
        case people
        case incidents
        case email
        case conditionalAccess
    }

    public let id: UUID
    public var name: String
    public let scope: Scope
    /// The text in the search field, or the email query's one value.
    public var query: String
    /// The scope's own filters by name, for example `openOnly`, `severity`, `failuresOnly`,
    /// `hunt`, `window` or `sort`. Each screen reads the names it knows and ignores the rest,
    /// so an older search never breaks a newer screen.
    public var options: [String: String]
    public var savedAt: Date

    public init(id: UUID = UUID(), name: String, scope: Scope, query: String,
                options: [String: String] = [:], savedAt: Date = Date()) {
        self.id = id
        self.name = name
        self.scope = scope
        self.query = query
        self.options = options
        self.savedAt = savedAt
    }
}

/// The list's rules, kept out of the stores so they are testable without a file.
public enum SavedSearchList {
    /// Enough for a working set, small enough to scan in a menu.
    public static let limit = 50
    public static let nameLimit = 60

    public enum Problem: Error, Equatable {
        case emptyName
        case full
    }

    /// Adds a search. A name already used on the same screen replaces that search rather
    /// than making a second row with the same name, which a menu could not tell apart.
    public static func adding(_ search: SavedSearch, to list: [SavedSearch]) throws(Problem) -> [SavedSearch] {
        var search = search
        search.name = String(search.name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(nameLimit))
        guard !search.name.isEmpty else { throw .emptyName }
        var rest = list.filter { !($0.scope == search.scope && $0.name.caseInsensitiveCompare(search.name) == .orderedSame) }
        guard rest.count < limit else { throw .full }
        rest.append(search)
        return rest
    }

    public static func removing(_ id: UUID, from list: [SavedSearch]) -> [SavedSearch] {
        list.filter { $0.id != id }
    }

    /// One screen's searches, alphabetical: a menu is scanned by name, not by age.
    public static func searches(in scope: SavedSearch.Scope, from list: [SavedSearch]) -> [SavedSearch] {
        list.filter { $0.scope == scope }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
}

public protocol SavedSearchStoring: Sendable {
    func load() throws -> [SavedSearch]
    func save(_ searches: [SavedSearch]) throws
    func clear() throws
}

/// The live store: one JSON file in Application Support, written with complete file
/// protection and excluded from backup.
public struct FileSavedSearchStore: SavedSearchStoring {
    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    /// `Application Support/saved-searches.json` in the app's own container.
    public static func standard() -> FileSavedSearchStore {
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                 appropriateFor: nil, create: true))
            ?? FileManager.default.temporaryDirectory
        return FileSavedSearchStore(url: base.appendingPathComponent("saved-searches.json"))
    }

    public func load() throws -> [SavedSearch] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([SavedSearch].self, from: data)
    }

    public func save(_ searches: [SavedSearch]) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(searches)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        #if os(iOS) || os(watchOS) || os(visionOS)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: url, options: [.atomic])
        #endif
        var file = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try file.setResourceValues(values)
    }

    public func clear() throws {
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }
}

/// Demo mode and tests: in memory, gone with the process.
public final class MemorySavedSearchStore: SavedSearchStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var searches: [SavedSearch]

    public init(_ searches: [SavedSearch] = []) {
        self.searches = searches
    }

    public func load() throws -> [SavedSearch] {
        lock.lock(); defer { lock.unlock() }
        return searches
    }

    public func save(_ searches: [SavedSearch]) throws {
        lock.lock(); defer { lock.unlock() }
        self.searches = searches
    }

    public func clear() throws {
        lock.lock(); defer { lock.unlock() }
        searches = []
    }
}

extension SavedSearch {
    /// Demo mode's examples, one per kind of screen that has filters worth keeping.
    public static let demoExamples: [SavedSearch] = [
        SavedSearch(name: "Sales laptops", scope: .devices, query: "LT-SALES"),
        SavedSearch(name: "Jane, failures today", scope: .people, query: "jane",
                    options: ["failuresOnly": "true", "last24Hours": "true"]),
        SavedSearch(name: "Open high severity", scope: .incidents, query: "",
                    options: ["openOnly": "true", "severity": "highOnly"]),
    ]
}
