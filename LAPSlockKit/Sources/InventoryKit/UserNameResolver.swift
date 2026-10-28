import Foundation
import AuthKit

// Primary-user display names, looked up in Entra when Intune leaves the field empty.
//
// Why this is opt-in: Intune's `userDisplayName` is often blank depending on how the primary
// user was assigned, so rows show the UPN. Filling the gap means reading user objects from
// the directory, which is a NEW permission on every customer's consent screen, 
// `User.ReadBasic.All`, a password app asking to read the user list. A security reviewer
// will ask why. So it sits behind a Settings toggle, off by default, exactly like BitLocker
// rotation and role activation: a customer who never turns it on never sees the permission
// requested, and the footer beside the toggle says what it adds. The UPN is the default;
// names are optional for those who want them.
//
// What it costs and what it keeps: lookups are by UPN, which the device record already
// carries, so the inventory query is untouched, the `$select` there is fragile and one bad
// field 400s the whole list. Fifteen UPNs per request, the most Graph's `in` operator takes.
// Results live in memory for the session and are never written anywhere: the app already
// promises to record nothing about a tenant's users, and a name cache on disk would be a
// small betrayal of that.

public protocol UserNameResolving: Sendable {
    /// Display names keyed by LOWERCASED user principal name. Absent means not found.
    func displayNames(forUserPrincipalNames upns: [String]) async throws -> [String: String]
}

public actor UserNameResolver: UserNameResolving {

    /// Read basic profile of every user: display name, UPN, mail and the like. No groups,
    /// no licences, no directory writes. The least that resolves a name.
    public static let scope = "User.ReadBasic.All"

    /// Graph's `in` operator accepts at most this many values.
    public static let batchSize = 15

    /// Lookups sent at once. One at a time was 167 requests in a row for 2,500 people.
    static let parallelBatches = 4

    private let auth: any AuthManaging
    private let session: URLSession
    private let base: String

    /// Lowercased UPN → display name, or nil for "looked up, nothing there". Caching the
    /// misses matters as much as the hits: a device whose user has no display name would
    /// otherwise be looked up again on every page the fill delivers.
    private var cache: [String: String?] = [:]

    /// Lookups on their way, by lowercased UPN. Two callers asking for the same people at
    /// once share one lookup instead of both sending it, and a caller that gives up and
    /// asks again picks up the lookup it started rather than throwing it away.
    private var inFlight: [String: Task<[String: String], Error>] = [:]

    public init(auth: any AuthManaging, base: String = "https://graph.microsoft.com", session: URLSession? = nil) {
        self.auth = auth
        self.base = base
        self.session = session ?? InventoryHTTP.makeSession()
    }

    public func displayNames(forUserPrincipalNames upns: [String]) async throws -> [String: String] {
        let wanted = Set(upns.map { $0.lowercased() }).filter { !$0.isEmpty }
        let missing = wanted.filter { cache[$0] == nil && inFlight[$0] == nil }.sorted()

        // Never interactive. Consent for the scope is requested by the Settings toggle, at
        // the moment of the decision; a list that pops a permission prompt while scrolling
        // would be asking at the worst possible time.
        if !missing.isEmpty {
            let rounds = Self.rounds(Self.batches(missing))
            let auth = auth
            let session = session
            let base = base
            // Registered before anything here waits, the token included, so a caller
            // arriving meanwhile finds it rather than starting the same lookup. Not a child
            // of the caller: it finishes even if the caller is cancelled, so the work is
            // there for whoever asks next.
            let work = Task { () async throws -> [String: String] in
                let token = try await auth.token(scopes: [Self.scope], allowInteractive: false)
                var found: [String: String] = [:]
                for round in rounds {
                    try await withThrowingTaskGroup(of: [String: String].self) { group in
                        for batch in round {
                            group.addTask { try await Self.fetch(batch, token: token, session: session, base: base) }
                        }
                        for try await part in group { found.merge(part) { first, _ in first } }
                    }
                }
                return found
            }
            for upn in missing { inFlight[upn] = work }
        }

        // Every lookup that covers what was asked, this caller's and any already running.
        var lookups: [Task<[String: String], Error>] = []
        for upn in wanted {
            if let task = inFlight[upn], !lookups.contains(task) { lookups.append(task) }
        }
        for task in lookups {
            let found: [String: String]
            do {
                found = try await task.value
            } catch {
                // A failed lookup leaves nothing cached, so the next caller tries again.
                for (upn, running) in inFlight where running == task { inFlight[upn] = nil }
                throw error
            }
            for (upn, running) in inFlight where running == task {
                cache[upn] = .some(found[upn])
                inFlight[upn] = nil
            }
        }

        var result: [String: String] = [:]
        for upn in wanted {
            if let name = cache[upn] ?? nil { result[upn] = name }
        }
        return result
    }

    private static func fetch(_ upns: [String], token: String, session: URLSession, base: String) async throws -> [String: String] {
        var comps = URLComponents(string: base)!
        comps.path = "/v1.0/users"
        comps.queryItems = [
            URLQueryItem(name: "$filter", value: Self.filterClause(for: upns)),
            URLQueryItem(name: "$select", value: "userPrincipalName,displayName"),
        ]
        var req = URLRequest(url: comps.url!)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await session.data(for: req)
        try InventoryHTTP.validate(response)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw InventoryError.decodeFailure
        }
        return Self.parse(json)
    }

    // MARK: - pure pieces

    /// `userPrincipalName in ('a@x.com','b@x.com')`, with OData's quote escaping.
    ///
    /// An apostrophe in a UPN, o'brien@, is legal and, unescaped, ends the string literal
    /// early and turns the whole filter into a 400. Doubled, per OData, it is a literal quote.
    static func filterClause(for upns: [String]) -> String {
        let quoted = upns.map { "'" + $0.replacingOccurrences(of: "'", with: "''") + "'" }
        return "userPrincipalName in (" + quoted.joined(separator: ",") + ")"
    }

    static func batches(_ upns: [String]) -> [[String]] {
        stride(from: 0, to: upns.count, by: batchSize).map {
            Array(upns[$0 ..< min($0 + batchSize, upns.count)])
        }
    }

    /// Batches grouped into rounds sent together, `parallelBatches` at a time.
    static func rounds(_ batches: [[String]]) -> [[[String]]] {
        stride(from: 0, to: batches.count, by: parallelBatches).map {
            Array(batches[$0 ..< min($0 + parallelBatches, batches.count)])
        }
    }

    /// Lowercased UPN → display name, skipping entries without either.
    static func parse(_ json: [String: Any]) -> [String: String] {
        var out: [String: String] = [:]
        for item in json["value"] as? [[String: Any]] ?? [] {
            guard let upn = (item["userPrincipalName"] as? String)?.lowercased(), !upn.isEmpty,
                  let name = (item["displayName"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !name.isEmpty
            else { continue }
            out[upn] = name
        }
        return out
    }

    // MARK: - applying names to devices

    /// UPNs of devices that have a primary user but no display name, deduplicated and
    /// lowercased. Everything else already has what it needs or has nobody to look up.
    public static func upnsNeedingNames(in devices: [ManagedDeviceSummary]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for device in devices where device.userDisplayName == nil {
            guard let upn = device.userPrincipalName?.lowercased(), !upn.isEmpty, !seen.contains(upn) else { continue }
            seen.insert(upn)
            out.append(upn)
        }
        return out
    }

    /// Fills in display names where Intune left them empty and a lookup found one.
    /// Devices that already had a name are untouched: Intune's own value wins.
    public static func enrich(_ devices: [ManagedDeviceSummary], names: [String: String]) -> [ManagedDeviceSummary] {
        guard !names.isEmpty else { return devices }
        return devices.map { device in
            guard device.userDisplayName == nil,
                  let upn = device.userPrincipalName?.lowercased(),
                  let name = names[upn]
            else { return device }
            return device.withUserDisplayName(name)
        }
    }
}
