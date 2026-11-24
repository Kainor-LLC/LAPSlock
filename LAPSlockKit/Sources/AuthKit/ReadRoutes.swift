import Foundation
import CryptoKit

// Which registration an organization's reads go through, for a person who signed in before
// TenantKeep's sign-in was split into a read-only registration and separate ones for actions.
//
// Approval is per organization, so the move is too. A provider's own organization can
// approve the read registration today while a customer's administrator has not got to it,
// and that customer must keep working. The rules, in the order they apply:
//
// - **The person's own organization moves first.** Until it does, the session itself lives
//   on the original registration and every organization reads through it, exactly as
//   before the split (`SessionRestore`). Nothing here is consulted.
// - **When it moves, the customers saved on the device are recorded as waiting.** A waiting
//   customer keeps reading through the original registration, where it already was.
// - **A waiting customer is tried on the read registration first, every time it is
//   entered.** The moment that answers, the customer has moved, and it is taken off the
//   list for good.
// - **Nothing is ever added to the list afterwards.** A customer that has moved, a customer
//   added later, and anyone but the person who began the list read through the read
//   registration or not at all. So the original registration, which can write, is only ever where a customer
//   already was. It is never somewhere a failure sends reads back to: an organization that
//   disables the read app stops the app, as it means to.
//
// The list is a preference, not a credential: it can only name customers this person was
// already reading through the original registration, and it needs that registration's
// session, which is in the Keychain, to mean anything. It belongs to the person who began
// it: a sign-in by that person keeps it, anyone else's drops it, sign-out clears it, and a
// forgotten customer leaves it. (Until the second review, R2-1 on 2026-11-24, every sign-in
// cleared it, so a sign-in the session needed, under a sign-in frequency policy or after a
// revoke, sent the waiting customers through a registration they had not approved.)

/// What the screens say is waiting.
public enum ReadUpdate: Sendable, Equatable {
    /// Nothing has moved: the person's own organization has not approved the read
    /// registration, or nobody has finished the update since it did.
    case ownOrganization
    /// The person's own organization has moved. The customer being worked in has not.
    case thisCustomer
}

/// What one silent request for a token, through one registration in one organization, came to.
public enum RouteProbe: Sendable, Equatable {
    case token
    /// Entra's definite answer that the organization has not approved the registration,
    /// or, for the original registration, that this person has no session on it.
    case notApproved
    /// The registration may be approved, but the person has to answer a prompt first.
    case needsPrompt
    /// No answer worth deciding on: offline, cancelled, or something unexpected.
    case failed

    /// Entra's codes for "this organization has not approved this application": the
    /// consent codes, and the one for an application the directory has never seen.
    static let notApprovedCodes = ConsentDiagnostics.consentCodes + ["AADSTS700016"]

    /// Reads a failed silent request. `aadCode` is the `AADSTS` code from Microsoft's
    /// message, `subError` the OAuth sub-error, both as the sign-in library reported them.
    public static func failure(aadCode: String?, subError: String?, interactionRequired: Bool) -> RouteProbe {
        if let aadCode, notApprovedCodes.contains(aadCode.uppercased()) { return .notApproved }
        if let subError, subError.lowercased().contains("consent") { return .notApproved }
        return interactionRequired ? .needsPrompt : .failed
    }
}

/// The decision for a waiting customer, kept apart from the sign-in library so it can be tested.
public enum ReadRoutes {

    public enum Step: Sendable, Equatable {
        /// The read registration answered: the customer has moved.
        case read
        /// The original registration answered: the customer stays where it was.
        case original
        /// Neither answered silently. Ask the person through this registration.
        case ask(AppRegistration)
        /// The customer has approved neither. Its administrator is sent the read
        /// registration's approval link; nobody is prompted.
        case notApproved
        /// Nothing to decide on. Nothing changes.
        case fail
    }

    /// What to do once both registrations have been asked silently, the read one first.
    ///
    /// The person is asked through the original registration in two cases only: Entra said
    /// outright that the customer has not approved the read one, or they were already
    /// asked through the read one this session and no token came back. The second covers
    /// a customer whose need for a fresh sign-in hides the fact that it has not approved
    /// the read registration, which would otherwise ask the same question forever.
    public static func settle(read: RouteProbe, original: RouteProbe, askedReadBefore: Bool) -> Step {
        if read == .token { return .read }
        if original == .token { return .original }
        switch (read, original) {
        case (.notApproved, .notApproved):
            return .notApproved
        case (.notApproved, .needsPrompt):
            return .ask(.actions)
        case (.needsPrompt, .needsPrompt):
            return .ask(askedReadBefore ? .actions : .read)
        case (.needsPrompt, _):
            return .ask(.read)
        default:
            return .fail
        }
    }
}

/// Where the list of waiting customers is kept. Every sign-in manager in the process
/// reads the same one (the background check builds its own manager), and a customer is
/// only ever taken off it, so two of them cannot put one back.
public struct ReadRouteStore: @unchecked Sendable {
    private let defaults: UserDefaults?
    private static let homeKey = "readRoute.home"
    private static let waitingKey = "readRoute.waiting"
    /// Who began the list, as a digest of the sign-in library's account identifier: enough
    /// to tell the same person, without keeping their identifier beside the list.
    private static let personKey = "readRoute.person"

    public init(defaults: UserDefaults?) {
        self.defaults = defaults
    }

    public static let standard = ReadRouteStore(defaults: .standard)
    /// Keeps nothing: every organization reads through the read registration.
    public static let none = ReadRouteStore(defaults: nil)

    /// The customers still waiting, for the person whose own organization is `home`.
    /// A list recorded for anyone else's organization is not this person's.
    public func waiting(home: String) -> Set<String> {
        guard let defaults, defaults.string(forKey: Self.homeKey) == home.lowercased() else { return [] }
        return Set(defaults.stringArray(forKey: Self.waitingKey) ?? [])
    }

    public func waits(_ tenant: String, home: String) -> Bool {
        waiting(home: home).contains(tenant.lowercased())
    }

    /// The person's own organization has just moved: these customers have not. The one
    /// time anything is put on the list. `person` is the account that moved them.
    public func begin(home: String, person: String, waiting: Set<String>) {
        let home = home.lowercased()
        let customers = Set(waiting.map { $0.lowercased() }).subtracting([home])
        guard !customers.isEmpty else { return clear() }
        defaults?.set(home, forKey: Self.homeKey)
        defaults?.set(Self.digest(person), forKey: Self.personKey)
        defaults?.set(customers.sorted(), forKey: Self.waitingKey)
    }

    /// A customer has moved, or was forgotten. Read and written here rather than from a
    /// copy held by the caller, so a second manager's stale copy cannot undo it.
    public func remove(_ tenant: String, home: String) {
        var left = waiting(home: home)
        guard left.remove(tenant.lowercased()) != nil else { return }
        if left.isEmpty { return clear() }
        defaults?.set(left.sorted(), forKey: Self.waitingKey)
    }

    /// Keeps the list for the person who began it, at a restore and at a sign-in, and drops
    /// it for anyone else. A list from before the person was recorded with it (build 14) is
    /// taken as theirs: until then any sign-in cleared it, so only the session it was begun
    /// in can be holding it.
    public func keep(onlyFor home: String, person: String) {
        guard let defaults, let stored = defaults.string(forKey: Self.homeKey) else { return }
        guard stored == home.lowercased() else { return clear() }
        let who = Self.digest(person)
        guard let began = defaults.string(forKey: Self.personKey) else {
            return defaults.set(who, forKey: Self.personKey)
        }
        if began != who { clear() }
    }

    public func clear() {
        defaults?.removeObject(forKey: Self.homeKey)
        defaults?.removeObject(forKey: Self.waitingKey)
        defaults?.removeObject(forKey: Self.personKey)
    }

    static func digest(_ person: String) -> String {
        SHA256.hash(data: Data(person.lowercased().utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
