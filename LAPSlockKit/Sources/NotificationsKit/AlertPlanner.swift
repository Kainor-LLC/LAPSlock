import Foundation

// What to post from one run, given what was seen before. Pure, so every rule has a test.
//
// The rules, in order:
// 1. The first time a kind is checked in a tenant, everything it finds is the baseline:
//    remembered, not announced. Turning a switch on must not dump a year of history onto
//    the lock screen.
// 2. After that, a key not seen before is new. New keys of one kind in one tenant become
//    ONE notification with a count, never one each.
// 3. Remembered keys are capped per kind, oldest dropped, so the store cannot grow forever.

public protocol LastSeenStoring: Sendable {
    /// Nil means never checked: the baseline rule applies.
    func keys(tenantId: String, kind: AlertKind) -> Set<String>?
    func setKeys(_ keys: Set<String>, tenantId: String, kind: AlertKind)
    func clear(tenantId: String)
}

public struct AlertPlanner: Sendable {

    public static let rememberedCap = 500

    public init() {}

    public struct Result: Sendable, Equatable {
        public let alerts: [PlannedAlert]
        /// What to store for each kind after this run.
        public let remembered: [AlertKind: Set<String>]
    }

    public func plan(
        tenantId: String,
        label: String,
        observations: [AlertObservation],
        lastSeen: (AlertKind) -> Set<String>?
    ) -> Result {
        var alerts: [PlannedAlert] = []
        var remembered: [AlertKind: Set<String>] = [:]
        for observation in observations.sorted(by: { $0.kind < $1.kind }) {
            let previous = lastSeen(observation.kind)
            let fresh = previous.map { observation.keys.subtracting($0) } ?? []
            if !fresh.isEmpty {
                alerts.append(AlertCopy.alert(tenantId: tenantId, label: label, kind: observation.kind, count: fresh.count))
            }
            let merged = (previous ?? []).union(observation.keys)
            remembered[observation.kind] = Self.capped(merged, keeping: observation.keys)
        }
        return Result(alerts: alerts, remembered: remembered)
    }

    /// Keeps everything currently observed, then fills to the cap with older keys in a
    /// stable order, so a key that just left the source is the first to go.
    static func capped(_ keys: Set<String>, keeping current: Set<String>) -> Set<String> {
        guard keys.count > rememberedCap else { return keys }
        var kept = current
        for key in keys.subtracting(current).sorted() where kept.count < rememberedCap {
            kept.insert(key)
        }
        return kept
    }
}

/// Last-seen keys in UserDefaults. Keys are opaque identifiers (an incident id, a hash of a
/// sign-in id): nothing a reader of the preferences file could act on.
public final class UserDefaultsLastSeenStore: LastSeenStoring, @unchecked Sendable {

    private let defaults: UserDefaults
    private let prefix: String

    public init(defaults: UserDefaults = .standard, prefix: String = "notifications.lastSeen.") {
        self.defaults = defaults
        self.prefix = prefix
    }

    private func key(_ tenantId: String, _ kind: AlertKind) -> String {
        prefix + tenantId.lowercased() + "." + kind.rawValue
    }

    public func keys(tenantId: String, kind: AlertKind) -> Set<String>? {
        (defaults.array(forKey: key(tenantId, kind)) as? [String]).map(Set.init)
    }

    public func setKeys(_ keys: Set<String>, tenantId: String, kind: AlertKind) {
        defaults.set(keys.sorted(), forKey: key(tenantId, kind))
    }

    public func clear(tenantId: String) {
        for kind in AlertKind.allCases {
            defaults.removeObject(forKey: key(tenantId, kind))
        }
    }
}

/// Turns a sign-in id into a key that is stable but says nothing. A break-glass sign-in id
/// is a Graph identifier, not a secret, but the rule for this store is that nothing in it
/// points at a person.
public enum OpaqueKey {
    public static func make(_ parts: String...) -> String {
        // FNV-1a, 64 bit: stable across launches and platforms, no crypto needed.
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in parts.joined(separator: "|").utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x100000001b3
        }
        return String(hash, radix: 16)
    }
}
