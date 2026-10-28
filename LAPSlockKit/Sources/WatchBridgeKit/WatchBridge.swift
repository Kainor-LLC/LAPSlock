import Foundation

// The Apple Watch companion's whole vocabulary, phase 4 step B, spec 3.13.
//
// The watch is a remote for the phone. MSAL does not run on watchOS, so the watch never
// holds a token; it shows what the phone sends it and asks the phone to act. Everything
// that crosses between them is one of the types below, encoded as JSON inside a
// WatchConnectivity message.
//
// No credential of any kind ever crosses: there is no privacy cover, no capture detection
// and no app switcher story on a wrist, and a password on a watch at a bench is a camera's
// best angle. That is enforced by shape, not by care: none of these types has a field
// that could carry a password, a recovery key, a pass or a token, and a test walks the
// encoded JSON to keep it that way.
//
// Foundation only, so it builds for watchOS, iOS and macOS alike.

public enum WatchBridge {
    /// Bumped when a type changes shape. The watch shows "update the phone app" on a
    /// mismatch rather than guessing.
    public static let version = 1
    /// The WatchConnectivity dictionary key the JSON travels under.
    public static let payloadKey = "p"
    /// Application context is capped at about 64 KB; the glance stays well under.
    public static let glanceByteLimit = 48_000

    public static func encode<T: Encodable>(_ value: T) throws -> [String: Any] {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return [payloadKey: try encoder.encode(value)]
    }

    public static func decode<T: Decodable>(_ type: T.Type, from message: [String: Any]) -> T? {
        guard let data = message[payloadKey] as? Data else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(type, from: data)
    }
}

/// What the wrist shows, sent by the phone whenever it learns something new. Counts and
/// names, never content a lock screen should not show beyond what the phone already does.
public struct WatchGlance: Codable, Sendable, Equatable {
    public struct Health: Codable, Sendable, Equatable {
        public var degradedServices: Int?
        public var openIncidents: Int?
        public var expiringSoon: Int?
        public var secureScorePercent: Int?
        public init(degradedServices: Int? = nil, openIncidents: Int? = nil, expiringSoon: Int? = nil, secureScorePercent: Int? = nil) {
            self.degradedServices = degradedServices
            self.openIncidents = openIncidents
            self.expiringSoon = expiringSoon
            self.secureScorePercent = secureScorePercent
        }
    }

    public struct ActiveRole: Codable, Sendable, Equatable, Identifiable {
        public var id: String { name }
        public var name: String
        public var endsAt: Date?
        public init(name: String, endsAt: Date?) {
            self.name = name
            self.endsAt = endsAt
        }
    }

    public struct Eligible: Codable, Sendable, Equatable, Identifiable {
        public var id: String
        public var name: String
        public var isGroup: Bool
        public init(id: String, name: String, isGroup: Bool) {
            self.id = id
            self.name = name
            self.isGroup = isGroup
        }
    }

    public struct Approval: Codable, Sendable, Equatable, Identifiable {
        public var id: String
        public var requester: String
        public var target: String
        public var duration: String?
        public var reason: String?
        public var askedAt: Date?
        public init(id: String, requester: String, target: String, duration: String?, reason: String?, askedAt: Date?) {
            self.id = id
            self.requester = requester
            self.target = target
            self.duration = duration
            self.reason = reason
            self.askedAt = askedAt
        }
    }

    public var v: Int
    public var updatedAt: Date
    public var tenant: String
    public var isDemo: Bool
    public var health: Health
    public var activeRoles: [ActiveRole]
    public var eligible: [Eligible]
    public var approvals: [Approval]
    /// Set when the phone could not read something, in words for the wrist.
    public var problem: String?

    public init(updatedAt: Date, tenant: String, isDemo: Bool, health: Health = Health(), activeRoles: [ActiveRole] = [],
                eligible: [Eligible] = [], approvals: [Approval] = [], problem: String? = nil) {
        self.v = WatchBridge.version
        self.updatedAt = updatedAt
        self.tenant = tenant
        self.isDemo = isDemo
        self.health = health
        self.activeRoles = activeRoles
        self.eligible = eligible
        self.approvals = approvals
        self.problem = problem
    }

    /// Keeps the glance under the transport's limit by trimming the longest lists first.
    public func fitted() -> WatchGlance {
        var copy = self
        copy.approvals = Array(copy.approvals.prefix(20))
        copy.eligible = Array(copy.eligible.prefix(30))
        copy.activeRoles = Array(copy.activeRoles.prefix(20))
        for i in copy.approvals.indices {
            if let reason = copy.approvals[i].reason, reason.count > 300 { copy.approvals[i].reason = String(reason.prefix(300)) + "…" }
        }
        return copy
    }
}

/// What the watch asks of the phone. The phone does every Graph call.
public enum WatchRequest: Codable, Sendable, Equatable {
    case refresh
    case decide(approvalId: String, approve: Bool, reason: String)
    case activate(eligibleId: String, reason: String, hours: Int)

    public static let minimumReason = 3
    public static let hours = 1...8

    /// Nil when the request is fine; otherwise what to fix, in words for the wrist.
    public var problem: String? {
        switch self {
        case .refresh:
            return nil
        case .decide(_, _, let reason):
            return reason.trimmingCharacters(in: .whitespacesAndNewlines).count < Self.minimumReason ? "Say a reason of a few words." : nil
        case .activate(_, let reason, let hours):
            if reason.trimmingCharacters(in: .whitespacesAndNewlines).count < Self.minimumReason { return "Say why you need it." }
            if !Self.hours.contains(hours) { return "Between 1 and 8 hours." }
            return nil
        }
    }
}

/// The phone's answer to a request.
public struct WatchReply: Codable, Sendable, Equatable {
    public enum Outcome: String, Codable, Sendable {
        /// Done, or accepted by Microsoft.
        case done
        /// Needs the phone: a fresh sign-in step, or a decision Microsoft wants made in
        /// the portal. The phone has posted a notification saying so.
        case finishOnPhone
        case failed
    }

    public var outcome: Outcome
    public var message: String
    public var glance: WatchGlance?

    public init(outcome: Outcome, message: String, glance: WatchGlance? = nil) {
        self.outcome = outcome
        self.message = message
        self.glance = glance
    }
}

// MARK: - complications

/// What a watch face complication shows: counts and one time, never a name. Written by the
/// watch app when a glance arrives, read by the complication extension, in the App Group
/// they share on the watch. Nothing here leaves the watch.
public struct ComplicationSnapshot: Codable, Sendable, Equatable {
    public var updatedAt: Date
    public var approvalsWaiting: Int
    public var degradedServices: Int?
    public var openIncidents: Int?
    /// When the soonest-ending active role ends, if any role is time-bound.
    public var nextRoleEnds: Date?
    public var isDemo: Bool

    public static let appGroup = "group.com.kainor.lapslock.watch"
    static let storageKey = "complication.snapshot"

    public init(updatedAt: Date, approvalsWaiting: Int, degradedServices: Int?, openIncidents: Int?, nextRoleEnds: Date?, isDemo: Bool) {
        self.updatedAt = updatedAt
        self.approvalsWaiting = approvalsWaiting
        self.degradedServices = degradedServices
        self.openIncidents = openIncidents
        self.nextRoleEnds = nextRoleEnds
        self.isDemo = isDemo
    }

    public init(_ glance: WatchGlance) {
        self.init(updatedAt: glance.updatedAt,
                  approvalsWaiting: glance.approvals.count,
                  degradedServices: glance.health.degradedServices,
                  openIncidents: glance.health.openIncidents,
                  nextRoleEnds: glance.activeRoles.compactMap(\.endsAt).filter { $0 > glance.updatedAt }.min(),
                  isDemo: glance.isDemo)
    }

    /// Something that needs the admin: an approval, a degraded service, an open incident.
    public var needsAttention: Bool {
        approvalsWaiting > 0 || (degradedServices ?? 0) > 0 || (openIncidents ?? 0) > 0
    }

    /// The same counts and the same next role end, whenever each was taken. A watch face
    /// is only worth waking for a change in what it shows.
    public func shows(sameAs other: ComplicationSnapshot?) -> Bool {
        guard let other else { return false }
        return approvalsWaiting == other.approvalsWaiting && degradedServices == other.degradedServices
            && openIncidents == other.openIncidents && nextRoleEnds == other.nextRoleEnds && isDemo == other.isDemo
    }

    /// For the phone to send over WatchConnectivity's complication channel.
    public var userInfo: [String: Any] {
        (try? WatchBridge.encode(self)) ?? [:]
    }

    public init?(userInfo: [String: Any]) {
        guard let decoded = WatchBridge.decode(ComplicationSnapshot.self, from: userInfo) else { return nil }
        self = decoded
    }

    public func save(to defaults: UserDefaults?) {
        guard let defaults, let data = try? JSONEncoder().encode(self) else { return }
        defaults.set(data, forKey: Self.storageKey)
    }

    public static func load(from defaults: UserDefaults?) -> ComplicationSnapshot? {
        guard let data = defaults?.data(forKey: storageKey) else { return nil }
        return try? JSONDecoder().decode(ComplicationSnapshot.self, from: data)
    }

    /// Signed out: the complication must not keep showing a previous tenant's counts.
    public static func clear(in defaults: UserDefaults?) {
        defaults?.removeObject(forKey: storageKey)
    }
}
