import Foundation

// Notifications. Spec section 3.11, decision D13.
//
// This target decides what to post and holds the preferences. It knows nothing about Graph
// or tokens: the app's background run fetches each enabled kind with the module that owns
// it, reduces what came back to opaque keys, and hands the keys here. Nothing a module
// returns can reach a notification's text, because the only thing that crosses into this
// target is a key, and the text is built from the kind and the tenant's label alone. A
// lock screen shows "Contoso: 2 service incidents", never an incident title, a person's
// sign-in address or a policy name.
//
// Imports Foundation and Security (for the Keychain item) and nothing else.

/// One thing an administrator can be told about. Each reads what its module already reads,
/// so none needs a scope of its own.
public enum AlertKind: String, Codable, Sendable, CaseIterable, Identifiable, Comparable {
    case serviceIncident
    case messageDeadline
    case breakGlassSignIn
    case expiringCredential
    case secureScoreDrop
    case conditionalAccessChange
    case securityIncident
    case pimApproval

    public var id: String { rawValue }

    public static func < (a: AlertKind, b: AlertKind) -> Bool {
        (allCases.firstIndex(of: a) ?? 0) < (allCases.firstIndex(of: b) ?? 0)
    }

    /// The switch in Settings.
    public var title: String {
        switch self {
        case .serviceIncident:         return "Service health incidents"
        case .messageDeadline:         return "Message Center deadlines"
        case .breakGlassSignIn:        return "Break-glass sign-ins"
        case .expiringCredential:      return "Expiring secrets and certificates"
        case .secureScoreDrop:         return "Secure Score drops"
        case .conditionalAccessChange: return "Conditional Access changes"
        case .securityIncident:        return "High-severity security incidents"
        case .pimApproval:             return "PIM approvals waiting for you"
        }
    }

    /// The line under the switch.
    public var detail: String {
        switch self {
        case .serviceIncident:         return "An incident opens or is updated."
        case .messageDeadline:         return "A post needs action within 14 days."
        case .breakGlassSignIn:        return "One of the accounts you list signs in."
        case .expiringCredential:      return "A secret or certificate comes within 30 days of expiring."
        case .secureScoreDrop:         return "The score falls from one day to the next."
        case .conditionalAccessChange: return "A policy is created or changed."
        case .securityIncident:        return "An open high-severity incident appears."
        case .pimApproval:             return "Someone asks to activate a role or group you approve."
        }
    }

    /// For the notification body: "1 service incident", "3 service incidents".
    public var singular: String {
        switch self {
        case .serviceIncident:         return "service incident"
        case .messageDeadline:         return "Message Center deadline"
        case .breakGlassSignIn:        return "break-glass sign-in"
        case .expiringCredential:      return "credential expiring soon"
        case .secureScoreDrop:         return "Secure Score drop"
        case .conditionalAccessChange: return "Conditional Access change"
        case .securityIncident:        return "high-severity incident"
        case .pimApproval:             return "PIM request waiting for you"
        }
    }

    public var plural: String {
        switch self {
        case .serviceIncident:         return "service incidents"
        case .messageDeadline:         return "Message Center deadlines"
        case .breakGlassSignIn:        return "break-glass sign-ins"
        case .expiringCredential:      return "credentials expiring soon"
        case .secureScoreDrop:         return "Secure Score drops"
        case .conditionalAccessChange: return "Conditional Access changes"
        case .securityIncident:        return "high-severity incidents"
        case .pimApproval:             return "PIM requests waiting for you"
        }
    }

    /// The module a tap opens, by the app's module id.
    public var moduleId: String {
        switch self {
        case .serviceIncident, .messageDeadline, .expiringCredential, .secureScoreDrop: return "tenantPulse"
        case .breakGlassSignIn:        return "people"
        case .conditionalAccessChange: return "conditionalAccess"
        case .securityIncident:        return "security"
        case .pimApproval:             return "privilegedAccess"
        }
    }

    /// A break-glass sign-in is the one kind that wakes somebody. Everything else arrives
    /// quietly; the admin with notification fatigue reads them when they next look.
    public var isTimeSensitive: Bool { self == .breakGlassSignIn }
}

/// What the background run saw for one kind in one tenant: opaque keys, nothing else.
public struct Observation: Sendable, Equatable {
    public let kind: AlertKind
    /// Stable identity for "have I told them about this". For an item that can be updated
    /// (a service incident) the key includes the update time, so an update is new.
    public let keys: Set<String>
    public init(kind: AlertKind, keys: Set<String>) {
        self.kind = kind
        self.keys = keys
    }
}

/// One notification to post. Built only from the kind, a count and the tenant's label.
public struct PlannedAlert: Sendable, Equatable {
    public let tenantId: String
    public let tenantLabel: String
    public let kind: AlertKind?
    public let count: Int
    public let title: String
    public let body: String
    /// For the tap: which module, which tenant.
    public let moduleId: String?
    public let timeSensitive: Bool
    /// One per tenant per kind, so a second run replaces rather than stacks.
    public let threadIdentifier: String

    public var userInfo: [String: String] {
        var info = ["tenantId": tenantId]
        if let moduleId { info["module"] = moduleId }
        return info
    }
}

public enum AlertCopy {

    /// "Contoso: 2 service incidents". The label is the one the admin typed or the
    /// organization's domain; it is the only thing about the tenant on the lock screen.
    public static func alert(tenantId: String, label: String, kind: AlertKind, count: Int) -> PlannedAlert {
        let what = count == 1 ? "1 new " + kind.singular : "\(count) new " + kind.plural
        return PlannedAlert(
            tenantId: tenantId,
            tenantLabel: label,
            kind: kind,
            count: count,
            title: kind.title,
            body: label + ": " + what,
            moduleId: kind.moduleId,
            timeSensitive: kind.isTimeSensitive,
            threadIdentifier: tenantId + "." + kind.rawValue)
    }

    /// The one line posted when a tenant's silent sign-in stops working, after which that
    /// tenant is paused until the admin signs in again with the app open.
    public static func needsSignIn(tenantId: String, label: String) -> PlannedAlert {
        PlannedAlert(
            tenantId: tenantId,
            tenantLabel: label,
            kind: nil,
            count: 0,
            title: "Sign in to keep checking",
            body: label + ": TenantKeep can't check this organization until you open the app and sign in again.",
            moduleId: nil,
            timeSensitive: false,
            threadIdentifier: tenantId + ".signin")
    }
}
