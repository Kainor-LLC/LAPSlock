import Foundation

// Managed app configuration. Spec section 8a, decision D9.
//
// An organization pushes settings through an Intune app configuration policy, and iOS
// hands them to the app as a dictionary under `com.apple.configuration.managed`. Every key
// is optional and every default is the safe one, so an app with no policy behaves exactly
// as it did before this existed. The configuration can only take things away or require
// more care: turn a module off, ask for more confirmation, pin the tenant, require the app
// lock. Nothing here can turn on a write the admin did not turn on themselves.
//
// A key with the wrong type or an unknown value is ignored and reported, never guessed at,
// so a typo in a policy shows up in Settings instead of silently doing something else.
//
// Foundation only.

public struct ManagedConfiguration: Sendable, Equatable {

    public static let userDefaultsKey = "com.apple.configuration.managed"

    public enum ConfirmationLevel: String, Sendable, Equatable {
        /// The tiers as designed: sync on a tap, the rest confirmed, destructive actions typed.
        case standard
        /// Every write asks at least once more than standard.
        case strict
    }

    public enum GroupWriteScope: String, Sendable, Equatable {
        case tagged, all, none
    }

    /// Module and feature ids an organization may switch off.
    public static let switchableIds: [String] = [
        "credentials", "privilegedAccess", "signInTriage", "tenantPulse", "conditionalAccess",
        "security", "deviceActions", "userActions", "groupWrites", "notifications"
    ]

    public var disabledIds: Set<String> = []
    public var confirmationLevel: ConfirmationLevel = .standard
    public var groupWriteScope: GroupWriteScope = .tagged
    public var groupWriteAdministrativeUnit: String = "Helpdesk Managed Groups"
    public var groupWritePrefix: String?
    /// Lowercase canonical tenant GUID.
    public var tenantPin: String?
    public var appLockRequired = false
    public var breakGlassUPNs: [String] = []

    /// Keys that were present, in the order the Settings summary lists them.
    public private(set) var appliedKeys: [String] = []
    /// Keys present with a type or value the app could not use, with why.
    public private(set) var problems: [String] = []

    public init() {}

    /// True when the organization set anything at all.
    public var isManaged: Bool { !appliedKeys.isEmpty || !problems.isEmpty }

    public func isDisabled(_ id: String) -> Bool { disabledIds.contains(id) }

    // MARK: - parsing

    public static func parse(_ dictionary: [String: Any]?) -> ManagedConfiguration {
        var config = ManagedConfiguration()
        guard let dictionary, !dictionary.isEmpty else { return config }

        if let raw = dictionary["modules.disabled"] {
            if let ids = strings(raw) {
                let known = ids.filter { switchableIds.contains($0) }
                let unknown = ids.filter { !switchableIds.contains($0) }
                config.disabledIds = Set(known)
                config.appliedKeys.append("modules.disabled")
                if !unknown.isEmpty {
                    config.problems.append("modules.disabled: unknown id " + unknown.sorted().joined(separator: ", "))
                }
            } else {
                config.problems.append("modules.disabled: expected a list of module ids")
            }
        }

        if let raw = dictionary["confirmation.level"] {
            if let value = (raw as? String).flatMap({ ConfirmationLevel(rawValue: $0.lowercased()) }) {
                config.confirmationLevel = value
                config.appliedKeys.append("confirmation.level")
            } else {
                config.problems.append("confirmation.level: expected standard or strict")
            }
        }

        if let raw = dictionary["groupWrite.scope"] {
            if let value = (raw as? String).flatMap({ GroupWriteScope(rawValue: $0.lowercased()) }) {
                config.groupWriteScope = value
                config.appliedKeys.append("groupWrite.scope")
            } else {
                config.problems.append("groupWrite.scope: expected tagged, all or none")
            }
        }

        if let raw = dictionary["groupWrite.administrativeUnit"] {
            if let value = (raw as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty, value.count <= 256 {
                config.groupWriteAdministrativeUnit = value
                config.appliedKeys.append("groupWrite.administrativeUnit")
            } else {
                config.problems.append("groupWrite.administrativeUnit: expected a name")
            }
        }

        if let raw = dictionary["groupWrite.prefix"] {
            if let value = (raw as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty, value.count <= 64 {
                config.groupWritePrefix = value
                config.appliedKeys.append("groupWrite.prefix")
            } else {
                config.problems.append("groupWrite.prefix: expected a short prefix")
            }
        }

        if let raw = dictionary["tenant.pin"] {
            if let value = (raw as? String).flatMap(canonicalTenantId) {
                config.tenantPin = value
                config.appliedKeys.append("tenant.pin")
            } else {
                config.problems.append("tenant.pin: expected a tenant ID (a GUID)")
            }
        }

        if let raw = dictionary["appLock.required"] {
            if let value = bool(raw) {
                config.appLockRequired = value
                config.appliedKeys.append("appLock.required")
            } else {
                config.problems.append("appLock.required: expected true or false")
            }
        }

        if let raw = dictionary["breakGlass.upns"] {
            if let values = strings(raw) {
                config.breakGlassUPNs = values.map { $0.lowercased() }
                config.appliedKeys.append("breakGlass.upns")
            } else {
                config.problems.append("breakGlass.upns: expected a list of sign-in addresses")
            }
        }

        let known: Set<String> = ["modules.disabled", "confirmation.level", "groupWrite.scope", "groupWrite.administrativeUnit",
                                  "groupWrite.prefix", "tenant.pin", "appLock.required", "breakGlass.upns"]
        // Intune adds its own tokens ({{userprincipalname}} and the like) under keys the
        // admin names; anything else unknown is listed so a typo is visible.
        for key in dictionary.keys.sorted() where !known.contains(key) && !key.hasPrefix("IntuneMAM") {
            config.problems.append(key + ": not a TenantKeep setting")
        }
        return config
    }

    // MARK: - presentation

    /// One line per applied setting, for the Settings section, in plain words.
    public var summaryLines: [String] {
        var lines: [String] = []
        for key in appliedKeys {
            switch key {
            case "modules.disabled":
                lines.append(disabledIds.isEmpty ? "No modules turned off" : "Turned off: " + disabledIds.sorted().map(Self.label).joined(separator: ", "))
            case "confirmation.level":
                lines.append(confirmationLevel == .strict ? "Every action asks for extra confirmation" : "Standard confirmation")
            case "groupWrite.scope":
                lines.append("Group changes: " + groupWriteScope.rawValue)
            case "groupWrite.administrativeUnit":
                lines.append("Helpdesk administrative unit: " + groupWriteAdministrativeUnit)
            case "groupWrite.prefix":
                lines.append("Helpdesk group prefix: " + (groupWritePrefix ?? ""))
            case "tenant.pin":
                lines.append("Limited to one organization")
            case "appLock.required":
                lines.append(appLockRequired ? "App lock required" : "App lock up to you")
            case "breakGlass.upns":
                lines.append(breakGlassUPNs.count == 1 ? "1 break-glass account watched" : "\(breakGlassUPNs.count) break-glass accounts watched")
            default:
                break
            }
        }
        return lines
    }

    public static func label(_ id: String) -> String {
        switch id {
        case "credentials":       return "LAPSlock"
        case "privilegedAccess":  return "Privileged Access"
        case "signInTriage":      return "Sign-in Triage"
        case "tenantPulse":       return "Tenant Pulse"
        case "conditionalAccess": return "Conditional Access"
        case "security":          return "Security"
        case "deviceActions":     return "Device actions"
        case "userActions":       return "User actions"
        case "groupWrites":       return "Group changes"
        case "notifications":     return "Notifications"
        default:                  return id
        }
    }

    // MARK: - helpers

    /// A list arrives as an array from a plist-style policy and as a comma-separated string
    /// from the key-value designer; both are accepted.
    static func strings(_ raw: Any) -> [String]? {
        let values: [String]
        if let array = raw as? [String] {
            values = array
        } else if let array = raw as? [Any], array.allSatisfy({ $0 is String }) {
            values = array.compactMap { $0 as? String }
        } else if let string = raw as? String {
            values = string.split(separator: ",").map(String.init)
        } else {
            return nil
        }
        return values.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    /// A boolean arrives as a Bool, a number, or the strings true and false.
    static func bool(_ raw: Any) -> Bool? {
        if let value = raw as? Bool { return value }
        if let value = raw as? NSNumber { return value.boolValue }
        if let value = raw as? String {
            switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "true", "yes", "1": return true
            case "false", "no", "0": return false
            default: return nil
            }
        }
        return nil
    }

    /// Exact D-format GUID, lowercased; the same rule the auth layer's tenant pin uses.
    static func canonicalTenantId(_ raw: String) -> String? {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard value.count == 36 else { return nil }
        for (index, ch) in value.enumerated() {
            if [8, 13, 18, 23].contains(index) {
                guard ch == "-" else { return nil }
            } else {
                guard ch.isHexDigit else { return nil }
            }
        }
        return value
    }
}
