import Foundation
import AuthKit

/// How an organization approved writes, as a person can set it in Settings when the app
/// cannot read it for itself.
enum WriteRouteChoice: String, CaseIterable, Identifiable {
    /// Read the organization's approvals and follow them.
    case automatic
    /// A separate app for each kind of action.
    case separate
    /// The one app that holds every action, TenantKeep Actions.
    case combined

    var id: String { rawValue }

    var label: String {
        switch self {
        case .automatic: return "Automatic"
        case .separate:  return "A separate app for each"
        case .combined:  return "One app for all"
        }
    }
}

/// What is remembered, per organization, about which app registration its writes go
/// through. Not a credential and not in the Keychain: two small preferences that say
/// which of an organization's approvals to use, cleared with the organization's other data.
enum WriteRoutes {

    private static func choiceKey(_ tenant: String) -> String { "writeRoute.choice." + tenant.lowercased() }
    private static func combinedKey(_ tenant: String) -> String { "writeRoute.combined." + tenant.lowercased() }

    static func choice(for tenant: String) -> WriteRouteChoice {
        UserDefaults.standard.string(forKey: choiceKey(tenant)).flatMap(WriteRouteChoice.init(rawValue:)) ?? .automatic
    }

    static func setChoice(_ choice: WriteRouteChoice, for tenant: String) {
        UserDefaults.standard.set(choice.rawValue, forKey: choiceKey(tenant))
    }

    /// The kinds of write last found to go through the combined app in this organization.
    static func combined(for tenant: String) -> Set<AppRegistration> {
        let stored = UserDefaults.standard.stringArray(forKey: combinedKey(tenant)) ?? []
        return Set(stored.compactMap(AppRegistration.init(rawValue:)))
    }

    static func store(combined: Set<AppRegistration>, for tenant: String) {
        UserDefaults.standard.set(combined.map(\.rawValue).sorted(), forKey: combinedKey(tenant))
    }

    /// The set the sign-in manager should start a session with.
    static func startingRoute(for tenant: String) -> Set<AppRegistration> {
        switch choice(for: tenant) {
        case .combined:  return Set(AppRegistration.separateWrites)
        case .separate:  return []
        case .automatic: return combined(for: tenant)
        }
    }

    static func forget(_ tenant: String) {
        UserDefaults.standard.removeObject(forKey: choiceKey(tenant))
        UserDefaults.standard.removeObject(forKey: combinedKey(tenant))
    }
}
