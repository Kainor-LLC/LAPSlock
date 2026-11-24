import Foundation

// The app registrations TenantKeep On-Call signs in through, and which one a request for
// a token belongs to.
//
// Why there are several. Microsoft Entra ID puts every delegated permission an
// organization has granted an app into the tokens it issues that app, whichever of them
// the request named. Measured on a phone: one registration holding everything, asked for
// `Device.Read.All`, answered with a token that could also change group membership and
// issue a Temporary Access Pass. Asking for less does not get less. So "this sign-in
// cannot write" has to be a property of the registration, not of the request:
//
//   * one registration that only reads, shared with TenantKeep Posture;
//   * writes through other registrations, signed into only when a switch in Settings is
//     turned on.
//
// An organization that approves only the read registration has given TenantKeep nothing
// that can change its tenant.
//
// For writes an organization chooses one of two routes: a separate registration for each
// kind of action, or one registration, `.actions`, that holds every one of them. When both
// are approved the separate one is used, because its token is the narrower. `.actions` is
// the registration every build before the split signed in with.
//
// This file is the one place the list lives. `docs/app-registrations.json` publishes the
// same list for the consent page and for TenantKeep Posture, and a test holds the two
// together. `tools/setup/New-OnCallApps.ps1` creates the registrations from the same
// definitions.
//
// No MSAL here: AuthKitMSAL turns a registration into a client. This is plain data and
// pure functions, so every rule below is tested without a tenant.

public enum AppRegistration: String, CaseIterable, Sendable {
    /// Reads only. Shared with TenantKeep Posture, whose repository owns its definition.
    case read
    /// Every write in one registration, for an organization that prefers one approval.
    /// Also the original registration: until an organization approves `.read`, an install
    /// that signed in before the split keeps reading through it.
    case actions
    case roleActivation
    case deviceActions
    case userActions
    case accountRecovery
    case groupMembership
    /// No Microsoft Graph permission. Its one scope registers a phone for Instant alerts.
    case alerts
    /// No Microsoft Graph permission. Its one permission, on Microsoft's Mobile Application
    /// Management service, lets Microsoft's Intune App SDK enrol the app for a person whose
    /// organization targets it with an app protection policy. On a registration of its own
    /// because the permission's name is not a read, and the read registration holds reads
    /// only. An organization that does not use app protection never approves it.
    case appProtection

    /// The registrations that each hold one kind of write.
    public static let separateWrites: [AppRegistration] =
        [.roleActivation, .deviceActions, .userActions, .accountRecovery, .groupMembership]

    /// Not a secret: a client ID is in every authorization request by design.
    public var clientId: String {
        switch self {
        case .read:            return "e5b148e7-9689-40b2-9b09-9d0bef133049"
        case .actions:         return "50c9aa83-4f5c-4203-a3c0-adab54a2ba3a"
        case .roleActivation:  return "315a1b17-88ea-4255-9b1f-b945cf84750b"
        case .deviceActions:   return "308de19e-a4d9-41b1-98c4-e9e136f74718"
        case .userActions:     return "8b0d25f4-ce24-42e8-b179-ff3f8f824b6c"
        case .accountRecovery: return "0bd2d07f-98fd-45c3-8b88-62752bc1dd6b"
        case .groupMembership: return "8642d2ad-9722-42c5-959c-3058a3cc1f60"
        case .alerts:          return "d7c387b7-8e67-4957-bc67-4b71824a60ea"
        case .appProtection:   return "eaea8770-7305-4806-ae1c-7a03d2ef28fe"
        }
    }

    /// The name an administrator sees on Microsoft's consent screen and in their sign-in log.
    public var displayName: String {
        switch self {
        case .read:            return "TenantKeep"
        case .actions:         return "TenantKeep Actions"
        case .roleActivation:  return "TenantKeep Role Activation"
        case .deviceActions:   return "TenantKeep Device Actions"
        case .userActions:     return "TenantKeep User Actions"
        case .accountRecovery: return "TenantKeep Account Recovery"
        case .groupMembership: return "TenantKeep Group Membership"
        case .alerts:          return "TenantKeep Alerts"
        case .appProtection:   return "TenantKeep App Protection"
        }
    }

    /// What approving it allows, in one sentence, for the consent page and the app.
    public var summary: String {
        switch self {
        case .read:
            return "Reads devices, sign-ins, policies, service health and security incidents, and reveals Windows LAPS passwords and BitLocker recovery keys. It cannot change anything."
        case .actions:
            return "Every action in one app: role activation, device actions, user actions, account recovery and group membership. Approve this one, or the separate apps for the actions you want."
        case .roleActivation:
            return "Activates the roles and group memberships you are eligible for, and approves or denies requests."
        case .deviceActions:
            return "Syncs, restarts, locks, locates, retires and wipes devices, rotates keys and passwords, and reads a Mac's admin password."
        case .userActions:
            return "Revokes sessions, blocks or unblocks sign-in, and confirms or dismisses a user's risk."
        case .accountRecovery:
            return "Removes a person's sign-in methods and issues a Temporary Access Pass."
        case .groupMembership:
            return "Adds and removes group members."
        case .alerts:
            return "Registers a phone to receive Instant alerts. It has no access to Microsoft Graph."
        case .appProtection:
            return "Lets your organization's Intune app protection policy apply to TenantKeep on a phone that is not enrolled. It has no access to Microsoft Graph."
        }
    }

    /// True for the one registration that must never hold a permission that writes.
    public var isReadOnly: Bool { self == .read }

    /// The delegated Microsoft Graph permissions On-Call asks this registration for.
    ///
    /// For `.read` this is On-Call's share of the list; TenantKeep Posture may hold more
    /// read permissions on the same registration. For `.actions` it is everything the
    /// separate write registrations hold, built from them so the two cannot drift.
    public var scopes: [String] {
        switch self {
        case .read:
            return [
                // Devices and the two secrets this product exists to reveal.
                "DeviceManagementManagedDevices.Read.All",
                "Device.Read.All",
                "DeviceLocalCredential.ReadBasic.All",
                "DeviceLocalCredential.Read.All",
                "BitLockerKey.ReadBasic.All",
                "BitLockerKey.Read.All",
                // People.
                "User.ReadBasic.All",
                "User.Read.All",
                "IdentityRiskyUser.Read.All",
                // Sign-ins, policies and the directory names they refer to.
                "AuditLog.Read.All",
                "Policy.Read.All",
                "Directory.Read.All",
                // Tenant Pulse.
                "ServiceHealth.Read.All",
                "ServiceMessage.Read.All",
                "Application.Read.All",
                "DeviceManagementServiceConfig.Read.All",
                "SecurityEvents.Read.All",
                // Security.
                "SecurityIncident.Read.All",
                "ThreatHunting.Read.All",
                // Roles: what is active, what can be activated, and under which policy.
                "RoleAssignmentSchedule.Read.Directory",
                "RoleEligibilitySchedule.Read.Directory",
                "RoleManagementPolicy.Read.Directory",
                "PrivilegedAssignmentSchedule.Read.AzureADGroup",
                "PrivilegedEligibilitySchedule.Read.AzureADGroup",
                "RoleManagementPolicy.Read.AzureADGroup"
            ]
        case .actions:
            return Self.separateWrites.flatMap(\.scopes)
        case .roleActivation:
            return [
                "RoleAssignmentSchedule.ReadWrite.Directory",
                "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup"
            ]
        case .deviceActions:
            return [
                // Also the only permission Microsoft accepts for reading a Mac's admin
                // password, which is why that read is here and not in `.read`.
                "DeviceManagementManagedDevices.PrivilegedOperations.All",
                "DeviceManagementManagedDevices.ReadWrite.All"
            ]
        case .userActions:
            return [
                "User.RevokeSessions.All",
                "User.EnableDisableAccount.All",
                // Graph requires this on the same token as User.EnableDisableAccount.All.
                // A write registration may hold a read; the read registration never holds
                // a write.
                "User.Read.All",
                "IdentityRiskyUser.ReadWrite.All"
            ]
        case .accountRecovery:
            return [
                "UserAuthenticationMethod.ReadWrite.All",
                "UserAuthMethod-TAP.ReadWrite.All"
            ]
        case .groupMembership:
            return ["GroupMember.ReadWrite.All"]
        case .alerts, .appProtection:
            return []
        }
    }

    /// Scopes this registration defines itself, as `api://{client id}/{name}`.
    public var ownScopes: [String] {
        self == .alerts ? ["api://" + clientId + "/Alerts.Register"] : []
    }

    /// Microsoft's Mobile Application Management service, which Intune app protection
    /// answers from. Not Microsoft Graph, and nothing in a tenant's directory is behind it.
    public static let appManagementResource = "https://msmamservice.api.application"

    /// Permissions this registration holds on a Microsoft service other than Graph, with
    /// the service in front. One exists: the permission Microsoft's Intune App SDK needs,
    /// which reads and writes the signed-in person's own app management record.
    public var serviceScopes: [String] {
        self == .appProtection ? [Self.appManagementResource + "/DeviceManagementManagedApps.ReadWrite"] : []
    }

    /// What a token for this registration is asked for by name: its Graph permissions
    /// with the resource in front, then its own scopes and those on another service. For
    /// consent links, which must name their scopes and never use `.default`.
    public var qualifiedScopes: [String] {
        scopes.map { "https://graph.microsoft.com/" + $0 } + ownScopes + serviceScopes
    }
}

/// How one organization's requests reach the registrations, decided outside this file
/// (from what the organization approved) and applied by `client(for:)`.
public struct RegistrationRoute: Sendable, Equatable {
    /// The kinds of write this organization sends through `.actions`, because it approved
    /// that one registration and not the separate one.
    public var combined: Set<AppRegistration>
    /// Reads go through the original registration: this install signed in before the
    /// split and the organization has not approved `.read` yet.
    public var readsThroughOriginal: Bool

    public init(combined: Set<AppRegistration> = [], readsThroughOriginal: Bool = false) {
        self.combined = combined
        self.readsThroughOriginal = readsThroughOriginal
    }

    /// The registration whose client asks for the token, given the one the scopes belong to.
    public func client(for home: AppRegistration) -> AppRegistration {
        if home == .read { return readsThroughOriginal ? .actions : .read }
        if AppRegistration.separateWrites.contains(home), combined.contains(home) { return .actions }
        return home
    }
}

/// Decides which registration a set of scopes belongs to.
public enum ScopeRouter {

    public enum RoutingError: Error, Sendable, Equatable {
        /// Nothing to ask for once the sign-in protocol's own scopes are set aside.
        case noScopes
        /// A scope no registration holds. A new permission was added to a module without
        /// being added to `AppRegistration`.
        case unknownScope(String)
        /// The scopes belong to more than one registration. One token comes from one
        /// registration, so the caller has to make two requests.
        case mixedRegistrations([String])
    }

    /// The registration that holds every scope in `scopes`: `.read`, one of the separate
    /// write registrations, `.alerts` or `.appProtection`. Never `.actions`; whether that one stands in for
    /// a separate registration is the organization's choice, applied by `RegistrationRoute`.
    ///
    /// A request the read registration can satisfy always belongs to it, so a read never
    /// travels through a registration that can write. Anything else must fit one write
    /// registration exactly; there is no falling back to "whichever has the most".
    public static func registration(for scopes: [String]) throws -> AppRegistration {
        let wanted = scopes
            .map(normalize)
            .filter { !protocolScopes.contains($0) }
        guard !wanted.isEmpty else { throw RoutingError.noScopes }

        // A registration's own scope, api://{client id}/{name}, belongs to that registration,
        // and so does a permission on a service other than Graph. Each is matched whole:
        // a name the registration does not hold is unknown, never close enough.
        let own = wanted.filter { $0.hasPrefix(ownPrefix) || $0.hasPrefix(servicePrefix) }
        if !own.isEmpty {
            guard own.count == wanted.count else { throw RoutingError.mixedRegistrations(scopes) }
            let owners = AppRegistration.allCases.filter { registration in
                let defined = Set((registration.ownScopes + registration.serviceScopes).map { $0.lowercased() })
                return own.allSatisfy(defined.contains)
            }
            guard let owner = owners.first else { throw RoutingError.unknownScope(original(of: own[0], in: scopes) ?? own[0]) }
            return owner
        }

        for scope in wanted where !known.contains(scope) {
            throw RoutingError.unknownScope(original(of: scope, in: scopes) ?? scope)
        }

        if covers(.read, wanted) { return .read }
        let candidates = AppRegistration.separateWrites.filter { covers($0, wanted) }
        guard candidates.count == 1 else { throw RoutingError.mixedRegistrations(scopes) }
        return candidates[0]
    }

    /// Splits what a Settings switch asks for into one request per registration, reads
    /// first. A switch often needs both: turning on group changes needs three reads and
    /// one write, and one token cannot come from two registrations.
    ///
    /// Each registration is asked for exactly what was named and belongs to it, never for
    /// everything it holds: turning on Mac password reveal asks for one permission, not
    /// for the rest of device actions. One exception keeps a write working: a read that
    /// was named and that a write registration also holds (see `.userActions`) is asked of
    /// both, because Graph wants it on the same token as the write.
    public static func requests(for scopes: [String]) throws -> [(registration: AppRegistration, scopes: [String])] {
        var reads: [String] = []
        var order: [AppRegistration] = []
        var named: [AppRegistration: [String]] = [:]
        for scope in scopes where !protocolScopes.contains(normalize(scope)) {
            let home = try registration(for: [scope])
            if home == .read {
                if !reads.contains(scope) { reads.append(scope) }
            } else {
                if !order.contains(home) { order.append(home) }
                if named[home]?.contains(scope) != true { named[home, default: []].append(scope) }
            }
        }
        guard !reads.isEmpty || !order.isEmpty else { throw RoutingError.noScopes }
        let writes = order.map { registration -> (registration: AppRegistration, scopes: [String]) in
            let held = holdings[registration] ?? []
            let companions = reads.filter { held.contains(normalize($0)) }
            return (registration, (named[registration] ?? []) + companions)
        }
        return (reads.isEmpty ? [] : [(registration: AppRegistration.read, scopes: reads)]) + writes
    }

    // MARK: - pieces

    private static let graphPrefix = "https://graph.microsoft.com/"
    private static let ownPrefix = "api://"
    private static let servicePrefix = AppRegistration.appManagementResource.lowercased() + "/"
    /// Sign-in protocol scopes, which every registration answers and MSAL adds itself.
    private static let protocolScopes: Set<String> = ["openid", "profile", "offline_access", "email"]

    /// Lowercased, because Microsoft does not keep one spelling: it returns
    /// `BitlockerKey.Read.All` for what its own reference calls `BitLockerKey.Read.All`.
    private static let holdings: [AppRegistration: Set<String>] = Dictionary(
        uniqueKeysWithValues: AppRegistration.allCases.map { ($0, Set($0.scopes.map { $0.lowercased() })) })

    private static let known: Set<String> = holdings.values.reduce(into: []) { $0.formUnion($1) }

    private static func covers(_ registration: AppRegistration, _ wanted: [String]) -> Bool {
        guard let held = holdings[registration] else { return false }
        return wanted.allSatisfy(held.contains)
    }

    private static func normalize(_ scope: String) -> String {
        let lowered = scope.trimmingCharacters(in: .whitespaces).lowercased()
        return lowered.hasPrefix(graphPrefix) ? String(lowered.dropFirst(graphPrefix.count)) : lowered
    }

    private static func original(of normalized: String, in scopes: [String]) -> String? {
        scopes.first { normalize($0) == normalized }
    }
}
