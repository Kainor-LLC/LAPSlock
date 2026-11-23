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
//   * one registration per kind of write, each signed into only when its switch in
//     Settings is turned on.
//
// An organization that approves only the read registration has given TenantKeep nothing
// that can change its tenant.
//
// This file is the one place the list lives. `docs/app-registrations.json` publishes the
// same list for the approval page and for TenantKeep Posture, and a test holds the two
// together. `tools/setup/New-OnCallWriteApps.ps1` creates the write registrations from
// the same definitions.
//
// No MSAL here: AuthKitMSAL turns a registration into a client. This is plain data and
// one pure function, so every rule below is tested without a tenant.

public enum AppRegistration: String, CaseIterable, Sendable {
    /// Reads only. Shared with TenantKeep Posture, whose repository owns its definition.
    case read
    /// Activating roles and deciding approvals. The registration every build before the
    /// split signed in with, kept so organizations that turned role activation on keep it.
    case roleActivation
    case deviceActions
    case userActions
    case accountRecovery
    case groupMembership

    /// Not a secret: a client ID is in every authorization request by design.
    public var clientId: String {
        switch self {
        case .read:            return "e5b148e7-9689-40b2-9b09-9d0bef133049"
        case .roleActivation:  return "50c9aa83-4f5c-4203-a3c0-adab54a2ba3a"
        case .deviceActions:   return "308de19e-a4d9-41b1-98c4-e9e136f74718"
        case .userActions:     return "8b0d25f4-ce24-42e8-b179-ff3f8f824b6c"
        case .accountRecovery: return "0bd2d07f-98fd-45c3-8b88-62752bc1dd6b"
        case .groupMembership: return "8642d2ad-9722-42c5-959c-3058a3cc1f60"
        }
    }

    /// The name an administrator sees on Microsoft's consent screen and in their sign-in log.
    public var displayName: String {
        switch self {
        case .read:            return "TenantKeep"
        case .roleActivation:  return "TenantKeep Role Activation"
        case .deviceActions:   return "TenantKeep Device Actions"
        case .userActions:     return "TenantKeep User Actions"
        case .accountRecovery: return "TenantKeep Account Recovery"
        case .groupMembership: return "TenantKeep Group Membership"
        }
    }

    /// What approving it allows, in one sentence, for the approval page and the app.
    public var summary: String {
        switch self {
        case .read:
            return "Reads devices, sign-ins, policies, service health and security incidents, and reveals Windows LAPS passwords and BitLocker recovery keys. It cannot change anything."
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
        }
    }

    /// True for the one registration that must never hold a permission that writes.
    public var isReadOnly: Bool { self == .read }

    /// The delegated Microsoft Graph permissions On-Call asks this registration for.
    ///
    /// For `.read` this is On-Call's share of the list; TenantKeep Posture may hold more
    /// read permissions on the same registration.
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
        }
    }
}

/// Decides which registration a token request goes through.
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

    /// The registration that holds every scope in `scopes`.
    ///
    /// A request the read registration can satisfy always goes to it, so a read never
    /// travels through a registration that can write. Anything else must fit one write
    /// registration exactly; there is no falling back to "whichever has the most".
    public static func registration(for scopes: [String]) throws -> AppRegistration {
        let wanted = scopes
            .map(normalize)
            .filter { !protocolScopes.contains($0) }
        guard !wanted.isEmpty else { throw RoutingError.noScopes }

        // A registration's own API, api://{client id}/{scope}, belongs to that registration.
        let own = wanted.filter { $0.hasPrefix(ownPrefix) }
        if !own.isEmpty {
            guard own.count == wanted.count else { throw RoutingError.mixedRegistrations(scopes) }
            let owners = Set(own.map(ownerClientId))
            guard owners.count == 1, let owner = owners.first else { throw RoutingError.mixedRegistrations(scopes) }
            guard let registration = AppRegistration.allCases.first(where: { $0.clientId.lowercased() == owner }) else {
                throw RoutingError.unknownScope(own[0])
            }
            return registration
        }

        for (index, scope) in wanted.enumerated() where !known.contains(scope) {
            throw RoutingError.unknownScope(original(of: scope, in: scopes) ?? wanted[index])
        }

        if covers(.read, wanted) { return .read }
        let candidates = AppRegistration.allCases.filter { !$0.isReadOnly && covers($0, wanted) }
        guard candidates.count == 1 else { throw RoutingError.mixedRegistrations(scopes) }
        return candidates[0]
    }

    // MARK: - pieces

    private static let graphPrefix = "https://graph.microsoft.com/"
    private static let ownPrefix = "api://"
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

    /// `api://{client id}/Scope` gives `{client id}`.
    private static func ownerClientId(_ scope: String) -> String {
        let rest = scope.dropFirst(ownPrefix.count)
        return String(rest.prefix { $0 != "/" })
    }

    private static func original(of normalized: String, in scopes: [String]) -> String? {
        scopes.first { normalize($0) == normalized }
    }
}
