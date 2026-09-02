import Foundation

// Build Spec — PIM eligibility and activation, Graph v1.0 GA.
//
// THE SCENARIO. An administrator at a broken workstation needs a LAPS password, and the
// access that would let them read it is PIM-*eligible* rather than active. Today that means
// walking away, opening the portal on a desktop, activating, and coming back. Doing it in
// the app closes the loop, and it pairs with the `notAuthorized` error already shown on a
// failed reveal: "your access is not active, activate it here" rather than "you lack
// permission", which is true and useless.
//
// TWO KINDS, NOT ONE. Eligibility can be for a directory role, or for membership of a group
// that carries role assignments — "PIM for Groups". Mature tenants often prefer the group
// form because it is governed alongside every other group. They are separate Graph surfaces
// with separate scopes and separate request bodies, and an implementation that handled only
// roles would silently show "no eligible access" to exactly the tenants that manage access
// most carefully.

/// What a piece of eligible access actually is, which decides how it gets activated.
public enum EligibleAccessKind: Sendable, Equatable, Hashable {
    /// A directory role. Activated through `roleManagement/directory`.
    case directoryRole(roleDefinitionId: String, directoryScopeId: String)
    /// Membership or ownership of a group. Activated through
    /// `identityGovernance/privilegedAccess/group`.
    case group(groupId: String, accessId: GroupAccessId)
}

/// Which kind of group access is eligible. Graph's own vocabulary.
public enum GroupAccessId: String, Sendable, Equatable, Hashable, Codable {
    case member
    case owner
}

/// Something the signed-in user could activate.
public struct EligibleAccess: Sendable, Equatable, Identifiable, Hashable {
    /// The eligibility schedule's own id, not the role's or the group's.
    public let id: String
    public let kind: EligibleAccessKind
    /// Human-readable name, when Graph expanded it. Nil when only ids came back.
    public let displayName: String?
    /// When the ELIGIBILITY lapses — not the activation. Nil for permanent eligibility.
    public let eligibilityEndsAt: Date?

    public init(id: String, kind: EligibleAccessKind, displayName: String?, eligibilityEndsAt: Date?) {
        self.id = id
        self.kind = kind
        self.displayName = displayName
        self.eligibilityEndsAt = eligibilityEndsAt
    }

    /// What to show. Never a bare GUID: an administrator recognises "Cloud Device
    /// Administrator" or "LAPS Readers" and not `7698a772-…`.
    public var label: String {
        if let displayName, !displayName.isEmpty { return displayName }
        switch kind {
        case .directoryRole: return "Directory role"
        case .group(_, let accessId): return accessId == .owner ? "Group ownership" : "Group membership"
        }
    }

    /// True for a directory role known to be able to read Windows LAPS passwords, so the
    /// list can put the useful one first.
    ///
    /// **Always false for a group**, and that is honest rather than lazy: a group's id says
    /// nothing about which roles it carries, and finding out would mean another Graph call
    /// per group. Claiming a group grants credential access when it might not would be worse
    /// than not claiming it, so groups are simply not promoted.
    public var canReadLocalCredentials: Bool {
        guard case .directoryRole(let roleDefinitionId, _) = kind else { return false }
        return Self.credentialReadingRoles.contains(roleDefinitionId.lowercased())
    }

    /// Well-known role template GUIDs, which are identical in every tenant. Matched on id
    /// rather than display name because display names are localised.
    static let credentialReadingRoles: Set<String> = [
        "62e90394-69f5-4237-9190-012177145e10",  // Global Administrator
        "7698a772-787b-4ac8-901f-60d6b08affd2",  // Cloud Device Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  // Security Administrator
        "5d6b6bb7-de71-4623-b4af-96380a352509",  // Security Reader
        "9f06204d-73c1-4d4c-880a-6edb90606fd8",  // Entra Joined Device Local Administrator
        "3a2c62db-5318-420d-8d74-23affee5d9d5",  // Intune Administrator
    ]
}

/// Graph endpoints and scopes for both surfaces.
///
/// Scope names verified against Graph's own refusal, which names every scope it would have
/// accepted — a more reliable source than documentation.
public enum PrivilegedAccessGraph {

    // Directory roles.
    //
    // `filterByCurrentUser(on='principal')` rather than the plain list, and that is a
    // correctness matter rather than a nicety. The unfiltered collection returns every
    // schedule the CALLER can see, which needs directory-wide read — so it works for a
    // Global Administrator and returns nothing useful for the ordinary admin this feature
    // exists to help. The self-service function returns exactly the caller's own
    // eligibility with only the read scope.
    public static let roleEligibilityPath =
        "/v1.0/roleManagement/directory/roleEligibilitySchedules/filterByCurrentUser(on='principal')"
    public static let roleActivationPath = "/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
    public static let roleReadScope = "RoleEligibilitySchedule.Read.Directory"
    public static let roleActivateScope = "RoleAssignmentSchedule.ReadWrite.Directory"

    // PIM for Groups.
    //
    // Here the filter is not optional at all: Graph documents that listing group
    // eligibility **requires** either a `principalId` or a `groupId` filter, so the plain
    // collection is simply an invalid request. Calling it returned nothing, one surface
    // failing is tolerated by design, and the result was a tenant with PIM for Groups
    // configured showing no groups — a silent half-failure rather than an error.
    public static let groupEligibilityPath =
        "/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules/filterByCurrentUser(on='principal')"
    public static let groupActivationPath = "/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests"
    public static let groupReadScope = "PrivilegedEligibilitySchedule.Read.AzureADGroup"
    public static let groupActivateScope = "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup"

    /// Read scopes.
    public static let readScopes = [roleReadScope, groupReadScope]

    /// Activation scopes.
    public static let activateScopes = [roleActivateScope, groupActivateScope]

    /// **Everything the feature needs, requested together when the user opts in.**
    ///
    /// Read AND activate, and asking for only half is a bug this shipped once: the Settings
    /// toggle consented to the activation scopes alone, so opening the sheet then made a
    /// silent request for the unconsented READ scopes, which failed and surfaced as "your
    /// account may not be eligible" — a message about the wrong problem entirely.
    ///
    /// These are the only scopes gated behind the opt-in toggle, and they are a heavier ask
    /// than reading a password: they let the app request a privilege escalation. A customer
    /// who leaves the toggle off never sees any of them on a consent screen.
    public static let allScopes = readScopes + activateScopes
}

/// Where an activation ended up.
///
/// `pendingApproval` is not a flavour of success and must never be shown as one. When a
/// tenant requires approval, `selfActivate` creates a request and returns — nothing is
/// active. Telling an administrator otherwise sends them back to a broken machine to fail
/// again.
public enum ActivationOutcome: Sendable, Equatable {
    case activated(until: Date?)
    case pendingApproval(requestId: String?)
}

public enum PrivilegedAccessError: Error, Sendable, Equatable {
    /// Graph requires MFA satisfied in THIS session before it will self-activate anything.
    /// The caller re-authenticates with the challenge and retries. This is the only
    /// legitimate way to satisfy that requirement — see `ClaimsChallenge`.
    case claimsChallenge(ClaimsChallenge)
    /// The scope has not been consented. Expected until the user opts in.
    case consentRequired
    /// No eligible access. Not an error to apologise for — it usually means the user's
    /// access is permanent rather than PIM-managed.
    case noEligibleAccess
    case alreadyActive
    case notAuthorized
    case transport
    case decodeFailure
    case serviceError(status: Int)
}
