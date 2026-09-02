import Foundation

// Build Spec — PIM role eligibility and activation, Graph v1.0 GA.
//
// THE SCENARIO THIS EXISTS FOR. An administrator standing at a broken workstation needs a
// LAPS password, and their Cloud Device Administrator role is PIM-*eligible* rather than
// active. Today that means walking away from the machine, opening the portal on a desktop,
// activating, and coming back. Doing it in the app closes the loop, and it pairs with the
// `notAuthorized` error already surfaced on a failed reveal: "your role is not active,
// activate it here" instead of "you lack permission", which is true but useless.

/// A role the signed-in user could activate.
///
/// From `GET /v1.0/roleManagement/directory/roleEligibilitySchedules`.
public struct EligibleRole: Sendable, Equatable, Identifiable, Hashable {
    /// The eligibility schedule's own id, not the role's.
    public let id: String
    public let roleDefinitionId: String
    /// Human-readable name, when Graph expanded it. Nil when only the id came back.
    public let displayName: String?
    /// `/` for tenant-wide, or an administrative unit / app scope.
    public let directoryScopeId: String
    /// When the eligibility itself lapses — not the activation. Nil for permanent eligibility.
    public let eligibilityEndsAt: Date?

    public init(
        id: String,
        roleDefinitionId: String,
        displayName: String?,
        directoryScopeId: String,
        eligibilityEndsAt: Date?
    ) {
        self.id = id
        self.roleDefinitionId = roleDefinitionId
        self.displayName = displayName
        self.directoryScopeId = directoryScopeId
        self.eligibilityEndsAt = eligibilityEndsAt
    }

    /// What to show when Graph did not expand the role definition. Never a bare GUID in the
    /// UI: an administrator recognises "Cloud Device Administrator" and not
    /// `9f06204d-73c1-4d4c-880a-6edb90606fd8`.
    public var label: String { displayName ?? "Directory role" }

    /// True for a role that can read Windows LAPS passwords, so the activation sheet can
    /// order the useful one first.
    ///
    /// Matched on the role definition's well-known template GUIDs, which are stable across
    /// every tenant, rather than on display names, which are localised.
    public var canReadLocalCredentials: Bool {
        Self.credentialReadingRoles.contains(roleDefinitionId.lowercased())
    }

    static let credentialReadingRoles: Set<String> = [
        "62e90394-69f5-4237-9190-012177145e10",  // Global Administrator
        "7698a772-787b-4ac8-901f-60d6b08affd2",  // Cloud Device Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  // Security Administrator
        "5d6b6bb7-de71-4623-b4af-96380a352509",  // Security Reader
        "9f06204d-73c1-4d4c-880a-6edb90606fd8",  // Microsoft Entra Joined Device Local Administrator
        "3a2c62db-5318-420d-8d74-23affee5d9d5",  // Intune Administrator
    ]
}

/// Where an activation request ended up.
///
/// `pendingApproval` is not a variant of success and must never be presented as one. If the
/// tenant requires approval for a role, `selfActivate` creates a request and returns —
/// nothing is active yet. Telling an administrator their role is live when it is not sends
/// them back to a broken machine to fail again.
public enum ActivationOutcome: Sendable, Equatable {
    case activated(until: Date?)
    case pendingApproval(requestId: String?)
}

public enum PrivilegedAccessError: Error, Sendable, Equatable {
    /// Graph wants MFA satisfied in this session. The caller re-authenticates with the
    /// challenge and retries — see `ClaimsChallenge`.
    case claimsChallenge(ClaimsChallenge)
    /// The scope has not been consented. The role-activation scope is opt-in, so this is
    /// the expected state until the user enables it in Settings.
    case consentRequired
    /// Signed-in user holds no eligible roles. Not an error to apologise for: it usually
    /// means their access is permanent rather than PIM-managed.
    case noEligibleRoles
    /// The role is already active. Treated distinctly so the UI can say so plainly.
    case alreadyActive
    case notAuthorized
    case transport
    case decodeFailure
    case serviceError(status: Int)
}
