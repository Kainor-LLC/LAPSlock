import Foundation

// The session check, decided by Connor on 2026-11-24 (LAPSlock-internal CAE-PLAN.md,
// decisions 2 and 3).
//
// Revoking a person's sessions in Entra is the fast control in a breach, but a token the
// phone already holds keeps working until it expires, up to an hour and a half. So the app
// asks Microsoft itself: when it comes to the front, and every ten minutes while it stays
// there, it asks for a fresh token with the cached one skipped, so Entra has to accept the
// refresh token now. A session Microsoft has ended fails that at once.
//
// What the answer means is decided here, apart from the sign-in library, so it can be
// tested. The codes are Microsoft's, from its error reference, read 2026-11-24:
//
// - AADSTS50173: "The provided grant has expired due to it being revoked, a fresh auth
//   token is needed. The user might have changed or reset their password."
// - AADSTS50133 and AADSTS50132: "The session isn't valid due to password expiration or
//   recent password change."
// - AADSTS50057: "UserDisabled - The user account is disabled."
// - AADSTS50034: "UserAccountNotFound". Asked of the person's own organization, the
//   account is gone from it.
//
// Microsoft's pages do not say which of these a refresh gets after a revoke, a disabled
// account or a deleted one. The measurement in CAE-PLAN.md, step 0, shows it, and this
// list changes to match what is seen. Anything not listed changes nothing: no network,
// throttling, multifactor authentication due again (50078), a sign-in frequency policy
// (70043), a refresh token unused for too long (700082). The next request that needs a
// prompt asks for one, as before.

/// What Microsoft said when the app checked its own session.
public enum SessionStanding: Sendable, Equatable {
    /// A fresh token came back. Nothing changes.
    case current
    /// The session was revoked or the password changed. The session ends, as a sign-in
    /// that has expired ends: what the person set up stays.
    case ended
    /// The account is disabled. Everything the app holds is erased, as for an Intune wipe.
    case disabled
    /// The account no longer exists in its own organization. Erased, likewise.
    case removed
    /// No answer that means anything. Nothing changes.
    case unknown

    static let endedCodes: Set<String> = ["AADSTS50173", "AADSTS50133", "AADSTS50132"]
    static let disabledCodes: Set<String> = ["AADSTS50057"]
    static let removedCodes: Set<String> = ["AADSTS50034"]

    /// Reads a failed refresh by its `AADSTS` code, as `AuthFailureDetail` keeps it.
    public static func from(aadCode: String?) -> SessionStanding {
        guard let code = aadCode?.uppercased() else { return .unknown }
        if endedCodes.contains(code) { return .ended }
        if disabledCodes.contains(code) { return .disabled }
        if removedCodes.contains(code) { return .removed }
        return .unknown
    }

    /// Whether the session ends on this answer.
    public var endsTheSession: Bool {
        switch self {
        case .ended, .disabled, .removed: return true
        case .current, .unknown:          return false
        }
    }

    /// Whether the app erases what it holds, as for an Intune wipe.
    public var erases: Bool { self == .disabled || self == .removed }

    /// What the sign-in screen says afterwards.
    public var sentence: String? {
        switch self {
        case .ended:
            return "Microsoft ended this sign-in: its sessions were revoked or its password changed. Sign in again to carry on."
        case .disabled:
            return "Microsoft says this account is disabled. TenantKeep removed everything it held for it."
        case .removed:
            return "Microsoft says this account no longer exists in its organization. TenantKeep removed everything it held for it."
        case .current, .unknown:
            return nil
        }
    }
}

/// When the app asks.
public enum SessionCheck {
    /// Every ten minutes while the app is in front: about six non-interactive sign-ins an
    /// hour in the organization's sign-in log while it is open.
    public static let interval: TimeInterval = 600
    /// Coming back to the front this soon after a check does not ask again.
    public static let foregroundGap: TimeInterval = 120
}
