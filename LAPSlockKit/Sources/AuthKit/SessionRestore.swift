import Foundation

/// What a launch may restore, decided from how many people each registration's cache
/// holds and nothing else, so the decision can be tested without MSAL.
///
/// Two rules, both from the outside review of build 13:
///
/// - **The original registration is a fallback only for an install that never moved.**
///   It holds every write, so reads go through it only while the read registration's
///   cache is empty: an install from before the split that has not finished updating.
///   Once the read registration holds the person, a failure there (offline, a refresh
///   that fails, the read app disabled by the organization) ends at the sign-in screen.
///   It never falls back to tokens that can write.
/// - **A cache holding more than one person is not a session.** 1.0 had no same-account
///   check, so an administrator who once answered a prompt on a technician's phone can
///   still be in the original registration's cache. Restoring "the first" account could
///   sign the phone in as the wrong person, after the right one signed out. Nothing is
///   restored and every cache is emptied.
public enum SessionRestore: Equatable, Sendable {
    /// Restore through this registration, and through no other if it fails.
    case through(AppRegistration)
    /// Nothing to restore: show the sign-in screen.
    case signIn
    /// More than one person is cached: remove everyone, then show the sign-in screen.
    case clearThenSignIn

    public static func plan(readAccounts: Int, originalAccounts: Int) -> SessionRestore {
        if readAccounts > 1 { return .clearThenSignIn }
        if readAccounts == 1 { return .through(.read) }
        if originalAccounts > 1 { return .clearThenSignIn }
        if originalAccounts == 1 { return .through(.actions) }
        return .signIn
    }
}
