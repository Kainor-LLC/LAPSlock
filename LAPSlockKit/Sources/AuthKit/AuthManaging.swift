import Foundation

// Build Spec §4 + §3.1. The token-provider seam.
//
// CredentialKit and InventoryKit depend on THIS protocol, never on MSAL directly.
// Why this matters:
//   1. Testability — tests inject a fake AuthManaging, so CredentialKit is verifiable
//      with zero Microsoft dependencies (Spec §13 unit tests).
//   2. BYO registration (§9) — the concrete MSAL implementation is configured with a
//      client ID + authority that can come from the vendor default OR the customer's
//      own app registration, with no change to callers.
//   3. Isolation — keeps the MSAL binary out of the credential module's link graph.

/// A resolved, signed-in administrator account, scoped to exactly one tenant.
public struct AdminAccount: Sendable, Equatable, Identifiable {
    public let id: String            // MSAL account identifier (home account id)
    public let tenantId: String      // authoritative tenant, resolved from the ID token (§3.3)
    public let username: String      // UPN, for display only
    public init(id: String, tenantId: String, username: String) {
        self.id = id
        self.tenantId = tenantId
        self.username = username
    }
}

// Equatable so tests can assert on a specific failure rather than merely that something
// threw. `underlying(String)` is the only payload and String is Equatable, so this is
// synthesised — and it matters for the §3.3 guard, whose whole job is to throw ONE specific
// error and not some other one that happens to also fail the call.
public enum AuthError: Error, Sendable, Equatable {
    case noAccount                   // nobody signed in
    case interactionRequired         // silent failed; caller must allow interactive
    case consentRequired             // scope not yet consented (incremental consent, §4)
    case userCancelled
    case tenantMismatch              // token tenant != expected account tenant (§3.3 guard)
    case underlying(String)          // MSAL/other, message only — never contains a secret
}

/// The contract CredentialKit/InventoryKit use to obtain access tokens.
/// Implemented by MSALAuthManager (in AuthKit) for production and by a fake in tests.
public protocol AuthManaging: Sendable {
    /// The currently signed-in account, if any.
    var currentAccount: AdminAccount? { get async }

    /// Acquire an access token for `scopes`, scoped to the current account's tenant authority.
    /// - allowInteractive: if true, may present UI on `interactionRequired`/`consentRequired`;
    ///   if false, silent-only (throws instead of showing UI). Metadata calls pass false;
    ///   the reveal path passes true so first-use consent for DeviceLocalCredential.Read.All
    ///   can be prompted (§4 incremental consent).
    /// - Returns: a bearer access token string. Callers must not log or persist it.
    func token(scopes: [String], allowInteractive: Bool) async throws -> String

    /// Interactive account selection sign-in (uses /common or /organizations, §2.1).
    @discardableResult
    func signIn() async throws -> AdminAccount

    /// Sign out: clears MSAL cache for the account. The data layer teardown (§7) is the
    /// caller's responsibility and is triggered separately so tenant caches are wiped too.
    func signOut(account: AdminAccount) async throws
}
