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

    /// The directory object id of the signed-in user — the `oid` claim.
    ///
    /// **NOT the same as `id`, and the difference matters.** MSAL's account identifier is
    /// `{oid}.{utid}`, so anything that needs a *principal* — PIM self-activation, for one —
    /// must use this and not `id`. Passing the MSAL identifier where Graph wants a principal
    /// targets a directory object that does not exist, and the request fails in a way that
    /// looks like a permissions problem rather than a wrong-id problem.
    ///
    /// Optional and defaulted so existing conformances and test doubles keep compiling.
    public let objectId: String?

    public init(id: String, tenantId: String, username: String, objectId: String? = nil) {
        self.id = id
        self.tenantId = tenantId
        self.username = username
        self.objectId = objectId
    }
}

// Equatable so tests can assert on a specific failure rather than merely that something
// threw. `underlying(String)` is the only payload and String is Equatable, so this is
// synthesised — and it matters for the §3.3 guard, whose whole job is to throw ONE specific
// error and not some other one that happens to also fail the call.
public extension AuthManaging {

    /// Default: ignore the challenge and fall through.
    ///
    /// Graph refuses privileged operations — PIM self-activation above all — unless MFA was
    /// satisfied in the CURRENT session, and says so with a claims challenge rather than a
    /// plain 403. The only legitimate response is to re-authenticate carrying those claims.
    /// There is no way to satisfy it locally: a device biometric gate is not an identity
    /// assertion, and treating one as though it were would be security theatre.
    ///
    /// This default exists so a token provider that never sees a challenge — every test
    /// double, and the demo path — keeps working unchanged. `MSALAuthManager` overrides it.
    func token(scopes: [String], claims: String?, allowInteractive: Bool) async throws -> String {
        try await token(scopes: scopes, allowInteractive: allowInteractive)
    }
}

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

    /// Acquire a token while satisfying a claims challenge.
    ///
    /// **A protocol REQUIREMENT, not merely an extension method, and that distinction is
    /// load-bearing.** A method that lives only in a protocol extension is statically
    /// dispatched, so calling it through `any AuthManaging` runs the extension's version
    /// even when the concrete type has its own — which would mean the claims were silently
    /// discarded and every privileged operation failed forever with "not authorized". It
    /// carries a default implementation below, so existing conformances and test doubles
    /// still satisfy it without change.
    func token(scopes: [String], claims: String?, allowInteractive: Bool) async throws -> String

    /// Interactive account selection sign-in (uses /common or /organizations, §2.1).
    @discardableResult
    func signIn() async throws -> AdminAccount

    /// Sign out: clears MSAL cache for the account. The data layer teardown (§7) is the
    /// caller's responsibility and is triggered separately so tenant caches are wiped too.
    func signOut(account: AdminAccount) async throws
}
