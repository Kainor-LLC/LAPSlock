import Foundation

// The auth every service in one signed-in session is built on, bound to the tenant that
// session was built for. A tenant switch builds a new session; this is what keeps work the
// OLD session still has in flight from being served the NEW tenant's tokens.
//
// Without it, every service holds the one shared manager and asks it for "the operating
// tenant" at the moment it needs a token. A page, a role check or a write that started
// before a switch and asks after it would be answered for the customer just switched to.
//
// Silent requests name the session's tenant explicitly, so they are answered for that
// tenant whatever the manager is doing, including while it validates a switch. Anything
// that may show UI (consent, a claims challenge) runs only while the app is still operating
// in this session's tenant, and is refused if the tenant moved while it ran.

public struct SessionPinnedAuth: AuthManaging {

    private let base: any AuthManaging
    public let tenantId: String

    public init(base: any AuthManaging, tenantId: String) {
        self.base = base
        self.tenantId = tenantId.lowercased()
    }

    public var currentAccount: AdminAccount? {
        get async { await base.currentAccount }
    }

    public var operatingTenantId: String? { tenantId }

    public func objectId(inTenant tenantId: String) async -> String? {
        await base.objectId(inTenant: tenantId)
    }

    public func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        guard allowInteractive else { return try await silent(scopes) }
        return try await whileOperatingHere {
            try await base.token(scopes: scopes, allowInteractive: true)
        }
    }

    public func token(scopes: [String], claims: String?, allowInteractive: Bool) async throws -> String {
        guard let claims, !claims.isEmpty else {
            return try await token(scopes: scopes, allowInteractive: allowInteractive)
        }
        return try await whileOperatingHere {
            try await base.token(scopes: scopes, claims: claims, allowInteractive: allowInteractive)
        }
    }

    public func silentToken(scopes: [String], tenantId: String) async throws -> String {
        guard tenantId.lowercased() == self.tenantId else { throw AuthError.tenantMismatch }
        return try await base.silentToken(scopes: scopes, tenantId: self.tenantId)
    }

    public func signIn() async throws -> AdminAccount {
        throw AuthError.interactionRequired
    }

    public func signOut(account: AdminAccount) async throws {
        try await base.signOut(account: account)
    }

    /// A silent token for this session's tenant. Consent surfaces as interaction required,
    /// exactly as the base manager's silent-only path reports it, so callers that decide
    /// whether to offer "Request permission" see the same error either way.
    private func silent(_ scopes: [String]) async throws -> String {
        do {
            return try await base.silentToken(scopes: scopes, tenantId: tenantId)
        } catch AuthError.consentRequired {
            throw AuthError.interactionRequired
        }
    }

    /// Runs a token request that may present UI, refusing it unless the app is operating in
    /// this session's tenant before AND after: a switch that lands while a prompt is up must
    /// not hand this session a token for the tenant switched to.
    private func whileOperatingHere(_ body: () async throws -> String) async throws -> String {
        guard await base.operatingTenantId?.lowercased() == tenantId else { throw AuthError.tenantMismatch }
        let token = try await body()
        guard await base.operatingTenantId?.lowercased() == tenantId else { throw AuthError.tenantMismatch }
        return token
    }
}
