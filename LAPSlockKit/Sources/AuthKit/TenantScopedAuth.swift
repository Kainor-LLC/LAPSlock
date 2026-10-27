import Foundation

// An auth manager bound to one tenant, silent only. The background notification run hands
// one of these to a GraphClient per tenant, so every module service it builds asks for that
// tenant's tokens and nothing else, and the foreground session's operating tenant is never
// touched. Anything that would need a window, an interactive prompt, a claims challenge, a
// sign-in, is refused rather than attempted.

public struct TenantScopedAuth: AuthManaging {

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
        try await base.silentToken(scopes: scopes, tenantId: tenantId)
    }

    public func token(scopes: [String], claims: String?, allowInteractive: Bool) async throws -> String {
        guard claims == nil || claims?.isEmpty == true else { throw AuthError.interactionRequired }
        return try await base.silentToken(scopes: scopes, tenantId: tenantId)
    }

    public func silentToken(scopes: [String], tenantId: String) async throws -> String {
        guard tenantId.lowercased() == self.tenantId else { throw AuthError.tenantMismatch }
        return try await base.silentToken(scopes: scopes, tenantId: tenantId)
    }

    public func signIn() async throws -> AdminAccount {
        throw AuthError.interactionRequired
    }

    public func signOut(account: AdminAccount) async throws {}
}
