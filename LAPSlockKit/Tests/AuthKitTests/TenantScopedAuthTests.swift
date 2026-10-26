import XCTest
@testable import AuthKit

private actor RecordingBase: AuthManaging {
    private(set) var silentCalls: [(scopes: [String], tenantId: String)] = []
    private(set) var interactiveCalls = 0
    var currentAccount: AdminAccount? {
        AdminAccount(id: "a.t", tenantId: "11111111-1111-4111-8111-111111111111", username: "admin@example.com")
    }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        if allowInteractive { interactiveCalls += 1 }
        return "operating"
    }
    func silentToken(scopes: [String], tenantId: String) async throws -> String {
        silentCalls.append((scopes, tenantId))
        return "silent-" + tenantId
    }
    func signIn() async throws -> AdminAccount { throw AuthError.userCancelled }
    func signOut(account: AdminAccount) async throws {}
}

final class TenantScopedAuthTests: XCTestCase {

    private let tenant = "22222222-2222-4222-8222-222222222222"

    func test_everyTokenIsSilentForTheBoundTenantEvenWhenInteractiveIsAsked() async throws {
        let base = RecordingBase()
        let scoped = TenantScopedAuth(base: base, tenantId: tenant.uppercased())
        let token = try await scoped.token(scopes: ["X.Read"], allowInteractive: true)
        XCTAssertEqual(token, "silent-" + tenant)
        let calls = await base.silentCalls
        XCTAssertEqual(calls.first?.tenantId, tenant)
        let interactive = await base.interactiveCalls
        XCTAssertEqual(interactive, 0)
    }

    func test_aClaimsChallengeOrASignInIsRefused() async {
        let scoped = TenantScopedAuth(base: RecordingBase(), tenantId: tenant)
        do {
            _ = try await scoped.token(scopes: ["X"], claims: "{\"a\":1}", allowInteractive: true)
            XCTFail("expected refusal")
        } catch {
            XCTAssertEqual(error as? AuthError, .interactionRequired)
        }
        do {
            _ = try await scoped.signIn()
            XCTFail("expected refusal")
        } catch {
            XCTAssertEqual(error as? AuthError, .interactionRequired)
        }
    }

    func test_anotherTenantIsAMismatch() async {
        let scoped = TenantScopedAuth(base: RecordingBase(), tenantId: tenant)
        do {
            _ = try await scoped.silentToken(scopes: ["X"], tenantId: "33333333-3333-4333-8333-333333333333")
            XCTFail("expected mismatch")
        } catch {
            XCTAssertEqual(error as? AuthError, .tenantMismatch)
        }
    }

    func test_theDefaultSilentTokenFallsBackToTheOperatingTenantSilently() async throws {
        struct Plain: AuthManaging {
            var currentAccount: AdminAccount? { get async { nil } }
            func token(scopes: [String], allowInteractive: Bool) async throws -> String {
                allowInteractive ? "interactive" : "silent"
            }
            func signIn() async throws -> AdminAccount { throw AuthError.userCancelled }
            func signOut(account: AdminAccount) async throws {}
        }
        let token = try await Plain().silentToken(scopes: ["X"], tenantId: tenant)
        XCTAssertEqual(token, "silent")
    }
}
