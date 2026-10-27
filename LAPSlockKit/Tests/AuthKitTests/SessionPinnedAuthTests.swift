import XCTest
@testable import AuthKit

/// A base manager whose operating tenant can move, including in the middle of an
/// interactive request, which is the case the session pin exists for.
private actor MovingBase: AuthManaging {
    var operating: String?
    var switchDuringInteractive: String?
    var silentFailure: AuthError?
    private(set) var silentTenants: [String] = []
    private(set) var interactiveCalls = 0

    init(operating: String) { self.operating = operating }

    func move(to tenant: String) { operating = tenant }
    func moveDuringInteractive(to tenant: String) { switchDuringInteractive = tenant }
    func failSilent(with error: AuthError) { silentFailure = error }

    var currentAccount: AdminAccount? {
        AdminAccount(id: "a.t", tenantId: "11111111-1111-4111-8111-111111111111", username: "admin@example.com")
    }
    var operatingTenantId: String? { operating }

    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        interactiveCalls += 1
        if let next = switchDuringInteractive { operating = next }
        return "interactive-" + (operating ?? "")
    }
    func token(scopes: [String], claims: String?, allowInteractive: Bool) async throws -> String {
        interactiveCalls += 1
        return "claims-" + (operating ?? "")
    }
    func silentToken(scopes: [String], tenantId: String) async throws -> String {
        silentTenants.append(tenantId)
        if let silentFailure { throw silentFailure }
        return "silent-" + tenantId
    }
    func signIn() async throws -> AdminAccount { throw AuthError.userCancelled }
    func signOut(account: AdminAccount) async throws {}
}

final class SessionPinnedAuthTests: XCTestCase {

    private let home = "11111111-1111-4111-8111-111111111111"
    private let customer = "22222222-2222-4222-8222-222222222222"

    func test_silentRequestsNameTheSessionTenantEvenAfterASwitch() async throws {
        let base = MovingBase(operating: home)
        let pinned = SessionPinnedAuth(base: base, tenantId: home.uppercased())
        await base.move(to: customer)
        let token = try await pinned.token(scopes: ["X.Read"], allowInteractive: false)
        XCTAssertEqual(token, "silent-" + home)
        let tenants = await base.silentTenants
        XCTAssertEqual(tenants, [home])
    }

    func test_silentConsentIsReportedAsInteractionRequired() async {
        let base = MovingBase(operating: home)
        await base.failSilent(with: .consentRequired)
        let pinned = SessionPinnedAuth(base: base, tenantId: home)
        do {
            _ = try await pinned.token(scopes: ["X"], allowInteractive: false)
            XCTFail("expected interaction required")
        } catch {
            XCTAssertEqual(error as? AuthError, .interactionRequired)
        }
    }

    func test_anInteractiveRequestRunsWhileOperatingHere() async throws {
        let base = MovingBase(operating: home)
        let pinned = SessionPinnedAuth(base: base, tenantId: home)
        let token = try await pinned.token(scopes: ["X"], allowInteractive: true)
        XCTAssertEqual(token, "interactive-" + home)
    }

    func test_anInteractiveRequestAfterASwitchIsRefusedWithoutAsking() async {
        let base = MovingBase(operating: customer)
        let pinned = SessionPinnedAuth(base: base, tenantId: home)
        do {
            _ = try await pinned.token(scopes: ["X"], allowInteractive: true)
            XCTFail("expected mismatch")
        } catch {
            XCTAssertEqual(error as? AuthError, .tenantMismatch)
        }
        let calls = await base.interactiveCalls
        XCTAssertEqual(calls, 0)
    }

    func test_aSwitchThatLandsDuringAPromptDiscardsTheToken() async {
        let base = MovingBase(operating: home)
        await base.moveDuringInteractive(to: customer)
        let pinned = SessionPinnedAuth(base: base, tenantId: home)
        do {
            _ = try await pinned.token(scopes: ["X"], allowInteractive: true)
            XCTFail("expected mismatch")
        } catch {
            XCTAssertEqual(error as? AuthError, .tenantMismatch)
        }
    }

    func test_aClaimsChallengeIsAnsweredOnlyWhileOperatingHere() async throws {
        let base = MovingBase(operating: home)
        let pinned = SessionPinnedAuth(base: base, tenantId: home)
        let token = try await pinned.token(scopes: ["X"], claims: "{\"a\":1}", allowInteractive: true)
        XCTAssertEqual(token, "claims-" + home)
        await base.move(to: customer)
        do {
            _ = try await pinned.token(scopes: ["X"], claims: "{\"a\":1}", allowInteractive: true)
            XCTFail("expected mismatch")
        } catch {
            XCTAssertEqual(error as? AuthError, .tenantMismatch)
        }
    }

    func test_noClaimsIsAnOrdinaryRequest() async throws {
        let base = MovingBase(operating: customer)
        let pinned = SessionPinnedAuth(base: base, tenantId: home)
        let token = try await pinned.token(scopes: ["X"], claims: "", allowInteractive: false)
        XCTAssertEqual(token, "silent-" + home)
    }

    func test_theOperatingTenantIsTheSessionsAndAnotherTenantIsAMismatch() async {
        let pinned = SessionPinnedAuth(base: MovingBase(operating: customer), tenantId: home.uppercased())
        let operating = await pinned.operatingTenantId
        XCTAssertEqual(operating, home)
        do {
            _ = try await pinned.silentToken(scopes: ["X"], tenantId: customer)
            XCTFail("expected mismatch")
        } catch {
            XCTAssertEqual(error as? AuthError, .tenantMismatch)
        }
    }

    func test_aSessionCannotSignIn() async {
        let pinned = SessionPinnedAuth(base: MovingBase(operating: home), tenantId: home)
        do {
            _ = try await pinned.signIn()
            XCTFail("expected refusal")
        } catch {
            XCTAssertEqual(error as? AuthError, .interactionRequired)
        }
    }

    func test_theDefaultOperatingTenantIsTheAccountsOwn() async {
        struct Plain: AuthManaging {
            var currentAccount: AdminAccount? {
                get async { AdminAccount(id: "a", tenantId: "home-tenant", username: "u") }
            }
            func token(scopes: [String], allowInteractive: Bool) async throws -> String { "t" }
            func signIn() async throws -> AdminAccount { throw AuthError.userCancelled }
            func signOut(account: AdminAccount) async throws {}
        }
        let operating = await Plain().operatingTenantId
        XCTAssertEqual(operating, "home-tenant")
    }
}

final class ObjectIdInTenantTests: XCTestCase {
    func test_theDefaultIsTheHomeObjectIdAndWrappersPassThrough() async {
        struct Home: AuthManaging {
            var currentAccount: AdminAccount? {
                get async { AdminAccount(id: "a", tenantId: "home", username: "u", objectId: "home-oid") }
            }
            func token(scopes: [String], allowInteractive: Bool) async throws -> String { "t" }
            func signIn() async throws -> AdminAccount { throw AuthError.userCancelled }
            func signOut(account: AdminAccount) async throws {}
        }
        struct Guest: AuthManaging {
            var currentAccount: AdminAccount? { get async { nil } }
            func objectId(inTenant tenantId: String) async -> String? { "oid-in-" + tenantId }
            func token(scopes: [String], allowInteractive: Bool) async throws -> String { "t" }
            func signIn() async throws -> AdminAccount { throw AuthError.userCancelled }
            func signOut(account: AdminAccount) async throws {}
        }
        let home = await Home().objectId(inTenant: "anything")
        XCTAssertEqual(home, "home-oid")
        let pinned = await SessionPinnedAuth(base: Guest(), tenantId: "c").objectId(inTenant: "c")
        XCTAssertEqual(pinned, "oid-in-c")
        let scoped = await TenantScopedAuth(base: Guest(), tenantId: "c").objectId(inTenant: "c")
        XCTAssertEqual(scoped, "oid-in-c")
    }
}
