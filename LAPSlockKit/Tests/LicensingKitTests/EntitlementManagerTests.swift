import XCTest
import CryptoKit
@testable import LicensingKit

// MARK: - test support

/// Signs tokens with a throwaway key, standing in for the Function. Tokens are built at
/// runtime rather than embedded, because pre-push-scan.sh flags JWT-shaped strings.
struct TestTokenFactory {
    let key = P256.Signing.PrivateKey()
    let kid = "test-key"

    var keyring: EntitlementKeyring { EntitlementKeyring(keys: [kid: key.publicKey]) }
    var verifier: EntitlementVerifier { EntitlementVerifier(keyring: keyring) }

    func token(tenant: String, tier: String, issuedAt: Date, lifetime: TimeInterval = 30 * 86_400) -> String {
        let iat = Int(issuedAt.timeIntervalSince1970)
        let claims: [String: Any] = [
            "iss": "https://kainor.com/lapslock",
            "aud": "com.kainor.lapslock",
            "sub": tenant,
            "tier": tier,
            "iat": iat,
            "nbf": iat - 60,
            "exp": iat + Int(lifetime),
            "jti": UUID().uuidString,
        ]
        let header: [String: Any] = ["alg": "ES256", "typ": "JWT", "kid": kid]
        let h = Self.b64url(try! JSONSerialization.data(withJSONObject: header))
        let p = Self.b64url(try! JSONSerialization.data(withJSONObject: claims))
        let sig = try! key.signature(for: "\(h).\(p)".data(using: .ascii)!)
        return "\(h).\(p).\(Self.b64url(sig.rawRepresentation))"
    }

    static func b64url(_ d: Data) -> String {
        d.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// A scripted server. Each call consumes the next result; running out is a test bug.
final class FakeFetcher: EntitlementFetching, @unchecked Sendable {
    var script: [Result<EntitlementResponse, EntitlementFetchError>] = []
    private(set) var calls: [String] = []

    func fetch(tenantId: String) async throws -> EntitlementResponse {
        calls.append(tenantId)
        guard !script.isEmpty else {
            XCTFail("FakeFetcher called with nothing scripted — the client reached the network when it should not have")
            throw EntitlementFetchError.network
        }
        return try script.removeFirst().get()
    }

    func respond(token: String, refreshAfter: String? = nil) {
        script.append(.success(EntitlementResponse(version: 1, token: token, refreshAfter: refreshAfter)))
    }
    func fail(_ error: EntitlementFetchError) { script.append(.failure(error)) }
}

// MARK: - tests

@MainActor
final class EntitlementManagerTests: XCTestCase {

    private let tenantA = "4470dc21-a4b7-4729-a232-56d4c0eedf73"
    private let tenantB = "11111111-2222-3333-4444-555555555555"

    private var factory: TestTokenFactory!
    private var fetcher: FakeFetcher!
    private var store: InMemoryEntitlementStore!
    private var clock: ManualMeterClock!
    private var manager: EntitlementManager!

    override func setUp() {
        super.setUp()
        factory = TestTokenFactory()
        fetcher = FakeFetcher()
        store = InMemoryEntitlementStore()
        clock = ManualMeterClock(start: Date(timeIntervalSince1970: 1_788_321_139))
        manager = EntitlementManager(store: store, client: fetcher, verifier: factory.verifier, clock: clock)
    }

    private func token(_ tier: String, tenant: String? = nil, issuedAt: Date? = nil) -> String {
        factory.token(tenant: tenant ?? tenantA, tier: tier, issuedAt: issuedAt ?? clock.now)
    }

    private let day: TimeInterval = 86_400

    // MARK: 7.1 — a free install never calls

    func test_aFreshInstallNeverReachesTheNetwork() async {
        // The single most important property in this file. No activation, no call — not on
        // launch, not on refreshIfDue, not ever. FakeFetcher fails the test if touched.
        XCTAssertFalse(manager.isActivated)
        let outcome = await manager.refreshIfDue()
        XCTAssertNil(outcome)
        XCTAssertTrue(fetcher.calls.isEmpty)
        XCTAssertEqual(manager.state(signedInTenantId: tenantA), .free)
    }

    func test_refreshNowWithoutActivationDoesNothing() async {
        let outcome = await manager.refreshNow()
        XCTAssertNil(outcome)
        XCTAssertTrue(fetcher.calls.isEmpty)
    }

    // MARK: activation

    func test_activateFetchesOnceAndStoresAVerifiedToken() async {
        fetcher.respond(token: token("enterprise"))

        let outcome = await manager.activate(tenantId: tenantA)

        XCTAssertEqual(outcome, .updated(.enterprise))
        XCTAssertEqual(fetcher.calls, [tenantA])
        XCTAssertTrue(manager.isActivated)

        let state = manager.state(signedInTenantId: tenantA)
        XCTAssertEqual(state.tier, .enterprise)
        XCTAssertFalse(state.isInGrace)
        XCTAssertEqual(state.boundTenantId, tenantA)
    }

    func test_activateLowercasesTheTenant() async {
        fetcher.respond(token: token("pro"))
        _ = await manager.activate(tenantId: tenantA.uppercased())
        XCTAssertEqual(fetcher.calls, [tenantA])
        XCTAssertEqual(manager.state(signedInTenantId: tenantA).tier, .pro)
    }

    func test_aTokenForTheWrongTenantIsRejectedAndNotStored() async {
        // A server — or a man in the middle — hands back a valid token for someone else.
        fetcher.respond(token: token("enterprise", tenant: tenantB))

        let outcome = await manager.activate(tenantId: tenantA)

        XCTAssertEqual(outcome, .rejected(.subjectMismatch))
        XCTAssertNil(try store.load()?.token, "an unverifiable token must never reach the Keychain")
        XCTAssertEqual(manager.state(signedInTenantId: tenantA).tier, .free)
    }

    func test_anUnlicensedTenantGetsFreeAndIsStillActivated() async {
        // The server's 200-with-free. Activation is sticky, so a later renewal is picked up
        // on schedule without the user doing anything.
        fetcher.respond(token: token("free"))
        let outcome = await manager.activate(tenantId: tenantA)
        XCTAssertEqual(outcome, .updated(.free))
        XCTAssertTrue(manager.isActivated)
        XCTAssertEqual(manager.state(signedInTenantId: tenantA).tier, .free)
    }

    // MARK: 7.3 — schedule

    func test_refreshIsNotDueForAFreshToken() async {
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)

        clock.advance(2 * day)
        let outcome = await manager.refreshIfDue()

        XCTAssertNil(outcome)
        XCTAssertEqual(fetcher.calls.count, 1, "a fresh token must not trigger a refresh")
    }

    func test_refreshIsDueInsideSevenDaysOfExpiry() async {
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)

        clock.advance(24 * day)                      // 6 days left
        fetcher.respond(token: token("enterprise"))
        let outcome = await manager.refreshIfDue()

        XCTAssertEqual(outcome, .updated(.enterprise))
        XCTAssertEqual(fetcher.calls.count, 2)
    }

    func test_atMostOneAutomaticAttemptPerDay() async {
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)

        clock.advance(24 * day)
        fetcher.fail(.network)
        _ = await manager.refreshIfDue()
        XCTAssertEqual(fetcher.calls.count, 2)

        clock.advance(6 * 3600)                      // six hours later, still due, still blocked
        _ = await manager.refreshIfDue()
        XCTAssertEqual(fetcher.calls.count, 2, "failures count as attempts; no retry storm")

        clock.advance(19 * 3600)                     // past the 24 hour floor
        fetcher.respond(token: token("enterprise"))
        _ = await manager.refreshIfDue()
        XCTAssertEqual(fetcher.calls.count, 3)
    }

    func test_serverRefreshHintIsHonoured() async {
        let hint = clock.now.addingTimeInterval(3 * day)
        fetcher.respond(token: token("enterprise"), refreshAfter: iso(hint))
        _ = await manager.activate(tenantId: tenantA)

        clock.advance(2 * day)
        let before = await manager.refreshIfDue()
        XCTAssertNil(before, "before the hint: not due")

        clock.advance(1.5 * day)
        fetcher.respond(token: token("enterprise"))
        let after = await manager.refreshIfDue()
        XCTAssertEqual(after, .updated(.enterprise), "after the hint: due")
    }

    func test_serverRefreshHintIsClampedToAtLeastOneDay() async {
        // A server saying "refresh immediately" must not cause a storm. Section 4.1:
        // advisory, clamped to [iat + 1 day, exp].
        fetcher.respond(token: token("enterprise"), refreshAfter: iso(clock.now.addingTimeInterval(-3600)))
        _ = await manager.activate(tenantId: tenantA)

        clock.advance(25 * 3600)                     // past the 24h floor AND past iat + 1 day
        fetcher.respond(token: token("enterprise"))
        let outcome = await manager.refreshIfDue()
        XCTAssertEqual(outcome, .updated(.enterprise), "clamped floor is iat + 1 day, which has passed")
    }

    func test_serverRefreshHintCannotSuppressRefreshPastExpiry() async {
        // A hint in the year 2099 must not stop the 7-day-before-exp rule.
        fetcher.respond(token: token("enterprise"), refreshAfter: "2099-01-01T00:00:00Z")
        _ = await manager.activate(tenantId: tenantA)

        clock.advance(24 * day)
        fetcher.respond(token: token("enterprise"))
        let outcome = await manager.refreshIfDue()
        XCTAssertEqual(outcome, .updated(.enterprise))
    }

    // MARK: 7.5 — grace

    func test_anExpiredTokenIsKeptAliveOnlyByANetworkFailure() async {
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)

        clock.advance(25 * day)
        fetcher.fail(.network)
        let offline = await manager.refreshIfDue()
        XCTAssertEqual(offline, .offline)

        // Past expiry, still offline. Three days into grace: still enterprise.
        clock.advance(8 * day)
        let graced = manager.state(signedInTenantId: tenantA)
        XCTAssertEqual(graced.tier, .enterprise)
        XCTAssertTrue(graced.isInGrace)

        // Eight days past expiry: grace is over.
        clock.advance(5 * day)
        let over = manager.state(signedInTenantId: tenantA)
        XCTAssertEqual(over.tier, .free)
        XCTAssertFalse(over.isInGrace)
        if case .expired = over.lastFailure {} else { XCTFail("expected expiry, got \(String(describing: over.lastFailure))") }
    }

    func test_aServerErrorDoesNotEarnGrace() async {
        // The server ANSWERED. That is not "offline", and section 7.5 says so.
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)

        clock.advance(25 * day)
        fetcher.fail(.server(status: 503, code: "signing_unavailable"))
        let outcome = await manager.refreshIfDue()
        XCTAssertEqual(outcome, .serverError(status: 503))

        XCTAssertEqual(manager.state(signedInTenantId: tenantA).tier, .enterprise)

        clock.advance(6 * day)
        XCTAssertEqual(manager.state(signedInTenantId: tenantA).tier, .free)
    }

    func test_aServerErrorKeepsTheExistingToken() async {
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)

        clock.advance(day)
        fetcher.fail(.server(status: 500, code: nil))
        _ = await manager.refreshNow()

        XCTAssertEqual(manager.state(signedInTenantId: tenantA).tier, .enterprise)
    }

    func test_aHostileResponseCannotReplaceAGoodToken() async {
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)

        let other = TestTokenFactory()
        fetcher.respond(token: other.token(tenant: tenantA, tier: "enterprise", issuedAt: clock.now))
        clock.advance(day)
        let outcome = await manager.refreshNow()

        XCTAssertEqual(outcome, .rejected(.badSignature))
        XCTAssertEqual(manager.state(signedInTenantId: tenantA).tier, .enterprise, "the good token survives")
    }

    // MARK: 7.4 step 8 — tenant binding to the current sign-in

    func test_anEnterpriseLicenseDoesNotFollowTheUserToAnotherTenant() async {
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)

        let elsewhere = manager.state(signedInTenantId: tenantB)
        XCTAssertEqual(elsewhere.tier, .free)
        XCTAssertEqual(elsewhere.lastFailure, .subjectMismatch)

        // Signed out is not the licensed tenant either. Only msp is exempt from this.
        XCTAssertEqual(manager.state(signedInTenantId: nil).tier, .free)

        XCTAssertEqual(manager.state(signedInTenantId: tenantA).tier, .enterprise)
    }

    func test_anMSPLicenseDoesFollowTheUserAcrossTenants() async {
        fetcher.respond(token: token("msp"))
        _ = await manager.activate(tenantId: tenantA)

        XCTAssertEqual(manager.state(signedInTenantId: tenantB).tier, .msp)
        XCTAssertEqual(manager.state(signedInTenantId: nil).tier, .msp)
    }

    // MARK: 7.7 — StoreKit precedence

    func test_storeKitAloneIsSufficient() {
        XCTAssertTrue(manager.isPro(signedInTenantId: tenantA, storeKitEntitlementActive: true))
        XCTAssertFalse(manager.isPro(signedInTenantId: tenantA, storeKitEntitlementActive: false))
    }

    func test_aTenantLicenseAloneIsSufficient() async {
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)
        XCTAssertTrue(manager.isPro(signedInTenantId: tenantA, storeKitEntitlementActive: false))
    }

    // MARK: remove

    func test_removeReturnsToNeverCalling() async {
        fetcher.respond(token: token("enterprise"))
        _ = await manager.activate(tenantId: tenantA)

        manager.remove()

        XCTAssertFalse(manager.isActivated)
        XCTAssertEqual(manager.state(signedInTenantId: tenantA), .free)
        clock.advance(40 * day)
        let later = await manager.refreshIfDue()
        XCTAssertNil(later)
        XCTAssertEqual(fetcher.calls.count, 1, "after Remove, the network is never touched again")
    }

    // MARK: helpers

    private func iso(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: date)
    }
}
