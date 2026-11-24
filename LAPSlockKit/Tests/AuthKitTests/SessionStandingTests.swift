import XCTest
@testable import AuthKit

/// The session check (LAPSlock-internal CAE-PLAN.md, decisions 2 and 3): what Microsoft's
/// answer to a forced refresh means, and that the sign-in manager asks the way the plan
/// says. The manager's MSAL calls cannot run on a Mac, so its half is read as text.
final class SessionStandingTests: XCTestCase {

    // MARK: - what each answer means

    func testARevokeOrAChangedPasswordEndsTheSession() {
        for code in ["AADSTS50173", "AADSTS50133", "AADSTS50132", "aadsts50173"] {
            XCTAssertEqual(SessionStanding.from(aadCode: code), .ended, code)
        }
    }

    func testADisabledAccountIsErased() {
        XCTAssertEqual(SessionStanding.from(aadCode: "AADSTS50057"), .disabled)
        XCTAssertTrue(SessionStanding.disabled.erases)
    }

    func testAnAccountGoneFromItsOrganizationIsErased() {
        XCTAssertEqual(SessionStanding.from(aadCode: "AADSTS50034"), .removed)
        XCTAssertTrue(SessionStanding.removed.erases)
    }

    /// Ordinary reasons a refresh needs a person change nothing: the next request that
    /// needs a prompt asks for one, as it always did.
    func testEverythingElseChangesNothing() {
        let ordinary = ["AADSTS50078", "AADSTS70043", "AADSTS700082", "AADSTS70008", "AADSTS50089",
                        "AADSTS50076", "AADSTS53003", "AADSTS65001", "AADSTS50158"]
        for code in ordinary {
            XCTAssertEqual(SessionStanding.from(aadCode: code), .unknown, code)
        }
        XCTAssertEqual(SessionStanding.from(aadCode: nil), .unknown, "no code: offline, throttled, cancelled")
        XCTAssertFalse(SessionStanding.unknown.endsTheSession)
        XCTAssertFalse(SessionStanding.current.endsTheSession)
    }

    func testOnlyAnAccountThatIsGoneOrDisabledIsErased() {
        XCTAssertFalse(SessionStanding.ended.erases, "a changed password is ordinary")
        XCTAssertTrue(SessionStanding.ended.endsTheSession)
        XCTAssertFalse(SessionStanding.current.erases)
        XCTAssertFalse(SessionStanding.unknown.erases)
    }

    func testTheSignInScreenSaysWhy() throws {
        for standing in [SessionStanding.ended, .disabled, .removed] {
            let sentence = try XCTUnwrap(standing.sentence)
            XCTAssertFalse(sentence.contains("\u{2014}"))
            XCTAssertFalse(sentence.contains("!"))
            XCTAssertTrue(sentence.hasPrefix("Microsoft"), sentence)
        }
        XCTAssertTrue(try XCTUnwrap(SessionStanding.ended.sentence).contains("Sign in again"))
        XCTAssertNil(SessionStanding.current.sentence)
        XCTAssertNil(SessionStanding.unknown.sentence)
    }

    /// Connor's numbers: every ten minutes in front, about six sign-ins an hour.
    func testHowOftenItAsks() {
        XCTAssertEqual(SessionCheck.interval, 600)
        XCTAssertEqual(SessionCheck.foregroundGap, 120)
    }

    // MARK: - the sign-in manager asks as the plan says

    private func managerSource() throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent("Sources/AuthKitMSAL/MSALAuthManager.swift"), encoding: .utf8)
    }

    private func function(_ signature: String, in source: String) throws -> Substring {
        let start = try XCTUnwrap(source.range(of: signature), signature + " not found")
        let rest = source[start.upperBound...]
        let end = rest.range(of: "\n    }\n")?.upperBound ?? rest.endIndex
        return rest[..<end]
    }

    func testTheCheckSkipsTheCachedTokenInThePersonsOwnOrganizationAndNeverPrompts() throws {
        let check = try function("public func checkSession() async -> SessionStanding {", in: try managerSource())
        XCTAssertTrue(check.contains("silent.forceRefresh = true"))
        XCTAssertTrue(check.contains("TenantPin(expected: account.tenantId)"), "the home organization, not the one on screen")
        XCTAssertTrue(check.contains("application(for: primaryRegistration)"), "the registration the session lives on")
        XCTAssertTrue(check.contains("acquireSilent("))
        XCTAssertFalse(check.contains("acquireInteractive"))
        XCTAssertFalse(check.contains("interactiveToken"))
        XCTAssertTrue(check.contains("SessionStanding.from(aadCode:"))
    }

    /// A session Microsoft has ended must not come back at the next launch on a token
    /// cached before the end.
    func testARestoreAsksMicrosoftBeforeItTrustsTheCachedToken() throws {
        let restore = try function("private func restore(through registration: AppRegistration) async -> AdminAccount? {", in: try managerSource())
        let asked = try XCTUnwrap(restore.range(of: "if await checkSession().endsTheSession {"))
        let cached = try XCTUnwrap(restore.range(of: "_ = try await token(scopes: Self.baseScopes, allowInteractive: false)"))
        XCTAssertLessThan(asked.lowerBound, cached.lowerBound)
    }

    /// Ending the session for Microsoft removes nothing: that is what keeps the waiting
    /// customers and the person's set-up for their next sign-in.
    func testDroppingTheSessionRemovesNothing() throws {
        let drop = try function("public func dropSession() {", in: try managerSource())
        XCTAssertFalse(drop.contains("removeAccounts"))
        XCTAssertFalse(drop.contains("readRoutes"))
        XCTAssertFalse(drop.contains("forgetReadRoutes"))
        XCTAssertFalse(drop.contains("emptyCacheGroup"))
        XCTAssertTrue(drop.contains("pinnedAccount = nil"))
    }
}
