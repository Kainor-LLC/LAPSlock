import XCTest
import AuthKit
import ActionGateKit
import PrivilegedAccessKit
@testable import UserActionsKit

final class UserActionsTests: XCTestCase {

    private let jane = UserActionTarget(userId: "u-1", userPrincipalName: "jane.okafor@demo.example", displayName: "Jane Okafor")

    func test_requestsMatchTheReference() throws {
        let revoke = try XCTUnwrap(UserActionKind.revokeSessions.action(for: jane))
        XCTAssertEqual(revoke.request.method, .post)
        XCTAssertEqual(revoke.request.path, "/users/u-1/revokeSignInSessions")
        XCTAssertEqual(revoke.request.scopes, ["User.RevokeSessions.All"])

        let block = try XCTUnwrap(UserActionKind.blockSignIn.action(for: jane))
        XCTAssertEqual(block.request.method, .patch)
        XCTAssertEqual(block.request.path, "/users/u-1")
        XCTAssertEqual(block.request.template, "/users/{id}")
        XCTAssertEqual(block.request.scopes, ["User.EnableDisableAccount.All", "User.Read.All"])
        XCTAssertEqual(try JSONSerialization.jsonObject(with: block.request.body!) as? [String: Bool], ["accountEnabled": false])
        let allow = try XCTUnwrap(UserActionKind.unblockSignIn.action(for: jane))
        XCTAssertEqual(try JSONSerialization.jsonObject(with: allow.request.body!) as? [String: Bool], ["accountEnabled": true])

        let confirm = try XCTUnwrap(UserActionKind.confirmCompromised.action(for: jane))
        XCTAssertEqual(confirm.request.path, "/identityProtection/riskyUsers/confirmCompromised")
        XCTAssertEqual(try JSONSerialization.jsonObject(with: confirm.request.body!) as? [String: [String]], ["userIds": ["u-1"]])
        XCTAssertEqual(UserActionKind.dismissRisk.action(for: jane)?.request.path, "/identityProtection/riskyUsers/dismiss")
    }

    func test_tiersAndRoles() {
        XCTAssertEqual(UserActionKind.authenticationWipe.tier, .destructive)
        XCTAssertEqual(UserActionKind.revokeSessions.tier, .confirm)
        XCTAssertTrue(UserActionKind.confirmCompromised.requiredRoles.contains(UserActionRoles.securityAdministrator))
        XCTAssertTrue(UserActionKind.authenticationWipe.requiredRoles.contains(UserActionRoles.authenticationAdministrator))
        XCTAssertFalse(UserActionKind.revokeSessions.requiredRoles.contains(UserActionRoles.securityAdministrator))
    }

    func test_methodDeletePathsAndThePasswordIsKept() {
        let authenticator = AuthenticationMethodRef(id: "m1", odataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod")
        let action = authenticator.deleteAction(for: jane)
        XCTAssertEqual(action?.request.method, .delete)
        XCTAssertEqual(action?.request.path, "/users/u-1/authentication/microsoftAuthenticatorMethods/m1")
        XCTAssertEqual(action?.request.template, "/users/{id}/authentication/microsoftAuthenticatorMethods/{methodId}")
        XCTAssertEqual(action?.title, "Remove Microsoft Authenticator")
        let password = AuthenticationMethodRef(id: "pw", odataType: "#microsoft.graph.passwordAuthenticationMethod")
        XCTAssertNil(password.deleteAction(for: jane))
        XCTAssertEqual(password.label, "Password")
        let tomorrow = AuthenticationMethodRef(id: "x", odataType: "#microsoft.graph.somethingNewAuthenticationMethod")
        XCTAssertNil(tomorrow.collection, "an unknown type is kept, never guessed at")
        for type in ["phone", "fido2", "windowsHelloForBusiness", "email", "softwareOath", "temporaryAccessPass", "platformCredential"] {
            let ref = AuthenticationMethodRef(id: "i", odataType: "#microsoft.graph." + type + "AuthenticationMethod")
            XCTAssertEqual(ref.collection, type + "Methods", type)
        }
    }

    func test_theFreshMFAClaimsParse() {
        XCTAssertNotNil(ClaimsChallenge(json: UserActionClaims.freshMFA))
    }

    func test_scopesAskedTogether() {
        XCTAssertEqual(Set(UserActionScopes.module), ["User.RevokeSessions.All", "User.EnableDisableAccount.All", "User.Read.All",
                                                      "UserAuthenticationMethod.ReadWrite.All", "IdentityRiskyUser.ReadWrite.All",
                                                      "UserAuthMethod-TAP.ReadWrite.All"])
    }

    func test_copyHasNoEmDashesAndTheWipeSaysThePasswordStays() {
        for kind in UserActionKind.allCases {
            XCTAssertFalse(kind.confirmation.contains("\u{2014}"))
            XCTAssertFalse(kind.successCopy.contains("\u{2014}"))
        }
        XCTAssertTrue(UserActionKind.authenticationWipe.confirmation.contains("password stays"))
    }

    func test_demoWipeRemovesAllButThePassword() async {
        let demo = DemoUserActionsProvider(latency: .milliseconds(1))
        let result = await demo.authenticationWipe(jane, satisfying: nil)
        XCTAssertEqual(result.removed.count, 4)
        XCTAssertEqual(result.kept, ["Password"])
        let last = await demo.lastLogEntry(userId: "u-1")
        XCTAssertEqual(last?.actionTitle, "Remove all sign-in methods")
    }

    func test_leaverStepsInOrderWithActionsAndLinks() {
        XCTAssertEqual(LeaverStep.allCases.map(\.action), [.blockSignIn, .revokeSessions, .authenticationWipe, nil, nil, nil])
        XCTAssertNotNil(LeaverStep.mailbox.portal)
        XCTAssertNotNil(LeaverStep.privilegedAccess.portal)
        XCTAssertNil(LeaverStep.devices.portal)
        for step in LeaverStep.allCases { XCTAssertFalse(step.detail.contains("\u{2014}")) }
    }

    func test_leaverSummaryForTheTicket() {
        let text = LeaverSummary.text(
            person: jane,
            statuses: [(.blockSignIn, .done("Sign-in blocked.")), (.revokeSessions, .skipped), (.removeMethods, .failed("needs a role")),
                       (.devices, .done("")), (.mailbox, .pending), (.privilegedAccess, .pending)],
            devices: [("LT-FIELD-207", "wipe requested"), ("WS-ENG-041", "retire requested")],
            at: Date(timeIntervalSince1970: 1_800_000_000))
        XCTAssertTrue(text.hasPrefix("Leaver checklist for Jane Okafor (jane.okafor@demo.example)\nRecorded 2027-01-15 08:00Z"))
        XCTAssertTrue(text.contains("- Block sign-in: done (Sign-in blocked.)"))
        XCTAssertTrue(text.contains("- Revoke sessions: skipped"))
        XCTAssertTrue(text.contains("- Remove all sign-in methods: failed (needs a role)"))
        XCTAssertTrue(text.contains("    LT-FIELD-207: wipe requested"))
        XCTAssertTrue(text.contains("- Hand over the mailbox: not done"))
        XCTAssertTrue(text.hasSuffix("The tenant audit log is authoritative."))
    }

    func test_userDeviceEntraIdentity() {
        XCTAssertTrue(UserDevice(id: "1", deviceName: nil, operatingSystem: nil, managedDeviceOwnerType: nil, azureADDeviceId: "abc").hasEntraIdentity)
        XCTAssertFalse(UserDevice(id: "1", deviceName: nil, operatingSystem: nil, managedDeviceOwnerType: nil, azureADDeviceId: "00000000-0000-0000-0000-000000000000").hasEntraIdentity)
        XCTAssertFalse(UserDevice(id: "1", deviceName: nil, operatingSystem: nil, managedDeviceOwnerType: nil, azureADDeviceId: nil).hasEntraIdentity)
    }

    func testPersonSnapshotLines() {
        let snap = PersonSnapshot(accountEnabled: false, riskLevel: "high", methodCount: 1, deviceCount: 0)
        XCTAssertEqual(snap.signInLine, "Sign-in blocked")
        XCTAssertEqual(snap.riskLine, "User risk high")
        XCTAssertTrue(snap.isRisky)
        XCTAssertEqual(snap.methodsLine, "1 sign-in method besides the password")
        XCTAssertEqual(snap.devicesLine, "No devices")
        let unknown = PersonSnapshot()
        XCTAssertNil(unknown.signInLine)
        XCTAssertNil(unknown.riskLine)
        XCTAssertFalse(unknown.isRisky)
        XCTAssertEqual(PersonSnapshot(riskLevel: "none").riskLine, "No user risk")
    }

    func testSnapshotCountsMethodsWithoutThePassword() {
        XCTAssertEqual(PersonSnapshot.countMethods(DemoUserActionsProvider.demoMethods), 4)
    }

    func testDemoSnapshotFollowsBlockAndAllow() async {
        let demo = DemoUserActionsProvider(latency: .zero)
        let target = UserActionTarget(userId: "u1", userPrincipalName: "a@demo.example", displayName: "A")
        let before = await demo.snapshot(of: target)
        XCTAssertEqual(before.accountEnabled, true)
        _ = await demo.run(.blockSignIn, on: target)
        let blocked = await demo.snapshot(of: target)
        XCTAssertEqual(blocked.accountEnabled, false)
        _ = await demo.run(.unblockSignIn, on: target)
        let allowed = await demo.snapshot(of: target)
        XCTAssertEqual(allowed.accountEnabled, true)
    }
}
