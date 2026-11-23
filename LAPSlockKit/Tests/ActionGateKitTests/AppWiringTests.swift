import XCTest
import Foundation
@testable import ActionGateKit

/// The app target has no test bundle of its own, so the screens' models cannot be run
/// here. These tests read their source instead and hold a few shapes in place: each one
/// is a defect an outside review found in build 13, small to fix and easy to put back.
final class AppWiringTests: XCTestCase {

    private func appSource(_ name: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent("App/lapslock/lapslock/" + name), encoding: .utf8)
    }

    /// The text of one function: from its signature to the next declaration at the same depth.
    private func body(of signature: String, in source: String, file: StaticString = #filePath, line: UInt = #line) -> String {
        guard let start = source.range(of: signature) else {
            XCTFail(signature + " not found", file: file, line: line)
            return ""
        }
        let rest = source[start.upperBound...]
        let end = rest.range(of: "\n    }\n")?.upperBound ?? rest.endIndex
        return String(rest[..<end])
    }

    /// The first line of a function that is code, not a comment.
    private func firstStatement(of signature: String, in source: String, file: StaticString = #filePath, line: UInt = #line) -> String {
        // `body` starts after the signature, so its first line is the function's first.
        let lines = body(of: signature, in: source, file: file, line: line).split(separator: "\n")
        return lines.map { $0.trimmingCharacters(in: .whitespaces) }.first { !$0.isEmpty && !$0.hasPrefix("//") } ?? ""
    }

    // MARK: - one organization's data never under another's name

    /// The shell is keyed on the operating tenant and builds every module's model from the
    /// session it finds at that moment. If the tenant changes and the session follows after
    /// a suspension, the new tenant's shell is built on the old tenant's session and keeps
    /// it: customer A's devices under customer B's name.
    func testATenantSwitchChangesTheSessionAndTheTenantTogether() throws {
        let function = body(of: "func switchTenant(to tenantId: String?) async -> AuthError? {", in: try appSource("LAPSlockApp.swift"))
        let session = try XCTUnwrap(function.range(of: "liveSession = LiveSession("))
        let tenant = try XCTUnwrap(function.range(of: "operatingTenantId = tenant"))
        let between = session.lowerBound < tenant.lowerBound
            ? function[session.upperBound..<tenant.lowerBound]
            : function[tenant.upperBound..<session.lowerBound]
        XCTAssertFalse(between.contains("await"), "an await between the session and the tenant lets the shell render with one and not the other")
    }

    // MARK: - one confirmation, one send

    /// A sheet's own button stays on screen while the sheet closes, so a second tap reaches
    /// the model after the first has cleared the sheet's state. Each of these has to begin
    /// by checking that state; without it a group change was sent twice, and a retire or a
    /// wipe could be.
    func testAConfirmationSheetCannotSendTwice() throws {
        let device = firstStatement(of: "func destructiveConfirmed(_ kind: DeviceActionKind) async {", in: try appSource("DeviceActionsView.swift"))
        XCTAssertTrue(device.hasPrefix("guard destructive == kind"), device)
        let user = firstStatement(of: "func destructiveConfirmed(_ kind: UserActionKind) async {", in: try appSource("UserActionsView.swift"))
        XCTAssertTrue(user.hasPrefix("guard destructive == kind"), user)
        let groups = try appSource("GroupWritesView.swift")
        let reviewed = firstStatement(of: "func reviewed(_ pending: Pending) {", in: groups)
        XCTAssertTrue(reviewed.hasPrefix("guard reviewing?.id == pending.id"), reviewed)
        let typed = firstStatement(of: "func typedConfirmed(_ pending: Pending) async {", in: groups)
        XCTAssertTrue(typed.hasPrefix("guard typing?.id == pending.id"), typed)
    }

    /// Nothing sends while something is being sent.
    func testEverySendBeginsByCheckingNothingElseIsInFlight() throws {
        let device = try appSource("DeviceActionsView.swift")
        XCTAssertEqual(firstStatement(of: "func run(_ kind: DeviceActionKind) async {", in: device), "guard working == nil else { return }")
        let user = try appSource("UserActionsView.swift")
        XCTAssertEqual(firstStatement(of: "private func run(_ kind: UserActionKind) async {", in: user), "guard working == nil else { return }")
        XCTAssertEqual(firstStatement(of: "private func wipe(challenge: ClaimsChallenge?) async {", in: user), "guard working == nil else { return }")
        let groups = try appSource("GroupWritesView.swift")
        XCTAssertEqual(firstStatement(of: "private func send(_ pending: Pending) async {", in: groups), "guard working == nil else { return }")
    }

    // MARK: - the organization's switch

    /// Retire and wipe can be switched off by managed configuration. That has to hold on
    /// every screen that offers them: the leaver checklist once listed them by hand.
    func testRetireAndWipeAreOfferedOnlyThroughTheAllowedKinds() throws {
        let device = try appSource("DeviceActionsView.swift")
        XCTAssertTrue(firstStatement(of: "func tapped(_ kind: DeviceActionKind) {", in: device).hasPrefix("guard kinds.contains(kind)"))
        let user = try appSource("UserActionsView.swift")
        XCTAssertFalse(user.contains("ForEach([DeviceActionKind.retire, .wipe])"), "the leaver checklist lists retire and wipe by hand again")
    }

    // MARK: - a strict organization's Temporary Access Pass

    /// A strict policy lifts the pass to the destructive tier, and the service refuses a
    /// pass sent as an ordinary action, so that path has to hand it to the pass's own.
    func testAPassUnderAStrictPolicyTakesItsOwnPath() throws {
        let function = body(of: "func destructiveConfirmed(_ kind: UserActionKind) async {", in: try appSource("UserActionsView.swift"))
        XCTAssertTrue(function.contains("kind == .issueTemporaryAccessPass"))
        XCTAssertTrue(function.contains("issuePass(confirmedByFaceID: true)"))
    }

    // MARK: - a strict organization's approvals

    /// The phone asks for Face ID before a PIM decision under a strict policy. The watch
    /// cannot, so it has to hand the decision back to the phone instead of sending it.
    func testTheWatchHandsAStrictOrganizationsApprovalBackToThePhone() throws {
        // In the one function every watch handler calls, before anything is looked up or sent.
        let source = try appSource("WatchConnector.swift")
        let start = try XCTUnwrap(source.range(of: "static func decide(_ approvals: any ApprovalsProviding"))
        let send = try XCTUnwrap(source.range(of: "await approvals.decide(", range: start.upperBound..<source.endIndex))
        XCTAssertTrue(source[start.upperBound..<send.lowerBound].contains("confirmationLevel == .strict"))
        // And no handler reaches the service any other way.
        XCTAssertEqual(source.components(separatedBy: "approvals.decide(").count - 1, 1)
    }

    // MARK: - signing out

    /// A phone registered for an organization's Instant alerts keeps receiving them, and
    /// can read them, until it is unregistered. Signing out has to do that, before the
    /// sign-in it needs is gone.
    func testSigningOutTurnsInstantAlertsOffFirst() throws {
        let function = body(of: "func signOut() async {", in: try appSource("LAPSlockApp.swift"))
        let off = try XCTUnwrap(function.range(of: "RelayCoordinator.shared.turnOffForSignOut()"))
        let signOut = try XCTUnwrap(function.range(of: "auth.signOut(account: account)"))
        XCTAssertLessThan(off.lowerBound, signOut.lowerBound)
    }

    // MARK: - Instant alerts stay with the plan

    /// The relay recognizes Kainor's alert service by its own identity, so nothing on a
    /// server checks the plan any more. The phone does: without the plan the daily check-in
    /// stops, and the service drops the phone 30 days later. It must only stop checking in,
    /// never turn anything off, because the plan reads as lapsed for a moment at launch,
    /// before the App Store has answered, and turning off deletes the alert key.
    func testAPhoneWithoutThePlanStopsCheckingInAndNothingElse() throws {
        let relay = try appSource("RelaySettingsView.swift")
        let checkIn = body(of: "private func checkInIfDue() {", in: relay)
        XCTAssertTrue(checkIn.contains("guard planAllows,"), checkIn)

        let changed = body(of: "func planChanged(allows: Bool) {", in: relay)
        XCTAssertFalse(changed.contains("turnOff"), "a plan that reads as lapsed at launch must not delete the alert key")
        XCTAssertTrue(changed.contains("checkInIfDue()"), "a check-in that waited for the plan is made once it is confirmed")

        let apply = body(of: "private func apply(subscription: SubscriptionEntitlement) {", in: try appSource("LAPSlockApp.swift"))
        XCTAssertTrue(apply.contains("RelayCoordinator.shared.planChanged(allows: merged.isPro)"))

        // The gated check-in is the only registration nobody asked for.
        XCTAssertEqual(relay.components(separatedBy: "interactive: false").count - 1, 1)
    }

    // MARK: - a provider is told before finishing the update

    /// Finishing the update moves reads to the read-only app for every organization at
    /// once, and approval is per organization: a customer that has not approved it stops
    /// working on that device. Until the route is per organization, someone with customers
    /// is told so before the button.
    func testSomeoneWithCustomersIsWarnedBeforeFinishingTheUpdate() throws {
        let settings = try appSource("RegistrationSettings.swift")
        let warning = try XCTUnwrap(settings.range(of: "if registrations.customerCount > 0 {"))
        let button = try XCTUnwrap(settings.range(of: "message = await registrations.finishReadUpgrade()"))
        XCTAssertLessThan(warning.lowerBound, button.lowerBound, "the warning comes before the button it is about")
        XCTAssertTrue(try appSource("LAPSlockApp.swift").contains("customerCount: root.savedTenants.count"))
    }
}
