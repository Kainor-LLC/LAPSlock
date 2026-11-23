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

    /// iOS gives an app no push address until it may show notifications, and calls neither
    /// registration callback (Apple Developer Forums, thread 799635). Turning Instant
    /// alerts on used to register without asking. On a phone that had never been asked it
    /// timed out with "Apple didn't give this phone a push address", and a phone that was
    /// already registered stayed silent while the screen said On.
    func testTurningOnInstantAlertsAsksToNotifyBeforeAnythingElse() throws {
        let relay = try appSource("RelaySettingsView.swift")
        let turnOn = body(of: "func turnOn() async {", in: relay)
        let asked = try XCTUnwrap(turnOn.range(of: "guard await AlertsRunner.requestAuthorization() else {"))
        let key = try XCTUnwrap(turnOn.range(of: "try phone.turnOn(environment: Self.environment)"))
        let push = try XCTUnwrap(turnOn.range(of: "UIApplication.shared.registerForRemoteNotifications()"))
        XCTAssertLessThan(asked.lowerBound, key.lowerBound, "no key is made for a phone that cannot be alerted")
        XCTAssertLessThan(asked.lowerBound, push.lowerBound)
        XCTAssertTrue(turnOn.contains("status = .problem(Self.notificationsOffMessage)"))

        // A phone that is registered and silent says so, with the way to fix it.
        XCTAssertTrue(relay.contains("if !relay.notificationsAllowed {"))
        XCTAssertTrue(relay.contains("UIApplication.openNotificationSettingsURLString"))
        XCTAssertTrue(relay.contains(".task { await relay.refreshPermission() }"))
    }

    /// The push address kept with the alert key outlives the app: the Keychain survives a
    /// reinstall, and iOS gives the reinstalled app a new address. The service is only
    /// ever given one that Apple handed over in this launch.
    func testTheAlertServiceIsOnlyGivenAnAddressAppleGaveThisLaunch() throws {
        let relay = try appSource("RelaySettingsView.swift")
        XCTAssertTrue(body(of: "func registered(token: Data) {", in: relay).contains("addressConfirmed = true"))
        XCTAssertEqual(relay.components(separatedBy: "addressConfirmed = true").count - 1, 1, "only Apple's answer confirms it")
        XCTAssertTrue(body(of: "func update() async {", in: relay)
            .contains("guard let setup, addressConfirmed, let code = try? phone.pairingCode() else { return await turnOn() }"))
        XCTAssertTrue(body(of: "private func checkInIfDue() {", in: relay).contains("isRegistered, addressConfirmed,"))
        XCTAssertTrue(body(of: "private func pairingCode() async -> PairingCode? {", in: relay)
            .contains("if addressConfirmed, let code = try? phone.pairingCode() { return code }"))
        XCTAssertTrue(body(of: "func turnOff() async {", in: relay).contains("addressConfirmed = false"))
    }

    /// An address is registered under the push service of the build that was given it.
    /// The service's name kept with the alert key survives a reinstall, so a phone that
    /// had run an Xcode build registered a TestFlight build's address as sandbox, Apple
    /// refused every alert for it, and the phone said it was registered.
    func testAnAddressIsRegisteredUnderTheRunningBuildsPushService() throws {
        let relay = try appSource("RelaySettingsView.swift")
        let registered = body(of: "func registered(token: Data) {", in: relay)
        XCTAssertTrue(registered.contains("phone.setDeviceToken(token, environment: Self.environment)"), registered)
        XCTAssertTrue(registered.contains("if changed { UserDefaults.standard.removeObject(forKey: Self.checkInKey) }"),
                      "a changed address or service is registered again at once")
    }

    /// The Mac menu bar app activates a role through the app the organization approved for
    /// it. It used to sign in to the separate Role Activation app whatever was chosen, so
    /// an organization that had approved only TenantKeep Actions was asked for a second
    /// approval (AUTH-5). The decision itself is `ApprovalProbe.choose`, tested in AuthKit.
    func testTheMacAppReadsTheOrganizationsChoiceBeforeItActivates() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let mac = try String(contentsOf: root.appendingPathComponent("App/lapslock/TenantKeepMac/MacModel.swift"), encoding: .utf8)

        let activate = body(of: "func activate(_ access: EligibleAccess, justification: String, duration: String) async -> String {", in: mac)
        let settled = try XCTUnwrap(activate.range(of: "await settleActivationRoute()"))
        let asked = try XCTUnwrap(activate.range(of: "auth?.token(scopes: [access.activateScope], allowInteractive: true)"))
        XCTAssertLessThan(settled.lowerBound, asked.lowerBound, "the route is read before the sign-in is asked for")

        let settle = body(of: "private func settleActivationRoute() async {", in: mac)
        XCTAssertTrue(settle.contains("approvedScopes(for: [.roleActivation, .actions])"))
        XCTAssertTrue(settle.contains("ApprovalProbe.choose(for: .roleActivation, approved: approved)"))
        XCTAssertTrue(settle.contains("guard mode == .live, account?.tenantId == tenant else { return }"),
                      "an answer read for one person is not applied to the next")
        XCTAssertTrue(settle.contains("case .none:           return"), "an unreadable record is read again, not remembered")
        // A new session reads it again.
        XCTAssertEqual(mac.components(separatedBy: "activationRouteSettled = false").count - 1, 3)
    }

    // MARK: - a provider's customers move one at a time

    /// Approval is per organization, so the move to the read-only app is too. Finishing
    /// the update hands the sign-in manager the customers saved on the device, which it
    /// records as still on the earlier sign-in, and the screen says none of them stops.
    func testFinishingTheUpdateLeavesEachCustomerWhereItWas() throws {
        let app = try appSource("LAPSlockApp.swift")
        let finish = body(of: "func finishReadUpgrade() async -> String? {", in: app)
        XCTAssertTrue(finish.contains("auth.moveReadsToReadRegistration(customers: savedTenants.map(\\.tenantId))"), finish)
        XCTAssertTrue(finish.contains("await refreshUpdateWaiting(from: auth)"))

        let settings = try appSource("RegistrationSettings.swift")
        let told = try XCTUnwrap(settings.range(of: "if registrations.customerCount > 0 {"))
        let button = try XCTUnwrap(settings.range(of: "message = await registrations.finishReadUpgrade()"))
        XCTAssertLessThan(told.lowerBound, button.lowerBound, "a provider is told before the button")
        XCTAssertTrue(settings.contains("none of them stops working when you finish here"))
        XCTAssertFalse(settings.contains("stops working on this device until it does"), "the warning from when the move was all at once")
        XCTAssertTrue(app.contains("customerCount: root.savedTenants.count"))
    }

    /// What is waiting is read again after everything that can change it, and a switch
    /// reads it before it decides where the customer's writes start.
    func testWhatIsWaitingIsReadPerOrganization() throws {
        let app = try appSource("LAPSlockApp.swift")
        let switching = body(of: "func switchTenant(to tenantId: String?) async -> AuthError? {", in: app)
        let read = try XCTUnwrap(switching.range(of: "await refreshUpdateWaiting(from: session.auth)"))
        let writes = try XCTUnwrap(switching.range(of: "WriteRoutes.startingRoute(for: tenant, beforeTheSplit: readsThroughOriginalRegistration)"))
        XCTAssertLessThan(read.lowerBound, writes.lowerBound)
        XCTAssertTrue(body(of: "func restoreSession() async {", in: app).contains("await refreshUpdateWaiting(from: auth)"))

        // The approval link is for the organization Finish updating signs in to: the
        // customer's when the customer is what waits, otherwise the person's own.
        XCTAssertTrue(app.contains("readConsentURL: root.updateWaiting == .thisCustomer ? root.consentURL(for: .read) : root.consentURL,"))
        // A customer removed from the device leaves the list of those still waiting.
        XCTAssertTrue(body(of: "func forgetTenant(_ tenantId: String) {", in: app).contains("await auth.forgetReadRoute(for: tenantId)"))
    }
}
