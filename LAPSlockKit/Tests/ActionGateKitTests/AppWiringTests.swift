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

    /// An organization can turn the Mac menu bar app off on its Macs, or keep it to its own
    /// tenant, with a managed preference. Only a forced value counts, the check comes
    /// before anyone is let in, and it is made again while the app runs.
    func testTheMacAppObeysItsOrganizationsSwitch() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let mac = try String(contentsOf: root.appendingPathComponent("App/lapslock/TenantKeepMac/MacModel.swift"), encoding: .utf8)
        XCTAssertTrue(mac.contains("CFPreferencesAppValueIsForced(key as CFString, app) ? CFPreferencesCopyAppValue(key as CFString, app) : nil"),
                      "a value somebody wrote with defaults is not the organization's")
        XCTAssertTrue(mac.contains("static let disabledKey = \"menuBar.disabled\""))
        XCTAssertTrue(mac.contains("static let tenantPinKey = \"tenant.pin\""))

        let signIn = body(of: "func signIn() async {", in: mac)
        let refused = try XCTUnwrap(signIn.range(of: "guard !policy.disabled else { turnedOffByOrganization = true; return }"))
        let asked = try XCTUnwrap(signIn.range(of: "try await auth.signIn()"))
        XCTAssertLessThan(refused.lowerBound, asked.lowerBound, "a switched-off app does not ask anyone to sign in")
        XCTAssertTrue(signIn.contains("await enter(auth, signed, policy: policy)"), "the tenant pin is checked before going live")
        XCTAssertFalse(signIn.contains("goLive("), "sign-in never goes live around the pin")

        let enter = body(of: "private func enter(_ auth: MSALAuthManager, _ signed: AdminAccount, policy: Policy) async {", in: mac)
        XCTAssertTrue(enter.contains("guard policy.allows(tenant: signed.tenantId) else {"))
        XCTAssertTrue(enter.contains("try? await auth.signOut(account: signed)"))
        XCTAssertTrue(body(of: "func refreshStatus() async {", in: mac).contains("await applyPolicy()"), "read again while it runs")
        XCTAssertEqual(mac.components(separatedBy: "goLive(auth, ").count - 1, 1, "one way in, and it is through the pin")
    }

    // MARK: - a provider's customers move one at a time

    /// Under an Intune app protection policy, every notification the app or its extension
    /// shows goes through the one rule for how much may be shown, and the watch, which the
    /// policy cannot reach, is sent nothing and answered nothing.
    func testAPolicysLimitsReachNotificationsAndTheWatch() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let ext = try String(contentsOf: root.appendingPathComponent("App/lapslock/RelayNotificationService/NotificationService.swift"), encoding: .utf8)
        XCTAssertTrue(ext.contains("let detail = NotificationDetail.current()"))
        XCTAssertFalse(ext.contains("content.title = alert.title"), "the extension shows an alert's words only through the rule")
        XCTAssertFalse(ext.contains("import IntuneMAMSwift"), "the extension does not link Microsoft's SDK")

        XCTAssertTrue(body(of: "static func post(_ alert: PlannedAlert) async {", in: try appSource("AlertsRunner.swift"))
            .contains("guard let shown = NotificationDetail.current().shown(title: alert.title, body: alert.body) else { return }"))
        XCTAssertTrue(try appSource("DigestAlerts.swift").contains("guard NotificationDetail.current() != .none else { return 0 }"))
        let relay = try appSource("RelaySettingsView.swift")
        XCTAssertTrue(body(of: "func turnOn() async {", in: relay).contains("guard NotificationDetail.current() != .none else {"),
                      "a phone that may show nothing is not registered for alerts")
        XCTAssertFalse(relay.contains("content.title = alert.title"))

        let watch = try appSource("WatchConnector.swift")
        XCTAssertTrue(body(of: "private func pushOnce() async {", in: watch).contains("if let withheld = AppProtection.shared.watchWithheld {"))
        XCTAssertTrue(body(of: "fileprivate func handle(_ request: WatchRequest) async -> WatchReply {", in: watch)
            .contains("if let withheld = AppProtection.shared.watchWithheld {"))
        XCTAssertFalse(watch.contains("content.body = body"))

        let wrapper = try appSource("AppProtection.swift")
        XCTAssertTrue(wrapper.contains("guard policyInForce, !ManagedConfigStore.shared.config.watchAllowed else { return nil }"))
        for line in ["case .allow:        detail = .full", "case .blockOrgData: detail = .withoutDetails",
                     "case .block:        detail = .none", "@unknown default:   detail = .withoutDetails"] {
            XCTAssertTrue(wrapper.contains(line), line)
        }
        XCTAssertTrue(try appSource("ManagedConfigStore.swift").contains("appChannel: UserDefaults.standard.dictionary(forKey: ManagedConfiguration.appChannelDefaultsKey)"))
    }

    /// Intune can order an organization's data off the device. Everything goes, in an order
    /// that works: the alert service is told while a token can still say so, then every
    /// sign-in, then the rest of the Keychain, then files and settings. No Microsoft
    /// sign-out page is shown, because nothing in a wipe may wait on a person.
    func testAnOrganizationsWipeRemovesEverythingAndWaitsOnNobody() throws {
        let app = try appSource("LAPSlockApp.swift")
        let erase = body(of: "func eraseForOrganization() async -> Bool {", in: app)
        let alerts = try XCTUnwrap(erase.range(of: "await RelayCoordinator.shared.turnOff()"))
        let signIns = try XCTUnwrap(erase.range(of: "await auth?.forgetEveryone()"))
        XCTAssertLessThan(alerts.lowerBound, signIns.lowerBound, "unregistering needs the sign-in that goes next")
        for store in ["RevealMeters.live.resetLedger()", "Entitlements.live.remove()", "try TenantStores.live.clear()",
                      "try AlertsRunner.preferencesStore.clear()", "await FileShiftLog.shared.clearAll()",
                      "savedSearches.clear()", "AppProtection.eraseFilesAndSettings()", "endSession()"] {
            XCTAssertTrue(erase.contains(store), store)
        }
        XCTAssertFalse(erase.contains("auth.signOut("), "Microsoft's sign-out page waits on a person")
        XCTAssertFalse(erase.contains("signingOut("), "the SDK ends the enrolment itself during a wipe")
        XCTAssertTrue(body(of: "func signOut() async {", in: app).contains("endSession()"), "sign-out and a wipe end the session the same way")
        XCTAssertTrue(app.contains("AppProtection.shared.wipe = { [weak self] _ in"))

        // Microsoft's SDK is answered only once the data is gone, and never by blocking the
        // main thread on work the main thread must do.
        let wrapper = try appSource("AppProtection.swift")
        let ordered = body(of: "func wipeData(forAccountId accountId: String) -> Bool {", in: wrapper)
        XCTAssertTrue(ordered.contains("guard !Thread.isMainThread else {"))
        XCTAssertTrue(ordered.contains("finished.wait(timeout: .now() + 60) == .success && complete.value"))
        // Its own settings are not the app's to delete, nor its folders, nor the record iOS
        // keeps in every container. Counting those as failures made a complete wipe report
        // itself incomplete on a phone.
        XCTAssertTrue(wrapper.contains("where !Self.isMicrosofts(key)"))
        XCTAssertTrue(wrapper.contains("for url in doomed where Self.isOurs(url.lastPathComponent) {"))
        XCTAssertTrue(wrapper.contains("!name.hasPrefix(\".IntuneMAM\") && !name.hasPrefix(\".com.apple.\")"))

        // MSAL's removal leaves its record of who was signed in. The group the cache has to
        // itself is emptied after it, and that group is the one MSAL is told to use.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let msal = try String(contentsOf: root.appendingPathComponent("LAPSlockKit/Sources/AuthKitMSAL/MSALAuthManager.swift"), encoding: .utf8)
        let forget = body(of: "public func forgetEveryone() {", in: msal)
        let removed = try XCTUnwrap(forget.range(of: "removeAccounts(except: nil, keepingPrimary: false)"))
        let emptied = try XCTUnwrap(forget.range(of: "emptyCacheGroup()"))
        XCTAssertLessThan(removed.lowerBound, emptied.lowerBound)
        XCTAssertTrue(msal.contains("pcaConfig.cacheConfig.keychainSharingGroup = Bundle.main.bundleIdentifier ?? \"com.kainor.lapslock\""))
        XCTAssertTrue(msal.contains("let own = \".\" + (Bundle.main.bundleIdentifier ?? \"com.kainor.lapslock\")"))
    }

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

    // MARK: - the organization's switch for Privileged Access (second review, R2-3)

    /// `modules.disabled: privilegedAccess` hides the module and its Approvals tab on the
    /// phone. The watch listed requests and sent approve, deny and activate anyway, from a
    /// background launch too, and the device screen and Settings still offered activation.
    func testPrivilegedAccessOffReachesTheWatchAndEveryActivationButton() throws {
        let watch = try appSource("WatchConnector.swift")
        XCTAssertTrue(watch.contains("ManagedConfigStore.read().isDisabled(AppModule.privilegedAccess.rawValue)"),
                      "read when asked, as the strict confirmation is")
        // The one function both the foreground and the background handlers decide through.
        let deciding = body(of: "known: [PendingApproval]) async -> WatchReply {", in: watch)
        let refusal = try XCTUnwrap(deciding.range(of: "if privilegedAccessOff {"))
        let sent = try XCTUnwrap(deciding.range(of: "await approvals.decide("))
        XCTAssertLessThan(refusal.lowerBound, sent.lowerBound, "refused before anything is sent")
        XCTAssertTrue(watch.contains("""
            activate: { id, reason, hours in
                            guard !privilegedAccessOff else {
            """), "activation refused first")
        XCTAssertTrue(watch.contains("async let pending: [PendingApproval]? = privilegedOff ? [] : (try? approvals.pending())"))
        XCTAssertTrue(watch.contains("async let roles: [ActiveRole]? = privilegedOff ? nil : (try? gate.activeRoles())"))
        XCTAssertTrue(watch.contains("async let eligible = activationEnabled && !privilegedOff ? (try? privileged.eligibleAccess()) : nil"))

        let app = try appSource("LAPSlockApp.swift")
        XCTAssertEqual(app.components(separatedBy: "privilegedSheet: AppModule.privilegedAccess.isEnabled ? {").count - 1, 2,
                       "the device screen's sheet and Settings' sheet")
        XCTAssertFalse(app.contains("privilegedSheet: {"), "no sheet offered unconditionally")
        XCTAssertTrue(app.contains("requestPrivilegedConsent: AppModule.privilegedAccess.isEnabled"))
    }

    // MARK: - the session check (CAE-PLAN.md, decisions 2 and 3)

    /// The app asks Microsoft whether the session still stands on coming back to the front
    /// and every ten minutes while there, and acts on the answer.
    func testTheSessionCheckRunsInFrontAndActsOnTheAnswer() throws {
        let app = try appSource("LAPSlockApp.swift")
        let scene = try XCTUnwrap(app.range(of: "private struct SceneChanges: ViewModifier {"))
        let changes = String(app[scene.lowerBound...])
        XCTAssertTrue(changes.contains("root.cameToFront()"))
        XCTAssertTrue(changes.contains("root.wentToBackground()"))

        let loop = body(of: "func cameToFront() {", in: app)
        XCTAssertTrue(loop.contains("checkSession(unlessWithin: SessionCheck.foregroundGap)"))
        XCTAssertTrue(loop.contains("Task.sleep(for: .seconds(SessionCheck.interval))"))

        let check = body(of: "private func checkSession(unlessWithin gap: TimeInterval) async {", in: app)
        XCTAssertTrue(check.contains("guard case .live(let account) = mode"), "never in the demo or signed out")
        XCTAssertTrue(check.contains("guard isSignedIn(as: account) else { return }"), "the answer is for the person it was asked about")
        // The switch for the measurement is in debug builds only.
        let skip = try XCTUnwrap(check.range(of: "-LAPSlockNoSessionCheck"))
        let debug = try XCTUnwrap(check.range(of: "#if DEBUG"))
        XCTAssertLessThan(debug.lowerBound, skip.lowerBound)

        let act = body(of: "private func act(on standing: SessionStanding, for account: AdminAccount?) async {", in: app)
        XCTAssertTrue(act.contains("_ = await eraseForOrganization()"), "a disabled or deleted account is erased")
        XCTAssertTrue(act.contains("await auth?.dropSession()"))
        XCTAssertTrue(act.contains("endSession(forgetting: false)"), "a revoke leaves what is on disk")
        XCTAssertTrue(act.contains("signInError = standing.sentence"))

        // At a launch, the restore asks, and its answer is acted on the same way.
        let restore = body(of: "func restoreSession() async {", in: app)
        XCTAssertTrue(restore.contains("if let standing = await auth.lastSessionStanding, standing.endsTheSession {"))
        XCTAssertTrue(restore.contains("await act(on: standing, for: nil)"))
        // A session that ends for any reason stops the loop.
        XCTAssertTrue(body(of: "private func endSession(forgetting: Bool = true) {", in: app).contains("sessionCheck?.cancel()"))
    }

    // MARK: - Instant alerts at sign-out (second review, R2-9, R2-17, R2-18)

    func testInstantAlertsEndWithTheSessionThatTurnedThemOn() throws {
        let app = try appSource("LAPSlockApp.swift")
        let signOut = body(of: "func signOut() async {", in: app)
        let live = try XCTUnwrap(signOut.range(of: "if case .live(let account) = mode, let auth {"))
        let off = try XCTUnwrap(signOut.range(of: "await RelayCoordinator.shared.turnOffForSignOut()"))
        XCTAssertLessThan(live.lowerBound, off.lowerBound, "leaving the demo touches no real alert key (R2-17)")
        // Each session says whose it is, after a restore and after a sign-in.
        XCTAssertEqual(app.components(separatedBy: "await RelayCoordinator.shared.sessionStarted(for: account.id)").count - 1, 2)
        XCTAssertTrue(app.contains("person: { await session.auth.currentAccount?.id })"))

        let relay = try appSource("RelaySettingsView.swift")
        let signOutOff = body(of: "func turnOffForSignOut() async {", in: relay)
        XCTAssertTrue(signOutOff.contains("guard phone.isOn || status != .off else { return }"), "the key decides, not the status (R2-9)")
        let started = body(of: "func sessionStarted(for person: String) async {", in: relay)
        XCTAssertTrue(started.contains("if began != who { await turnOff() }"))
        let turnOff = body(of: "func turnOff() async {", in: relay)
        XCTAssertTrue(turnOff.contains("await Self.within(seconds: 8,"), "the token wait has a limit of its own (R2-18)")
        XCTAssertTrue(turnOff.contains("UserDefaults.standard.removeObject(forKey: Self.personKey)"))
    }

    /// Second review, R2-22: a pass lost on the network may exist, and the log says so.
    func testAPassLostOnTheNetworkIsLogged() throws {
        let view = try appSource("UserActionsView.swift")
        let issue = body(of: "private func issuePass(confirmedByFaceID: Bool = false) async {", in: view)
        let lastCatch = try XCTUnwrap(issue.range(of: "} catch {", options: .backwards))
        let tail = issue[lastCatch.upperBound...]
        XCTAssertTrue(tail.contains("await provider.logOffGate(.issueTemporaryAccessPass, on: target, outcome: .failed(.transport(status: 0)))"))
        XCTAssertTrue(tail.contains("errorMessage = Self.passNotKnown"))
        XCTAssertTrue(issue.contains("outcome: Self.passOutcome(for: error)") || issue.contains("let outcome = Self.passOutcome(for: error)"))
    }

    // MARK: - countdowns and lookups (second review, R2-24, R2-28)

    func testEveryCountdownIsCancelledFromTheRootOnTheWayToTheBackground() throws {
        let app = try appSource("LAPSlockApp.swift")
        let scene = try XCTUnwrap(app.range(of: "private struct SceneChanges: ViewModifier {"))
        let changes = String(app[scene.lowerBound...])
        let background = try XCTUnwrap(changes.range(of: "if phase == .background {"))
        let cancel = try XCTUnwrap(changes.range(of: "Task { await PendingActions.shared.cancelAll() }"))
        XCTAssertLessThan(background.lowerBound, cancel.lowerBound)
    }

    func testALookupThatFailedOrWasCutOffIsNotTakenAsAnAnswer() throws {
        let people = try appSource("PeopleView.swift")
        XCTAssertTrue(people.contains("do { found = try await provider.searchUsers(prefix: query) } catch { found = nil }"))
        XCTAssertFalse(people.contains("(try? await provider.searchUsers(prefix: query)) ?? []"), "a failure is not nobody")
        XCTAssertTrue(people.contains("} else if let problem = directory.lookupProblem {"))
        for (name, source) in [("PeopleView.swift", people), ("DeviceListView.swift", try appSource("DeviceListView.swift"))] {
            let refilter = body(of: "private func refilter() {", in: source)
            let reset = try XCTUnwrap(refilter.range(of: "if isLookingUp { lookedUpQuery = nil }"), name)
            let cancel = try XCTUnwrap(refilter.range(of: "lookupTask?.cancel()"), name)
            XCTAssertLessThan(reset.lowerBound, cancel.lowerBound, name)
        }
    }

    // MARK: - the plan and the check-in (second review, R2-8, R2-7)

    func testNothingIsSwitchedOffBeforeTheAppStoreHasAnswered() throws {
        let app = try appSource("LAPSlockApp.swift")
        XCTAssertTrue(app.contains("if case .live = mode, !merged.isPro, subscriptions.hasAnswered { AlertsRunner.disableAll() }"))
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let store = try String(contentsOf: root.appendingPathComponent("Sources/SubscriptionKit/SubscriptionStore.swift"), encoding: .utf8)
        let refresh = body(of: "public func refreshEntitlement() async {", in: store)
        let answered = try XCTUnwrap(refresh.range(of: "hasAnswered = true"))
        let told = try XCTUnwrap(refresh.range(of: "if first, fresh == entitlement { onEntitlementChange?(fresh) }"))
        XCTAssertLessThan(answered.lowerBound, told.lowerBound, "the app is told after the store says it has answered")
    }

    func testEveryCheckInMovesTheReminderOn() throws {
        let relay = try appSource("RelaySettingsView.swift")
        XCTAssertTrue(relay.contains("static let reminderAfter: TimeInterval = 25 * 86_400"))
        XCTAssertTrue(body(of: "func turnOff() async {", in: relay).contains("removePendingNotificationRequests(withIdentifiers: [Self.reminderId])"))
        let registered = try XCTUnwrap(relay.range(of: "UserDefaults.standard.set(Date(), forKey: Self.checkInKey)"))
        let reminded = try XCTUnwrap(relay.range(of: "remindBeforeTheServiceForgets()", range: registered.upperBound..<relay.endIndex))
        XCTAssertLessThan(registered.lowerBound, reminded.lowerBound)
    }

    /// The Mac reads the iPhone app's `modules.disabled` too: with Privileged Access off it
    /// shows no Roles view and activates nothing (R2-3's class, found on the way).
    func testTheMacMenuBarAppObeysPrivilegedAccessOff() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let mac = try String(contentsOf: root.appendingPathComponent("App/lapslock/TenantKeepMac/MacModel.swift"), encoding: .utf8)
        XCTAssertTrue(mac.contains("static let modulesDisabledKey = \"modules.disabled\""))
        let activate = body(of: "func activate(_ access: EligibleAccess, justification: String, duration: String) async -> String {", in: mac)
        let refused = try XCTUnwrap(activate.range(of: "guard !Policy.current().privilegedAccessOff else { return Policy.privilegedAccessOffMessage }"))
        let token = try XCTUnwrap(activate.range(of: "auth?.token(scopes: [access.activateScope]"))
        XCTAssertLessThan(refused.lowerBound, token.lowerBound, "refused before any sign-in or request")
        XCTAssertTrue(body(of: "func loadRoles() async {", in: mac).contains("guard !Policy.current().privilegedAccessOff else {"))
        let view = try String(contentsOf: root.appendingPathComponent("App/lapslock/TenantKeepMac/MacMenuView.swift"), encoding: .utf8)
        XCTAssertTrue(view.contains("let shown = Tab.allCases.filter { $0 != .roles || !model.privilegedAccessOff }"))
    }

    /// The scripted reveal for screenshots opens a credential, so it runs on demo data only.
    func testTheScriptedRevealRunsOnDemoDataOnly() throws {
        let detail = try appSource("DeviceDetailView.swift")
        XCTAssertTrue(detail.contains("if ScreenshotRoute.requestedInDemo == \"reveal\" { await model.reveal() }"))
        XCTAssertFalse(detail.contains("ScreenshotRoute.requested == \"reveal\""))
    }

    /// The organization's switches reach Instant alerts: Notifications off keeps them off, and
    /// the break-glass accounts it names go to the service as the background check watches them.
    func testTheOrganizationsSettingsReachInstantAlerts() throws {
        let relay = try appSource("RelaySettingsView.swift")
        XCTAssertTrue(relay.contains("static var turnedOffByOrganization: Bool { ManagedConfigStore.read().isDisabled(\"notifications\") }"))
        XCTAssertTrue(body(of: "func turnOn() async {", in: relay).contains("guard !Self.turnedOffByOrganization else {"))
        XCTAssertTrue(body(of: "func registerIfOn() {", in: relay).contains("Task { await turnOff() }"))
        XCTAssertTrue(relay.contains("guard planAllows, !Self.turnedOffByOrganization,"))
        let app = try appSource("LAPSlockApp.swift")
        XCTAssertTrue(app.contains("return TenantAlertPreferences.watchedUPNs("))
        let runner = try appSource("AlertsRunner.swift")
        XCTAssertTrue(runner.contains("own.breakGlassUPNs = TenantAlertPreferences.watchedUPNs("))
    }
}
