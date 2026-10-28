import SwiftUI
import ActionGateKit
import NotificationsKit
import ManagedConfigKit
import AuthKit
import GroupWritesKit
import CredentialKit
import LicensingKit
import SubscriptionKit
import StoreKit

// Settings. The first page holds what has to be found without looking: the organization's
// managed settings, the plan and its purchase, and Sign out. Everything else is a page of
// its own, which keeps its own state and reads it when it opens.
//
// Where this lives: a gear in the device list toolbar, opening a sheet. Not on the device
// list itself, that screen's job is find-a-device-fast, and controls there compete with
// the search field and get tapped by accident.

/// Persisted preferences. Plain UserDefaults: none of this is sensitive, and it must
/// survive a relaunch.
@MainActor
@Observable
final class AppSettings {
    static let shared = AppSettings()

    /// Whether device actions are enabled: sync, restart, lock, locate and BitLocker key
    /// rotation. Gating every write on one toggle is the whole point: customers who leave
    /// it off never see a "modify your devices" permission on their consent screen.
    /// Replaces the BitLocker rotation toggle; an install that had rotation on carries over.
    var deviceActionsEnabled: Bool {
        didSet { UserDefaults.standard.set(deviceActionsEnabled, forKey: Keys.deviceActions) }
    }

    /// Whether TenantKeep may request just-in-time activation of a PIM-eligible role.
    ///
    /// Same reasoning as rotation, and a heavier ask. `RoleAssignmentSchedule.ReadWrite.Directory`
    /// lets the app request a privilege escalation, which reads worse on a consent screen
    /// than reading a password does. Off by default: a customer who never turns it on never
    /// sees that permission requested at all.
    var privilegedActivationEnabled: Bool {
        didSet { UserDefaults.standard.set(privilegedActivationEnabled, forKey: Keys.privilegedActivation) }
    }

    /// Whether to look up primary users' display names in Entra when Intune leaves the
    /// field empty. The UPN is the default;
    /// names are optional because they cost a permission, `User.ReadBasic.All` on the
    /// consent screen, that a customer should choose, not inherit.
    var userNamesEnabled: Bool {
        didSet { UserDefaults.standard.set(userNamesEnabled, forKey: Keys.userNames) }
    }

    /// Whether the whole app is held behind Face ID, separate from the per-reveal gate.
    ///
    /// What it protects is NOT a credential, those already have their own gate. It is the
    /// device inventory: hostnames, primary users, compliance state. That is reconnaissance
    /// for an entire tenant, and a borrowed unlocked phone should not hand it over.
    var appLockEnabled: Bool {
        didSet { UserDefaults.standard.set(appLockEnabled, forKey: Keys.appLock) }
    }

    /// The organization can require the app lock; then it is on whatever the toggle says.
    var appLockEffective: Bool { appLockEnabled || ManagedConfigStore.shared.config.appLockRequired }

    /// The organization can switch device actions off; then they are off whatever the
    /// toggle says, and the toggle is not offered.
    var deviceActionsEffective: Bool { deviceActionsEnabled && !ManagedConfigStore.shared.config.isDisabled("deviceActions") }

    /// Whether user actions are enabled: revoke, block, the authentication wipe, a
    /// Temporary Access Pass, risk. Off by default; the organization can force it off.
    var userActionsEnabled: Bool {
        didSet { UserDefaults.standard.set(userActionsEnabled, forKey: Keys.userActions) }
    }

    var userActionsEffective: Bool { userActionsEnabled && !ManagedConfigStore.shared.config.isDisabled("userActions") }

    /// Whether group membership changes are enabled. Off by default; the organization can
    /// force them off, or set the scope to none.
    var groupWritesEnabled: Bool {
        didSet { UserDefaults.standard.set(groupWritesEnabled, forKey: Keys.groupWrites) }
    }

    /// Tagged or all, for a deployment without managed configuration. Tagged by default.
    var groupWriteMode: GroupWriteMode {
        didSet { UserDefaults.standard.set(groupWriteMode.rawValue, forKey: Keys.groupWriteMode) }
    }

    /// The rules in force: the organization's when its configuration sets the scope, this
    /// device's otherwise. The administrative unit and prefix come only from configuration.
    var groupWritePolicy: GroupWritePolicy {
        let config = ManagedConfigStore.shared.config
        let mode: GroupWriteMode
        if config.appliedKeys.contains("groupWrite.scope") {
            mode = GroupWriteMode(rawValue: config.groupWriteScope.rawValue) ?? .tagged
        } else {
            mode = groupWriteMode == .all ? .all : .tagged
        }
        return GroupWritePolicy(mode: mode, prefix: config.groupWritePrefix, administrativeUnit: config.groupWriteAdministrativeUnit)
    }

    var groupWritesEffective: Bool {
        groupWritesEnabled && !ManagedConfigStore.shared.config.isDisabled("groupWrites") && groupWritePolicy.mode != .none
    }

    var appearance: AppearancePreference {
        didSet {
            UserDefaults.standard.set(appearance.rawValue, forKey: Keys.appearance)
            AppearancePreference.applyToAllWindows(appearance)
        }
    }

    private enum Keys {
        static let rotation = "settings.bitLockerRotationEnabled"
        static let deviceActions = "settings.deviceActionsEnabled"
        static let userActions = "settings.userActionsEnabled"
        static let groupWrites = "settings.groupWritesEnabled"
        static let groupWriteMode = "settings.groupWriteMode"
        static let privilegedActivation = "settings.privilegedActivationEnabled"
        static let userNames = "settings.userNamesEnabled"
        static let appLock = "settings.appLockEnabled"
        static let appearance = "settings.appearance"
    }

    private init() {
        let defaults = UserDefaults.standard
        self.userActionsEnabled = defaults.bool(forKey: Keys.userActions)
        self.groupWritesEnabled = defaults.bool(forKey: Keys.groupWrites)
        self.groupWriteMode = GroupWriteMode(rawValue: defaults.string(forKey: Keys.groupWriteMode) ?? "") ?? .tagged
        self.deviceActionsEnabled = defaults.object(forKey: Keys.deviceActions) as? Bool
            ?? defaults.bool(forKey: Keys.rotation)
        self.privilegedActivationEnabled = UserDefaults.standard.bool(forKey: Keys.privilegedActivation)
        self.userNamesEnabled = UserDefaults.standard.bool(forKey: Keys.userNames)
        self.appLockEnabled = UserDefaults.standard.bool(forKey: Keys.appLock)
        let raw = UserDefaults.standard.string(forKey: Keys.appearance) ?? AppearancePreference.system.rawValue
        self.appearance = AppearancePreference(rawValue: raw) ?? .system
    }
}

/// Three-way, defaulting to System. A two-way light/dark toggle would force a choice the
/// OS already made correctly for most people, and it breaks Sunrise/Sunset schedules.
enum AppearancePreference: String, CaseIterable, Identifiable {
    case system, light, dark
    var id: String { rawValue }

    var label: String {
        switch self {
        case .system: return "System"
        case .light:  return "Light"
        case .dark:   return "Dark"
        }
    }

    var interfaceStyle: UIUserInterfaceStyle {
        switch self {
        case .system: return .unspecified
        case .light:  return .light
        case .dark:   return .dark
        }
    }

    /// Applied to every window rather than through `preferredColorScheme`: a sheet already
    /// open did not follow a change back to System that way, and stayed dark. A window's
    /// override reaches everything it presents, and `.unspecified` returns to the system.
    @MainActor
    static func applyToAllWindows(_ preference: AppearancePreference) {
        for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
            for window in scene.windows { window.overrideUserInterfaceStyle = preference.interfaceStyle }
        }
    }
}

// MARK: - view

struct SettingsView: View {
    @Bindable var settings: AppSettings
    /// Requests consent for the two write scopes. Returns nil on success, or a message.
    /// Injected so the sheet doesn't need to know about MSAL.
    let requestDeviceActionsConsent: () async -> String?
    /// Requests consent for the user action scopes. Nil in demo.
    var requestUserActionsConsent: (() async -> String?)? = nil
    /// Requests consent for the group membership scopes. Nil in demo.
    var requestGroupWritesConsent: (() async -> String?)? = nil
    let isDemo: Bool
    /// The shift log, for export and clear. Nil when signed out.
    var shiftLog: (any ShiftLogging)? = nil
    /// The tenant whose lines the export shows.
    var shiftLogTenantId: String? = nil
    /// The organizations the Notifications section offers a switch for, and where the
    /// choices are kept. Empty when signed out.
    var notificationTenants: [NotificationTenant] = []
    var notificationsStore: (any NotificationPreferencesStoring)? = nil
    /// Tenant id of the signed-in account, offered as an opt-in field in the report.
    let tenantId: String?
    /// Free-tier meter, shared with the list and detail screens so all three read one
    /// ledger. Optional and defaulted so existing call sites and previews still compile.
    var meter: RevealMeter? = nil
    var isPro: Bool = false
    /// Tenant-keyed organization license. Live mode only: nil in demo and in previews, which
    /// is also what keeps a demo install from ever having a path to Kainor's server.
    var entitlement: EntitlementManager? = nil
    /// Lets the root recompute `isPro` after Activate, Refresh or Remove.
    var entitlementDidChange: (() -> Void)? = nil
    /// The most recent MSAL failure, allowlisted, read at export time. Covers silent token
    /// failures during browsing as well as sign-in, with one hook instead of one per call.
    var lastAuthFailure: (() async -> AuthFailureDetail?)? = nil
    /// Domain of the signed-in account, shown on the Activate button so nobody licenses an
    /// organization they did not mean to. An MSP signed into a customer tenant is the case
    /// this exists for.
    var signedInDomain: String? = nil
    /// Ends the session. Injected because Settings must not know about MSAL.
    ///
    /// In live mode this signs out of Microsoft and clears tenant-scoped data; in demo mode
    /// it just leaves demo. One closure covers both because `AppRootModel.signOut()` already
    /// handles either state.
    var endSession: (() async -> Void)? = nil
    /// Requests consent for the PIM activation scopes. Nil in demo.
    var requestPrivilegedConsent: (() async -> String?)? = nil
    /// Requests consent to read users' display names. Nil in demo.
    var requestUserNamesConsent: (() async -> String?)? = nil
    /// Opens the activation sheet, injected so Settings need not know about Graph.
    var privilegedSheet: (() -> PrivilegedAccessView)? = nil
    /// Apple subscriptions. Nil in demo mode and while signed out, there is nothing to buy
    /// on a screen that cannot reach a tenant.
    var subscriptions: SubscriptionStore? = nil
    /// False when opened from the sign-in screen.
    ///
    /// **Settings must be reachable without signing in**, because the diagnostics report is
    /// in here and a failed sign-in is exactly when somebody needs it. Found on device: after
    /// a sign-in failure the only route to the report was through demo mode, which is not a
    /// route anyone would guess. Signed out, the sections that need a tenant, rotation,
    /// role activation, the macOS toggle, the license, sign-out, are simply absent rather
    /// than present and broken.
    var hasSession: Bool = true

    @Environment(\.dismiss) private var dismiss

    // Free tier
    @State private var remainingReveals = 0
    @State private var nextAvailable: Date?

    @State private var showingManageSubscriptions = false
    @State private var purchaseMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                if managed.config.isManaged {
                    managedSection
                }
                freeTierSection
                pagesSection
                // The plan stays on the first page, where App Review has to find the
                // purchase without knowing where to look; below the pages, because the
                // plans arrive late and pushed the page rows down under a finger.
                subscriptionSection
                sessionSection
                #if DEBUG
                debugSection
                #endif
            }
            .task {
                refreshMeter()
                // Defensive: if a previous visit left the purchase spinner up because
                // StoreKit never answered, reopening Settings must not inherit it.
                subscriptions?.stopWaiting()
                // The plans are asked of the App Store here, where they are shown, rather
                // than at every launch, where they competed with sign-in for the network.
                await subscriptions?.loadOffersIfNeeded()
            }
            .navigationTitle("Settings")
            .navigationDestination(for: SettingsPage.self) { page in
                destination(page)
                    .toolbarBackground(.visible, for: .navigationBar)
            }
            .toolbarBackground(.visible, for: .navigationBar)
            // On the NavigationStack, not a Section: a Section re-renders on every form
            // state change, which dismissed a sheet the instant it opened once before.
            .manageSubscriptionsSheet(isPresented: $showingManageSubscriptions)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    // MARK: - pages

    enum SettingsPage: Hashable {
        case general, notifications, actions, shiftLog, license, diagnostics, about
    }

    /// One row per page. A page that needs a session or a tenant is absent rather than
    /// present and broken, the rule the sections followed when they were one form.
    private var pagesSection: some View {
        Section {
            NavigationLink(value: SettingsPage.general) {
                Label("General", systemImage: "gearshape")
            }
            if hasSession {
                NavigationLink(value: SettingsPage.notifications) {
                    Label("Notifications", systemImage: "bell.badge")
                }
                NavigationLink(value: SettingsPage.actions) {
                    Label("Actions and Permissions", systemImage: "hand.raised")
                }
                if shiftLog != nil, shiftLogTenantId != nil {
                    NavigationLink(value: SettingsPage.shiftLog) {
                        Label("Shift Log", systemImage: "list.bullet.rectangle")
                    }
                }
            }
            if entitlement != nil, !isDemo {
                NavigationLink(value: SettingsPage.license) {
                    Label("Organization License", systemImage: "checkmark.seal")
                }
            }
            NavigationLink(value: SettingsPage.diagnostics) {
                Label("Diagnostics", systemImage: "stethoscope")
            }
            NavigationLink(value: SettingsPage.about) {
                Label("About", systemImage: "info.circle")
            }
        }
    }

    /// Each page owns its state and reads it when it opens.
    @ViewBuilder
    private func destination(_ page: SettingsPage) -> some View {
        switch page {
        case .general:
            SettingsGeneralPage(settings: settings, isDemo: isDemo, hasSession: hasSession,
                                requestUserNamesConsent: requestUserNamesConsent)
        case .notifications:
            SettingsNotificationsPage(notificationTenants: notificationTenants, notificationsStore: notificationsStore,
                                      isPro: isPro, isDemo: isDemo)
        case .actions:
            SettingsActionsPage(settings: settings, isDemo: isDemo,
                                requestDeviceActionsConsent: requestDeviceActionsConsent,
                                requestUserActionsConsent: requestUserActionsConsent,
                                requestGroupWritesConsent: requestGroupWritesConsent,
                                requestPrivilegedConsent: requestPrivilegedConsent,
                                privilegedSheet: privilegedSheet)
        case .shiftLog:
            SettingsShiftLogPage(shiftLog: shiftLog, shiftLogTenantId: shiftLogTenantId)
        case .license:
            SettingsLicensePage(entitlement: entitlement, isDemo: isDemo, tenantId: tenantId,
                                signedInDomain: signedInDomain, entitlementDidChange: entitlementDidChange)
        case .diagnostics:
            SettingsDiagnosticsPage(tenantId: tenantId, lastAuthFailure: lastAuthFailure)
        case .about:
            SettingsAboutPage(tenantId: tenantId, isDemo: isDemo)
        }
    }

    // MARK: - managed by the organization

    private let managed = ManagedConfigStore.shared

    private var managedSection: some View {
        Section {
            ForEach(managed.config.summaryLines, id: \.self) { line in
                Text(line)
            }
            ForEach(managed.config.problems, id: \.self) { problem in
                Label(problem, systemImage: "exclamationmark.triangle")
                    .font(.footnote)
                    .foregroundStyle(.orange)
            }
        } header: {
            Text("Managed by Your Organization")
        } footer: {
            Text("These settings come from your organization's Intune app configuration policy and can't be changed here. A setting with a warning was not understood and is being ignored; tell whoever manages the policy.")
        }
    }

    // MARK: - free tier

    /// Read-only status, always present for free-tier users.
    ///
    /// Deliberately NOT a sales surface. There is no upgrade button and no price here:
    /// this is the place a confused customer looks, and the place support asks them to
    /// read from, so it answers "how many are left and when do I get more" and stops.
    /// Turning a status readout into a pitch is exactly what this audience resents.
    ///
    /// The footer does double duty. It explains the count, and while doing so it states
    /// the strongest privacy claim the product has: the tally is local, because a server
    /// counter would mean recording how often each tenant retrieves passwords.
    @ViewBuilder
    private var freeTierSection: some View {
        if !isPro, meter != nil {
            Section {
                LabeledContent("Free reveals left", value: "\(remainingReveals) of \(meterTotal)")
                if let nextAvailable {
                    LabeledContent("Next one available", value: Self.relative(nextAvailable))
                }
            } header: {
                Text("Reveals")
            } footer: {
                Text("""
                    Local administrator passwords and BitLocker keys draw on the same \
                    allowance, and revealing the same device twice within an hour only \
                    counts once.

                    This tally is kept on this device and nowhere else. TenantKeep does not \
                    record which credentials you retrieve, or how often, on any server.
                    """)
            }
        }
    }

    // MARK: - Apple subscription

    /// In-app purchase of Pro or MSP.
    ///
    /// **This section shows prices and the organization licence section does not, which looks
    /// inconsistent and is not.** Guideline 3.1.3 forbids pointing at outside purchasing from
    /// inside the app, which is why the licence section is a bare status readout with no price
    /// and no link, see `App Store Review Guideline 3.1.3`. Apple's own in-app purchase is the one
    /// place selling is permitted, and Apple in fact requires the price to be shown. So the
    /// two sections follow opposite rules on purpose. Do not "harmonise" them.
    @ViewBuilder
    private var subscriptionSection: some View {
        // VISIBLE IN DEMO MODE, and that is deliberate rather than an oversight.
        //
        // App Review cannot sign into a customer's Entra tenant, that is the whole reason
        // demo mode exists (Guideline 2.1). If the purchase screen were reachable only after
        // signing in, a reviewer could never see it, and "in-app purchase not functional" is
        // a routine rejection. Hidden only while signed OUT, where there is no Settings sheet
        // to speak of anyway.
        //
        // Nothing about this reaches Kainor: StoreKit talks to Apple. The rule that a demo
        // install must have no path to our server is about the entitlement client, which is
        // still nil here.
        if let subscriptions, hasSession || isDemo {
            Section {
                if subscriptions.entitlement.isActive {
                    LabeledContent("Plan", value: activePlanName(subscriptions))
                    Button("Manage subscription") { showingManageSubscriptions = true }
                } else {
                    ForEach(subscriptions.offers) { offer in
                        Button {
                            Task { await buy(offer.plan, from: subscriptions) }
                        } label: {
                            HStack(alignment: .firstTextBaseline) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(offer.displayName)
                                    if let intro = offer.introductoryOffer {
                                        Text(intro).font(.footnote).foregroundStyle(Brand.accent)
                                    }
                                }
                                Spacer(minLength: 8)
                                // The price is the most important fact in the row, so it is
                                // NOT secondary, faded grey on a dark background made the
                                // numbers hard to read on device. The billing period stays
                                // quiet underneath, which is the part that can be small.
                                VStack(alignment: .trailing, spacing: 0) {
                                    Text(offer.displayPrice)
                                        .font(.subheadline.weight(.semibold))
                                        .monospacedDigit()
                                    if !offer.periodLabel.isEmpty {
                                        Text("per " + offer.periodLabel)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                        .disabled(subscriptions.isWorking)
                    }

                    if subscriptions.offers.isEmpty {
                        // Never a scary error: the app is fully usable unpaid, so a plan list
                        // that will not load is an inconvenience rather than a failure.
                        Text(subscriptions.loadFailed
                             ? "Plans aren't available right now. Check your connection and try again later."
                             : "Loading plans…")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    // Apple requires this, and it earns its place: entitlements belong to an
                    // Apple ID, so somebody who reinstalled or switched devices otherwise has
                    // no explanation for where their subscription went.
                    Button("Restore purchases") {
                        Task { await restore(subscriptions) }
                    }
                    .disabled(subscriptions.isWorking)
                }

                if subscriptions.isWorking {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("Contacting the App Store…").font(.footnote).foregroundStyle(.secondary)
                        Spacer(minLength: 8)
                        // An escape hatch, because the App Store sheet can be dismissed
                        // without `purchase()` ever returning. Abandoning the wait loses
                        // nothing: if the purchase does complete, the updates listener
                        // grants it anyway.
                        Button("Stop waiting") { subscriptions.stopWaiting() }
                            .font(.footnote)
                    }
                }

                if let purchaseMessage {
                    Text(purchaseMessage).font(.footnote).foregroundStyle(.secondary)
                }
            } header: {
                Text("Subscription")
            } footer: {
                Text("""
                    Removes the monthly reveal limit. Billed by Apple through your Apple \
                    Account; cancel any time in the App Store. The MSP plan adds switching \
                    between customer organizations.
                    """)
            }
        }
    }

    /// What just changed, and where to find it.
    ///
    /// After an MSP purchase the tenant switcher appeared with nothing to explain it, and
    /// a purchase that silently alters the toolbar reads as either broken or magic. This
    /// is deliberately NOT a tutorial: it names the capability and the one place it lives,
    /// once, at the moment it becomes true.
    static func unlockedMessage(for plan: SubscriptionProduct) -> String {
        switch plan {
        case .mspYearly:
            return "MSP is active. Reveals are unlimited, and the building icon in the device list toolbar now switches between customer organizations."
        case .proMonthly, .proYearly:
            return "Pro is active. Reveals are unlimited. The monthly count is gone."
        }
    }

    private func activePlanName(_ store: SubscriptionStore) -> String {
        switch store.entitlement.tier {
        case .msp:  return "TenantKeep MSP"
        case .pro:  return "TenantKeep Pro"
        default:    return "Active"
        }
    }

    private func buy(_ plan: SubscriptionProduct, from store: SubscriptionStore) async {
        purchaseMessage = nil
        switch await store.purchase(plan) {
        case .purchased:
            entitlementDidChange?()
            purchaseMessage = Self.unlockedMessage(for: plan)
        case .cancelled:
            // Silent. The user chose not to buy, and a message about it is nagging.
            break
        case .pending:
            // NOT success. Ask to Buy or a bank step is outstanding, nothing is owned yet,
            // and claiming otherwise sends somebody looking for a feature they do not have.
            purchaseMessage = "Waiting for approval. Your subscription starts once it's approved, and this screen will update on its own."
        case .failed(let message):
            purchaseMessage = message
        }
    }

    private func restore(_ store: SubscriptionStore) async {
        purchaseMessage = nil
        let restored = await store.restore()
        entitlementDidChange?()
        purchaseMessage = restored
            ? nil
            : "No subscription was found for this Apple Account. If you bought one with a different Apple ID, sign into that one in the App Store."
    }

    private var meterTotal: Int {
        meter?.policy.freeRevealsPerWindow ?? 5
    }

    private func refreshMeter() {
        guard let meter else { return }
        remainingReveals = meter.remaining(isPro: isPro)
        nextAvailable = meter.nextAvailable(isPro: isPro)
    }

    static func relative(_ date: Date) -> String {
        RelativeDates.full(date)
    }

    // MARK: - debug

    #if DEBUG
    /// DEBUG ONLY, and structurally so: the whole section is inside `#if DEBUG`, not
    /// hidden behind a runtime flag. A reset button that reaches a Release build makes
    /// the meter decorative, and a runtime flag is one careless edit away from shipping.
    ///
    /// It exists because testing anything about metering otherwise means waiting out a
    /// 30 day window or reinstalling, and reinstalling does not help, the ledger lives
    /// in the Keychain and survives deletion, which is verified behaviour.
    private var debugSection: some View {
        Section {
            LabeledContent("Ledger", value: "\(meterTotal - remainingReveals) of \(meterTotal) used")
            Button("Reset reveal meter", role: .destructive) {
                meter?.resetLedger()
                refreshMeter()
            }
            .disabled(meter == nil)
        } header: {
            Text("Debug")
        } footer: {
            Text("Compiled out of Release builds entirely.")
        }
    }
    #endif

    // MARK: - session

    /// Sign out, or leave demo.
    ///
    /// This was missing entirely at first: `signOut()` existed on the root model and
    /// was only reachable from an error-recovery path, so there was no way for a user to end
    /// a session at all. For a tool that reveals administrator passwords that is not a
    /// missing convenience, you could not hand the phone back, and an MSP could not change
    /// tenants without force-quitting.
    ///
    /// The license is deliberately NOT removed here. It is bound to a tenant and re-verified
    /// on every read, so signing back into the same organization keeps it, and signing into a
    /// different one shows the "Free here" branch. Discarding it on sign-out would make
    /// every tenant change an unnecessary round trip to Kainor.
    @ViewBuilder
    private var sessionSection: some View {
        if let endSession {
            Section {
                Button(role: .destructive) {
                    // Dismiss first: signing out swaps the whole view tree beneath this
                    // sheet, and a sheet outliving its presenter is how the Section-attached
                    // sheet bug happened before.
                    dismiss()
                    Task { await endSession() }
                } label: {
                    Label(
                        isDemo ? "Leave demo" : "Sign out",
                        systemImage: "rectangle.portrait.and.arrow.right"
                    )
                }
            } footer: {
                Text(isDemo
                    ? "Returns to the sign-in screen."
                    : """
                      Signs out of Microsoft and clears the device list from memory. Your \
                      organization license stays activated for the next time you sign in.
                      """)
            }
        }
    }

    static var versionString: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown"
        return "\(v) (\(b))"
    }
}

#Preview("Settings") {
    SettingsView(
        settings: AppSettings.shared,
        requestDeviceActionsConsent: { nil },
        isDemo: true,
        tenantId: nil
    )
}
