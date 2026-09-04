import SwiftUI
import Combine
import AuthKit
import CredentialKit
import DiagnosticsKit
import LicensingKit
import PrivilegedAccessKit
import SubscriptionKit
import StoreKit

// Settings. Three toggles, each with a deliberate design decision behind it.
//
// WHERE THIS LIVES: a gear in the device list toolbar, opening a sheet. Not on the device
// list itself — that screen's job is find-a-device-fast, and controls there compete with
// the search field and get tapped by accident.

/// Persisted preferences. Plain UserDefaults: none of this is sensitive, and it must
/// survive a relaunch.
@MainActor
final class AppSettings: ObservableObject {
    static let shared = AppSettings()

    /// Whether BitLocker key rotation is enabled. Gating this on a toggle is the whole
    /// point: customers who leave it off never see a "modify your devices" permission on
    /// their consent screen.
    @Published var bitLockerRotationEnabled: Bool {
        didSet { UserDefaults.standard.set(bitLockerRotationEnabled, forKey: Keys.rotation) }
    }

    /// Whether LAPSlock may request just-in-time activation of a PIM-eligible role.
    ///
    /// Same reasoning as rotation, and a heavier ask. `RoleAssignmentSchedule.ReadWrite.Directory`
    /// lets the app request a privilege escalation, which reads worse on a consent screen
    /// than reading a password does. Off by default: a customer who never turns it on never
    /// sees that permission requested at all.
    @Published var privilegedActivationEnabled: Bool {
        didSet { UserDefaults.standard.set(privilegedActivationEnabled, forKey: Keys.privilegedActivation) }
    }

    /// Whether to look up primary users' display names in Entra when Intune leaves the
    /// field empty. Founder decision 2026-09-03: the UPN is the default and is enough;
    /// names are optional because they cost a permission — `User.ReadBasic.All` on the
    /// consent screen — that a customer should choose, not inherit.
    @Published var userNamesEnabled: Bool {
        didSet { UserDefaults.standard.set(userNamesEnabled, forKey: Keys.userNames) }
    }

    /// Whether the whole app is held behind Face ID, separate from the per-reveal gate.
    ///
    /// What it protects is NOT a credential — those already have their own gate. It is the
    /// device inventory: hostnames, primary users, compliance state. That is reconnaissance
    /// for an entire tenant, and a borrowed unlocked phone should not hand it over.
    @Published var appLockEnabled: Bool {
        didSet { UserDefaults.standard.set(appLockEnabled, forKey: Keys.appLock) }
    }

    @Published var appearance: AppearancePreference {
        didSet { UserDefaults.standard.set(appearance.rawValue, forKey: Keys.appearance) }
    }

    private enum Keys {
        static let rotation = "settings.bitLockerRotationEnabled"
        static let privilegedActivation = "settings.privilegedActivationEnabled"
        static let userNames = "settings.userNamesEnabled"
        static let appLock = "settings.appLockEnabled"
        static let appearance = "settings.appearance"
    }

    private init() {
        self.bitLockerRotationEnabled = UserDefaults.standard.bool(forKey: Keys.rotation)
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

    /// nil means "follow the system", which is what SwiftUI expects.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light:  return .light
        case .dark:   return .dark
        }
    }
}

// MARK: - view

struct SettingsView: View {
    @ObservedObject var settings: AppSettings
    /// Requests consent for the write scope. Returns nil on success, or a message.
    /// Injected so the sheet doesn't need to know about MSAL.
    let requestRotationConsent: () async -> String?
    let isDemo: Bool
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
    /// Apple subscriptions. Nil in demo mode and while signed out — there is nothing to buy
    /// on a screen that cannot reach a tenant.
    var subscriptions: SubscriptionStore? = nil
    /// False when opened from the sign-in screen.
    ///
    /// **Settings must be reachable without signing in**, because the diagnostics report is
    /// in here and a failed sign-in is exactly when somebody needs it. Found on device: after
    /// a sign-in failure the only route to the report was through demo mode, which is not a
    /// route anyone would guess. Signed out, the sections that need a tenant — rotation,
    /// role activation, the macOS toggle, the license, sign-out — are simply absent rather
    /// than present and broken.
    var hasSession: Bool = true

    @Environment(\.dismiss) private var dismiss
    @State private var isRequestingConsent = false
    @State private var consentError: String?

    // Diagnostics
    @State private var includeTenantId = false
    @State private var report: String?
    @State private var isBuildingReport = false
    @State private var showingReport = false
    @State private var mailError: String?
    @Environment(\.openURL) private var openURL

    // Free tier
    @State private var remainingReveals = 0
    @State private var nextAvailable: Date?

    @State private var copiedTenantId = false
    @State private var isRequestingPrivilegedConsent = false
    @State private var privilegedConsentError: String?
    @State private var showingManageSubscriptions = false
    @State private var purchaseMessage: String?
    @State private var isRequestingNamesConsent = false
    @State private var namesConsentError: String?
    @State private var showingPrivilegedSheet = false

    // Organization license
    @State private var license: EntitlementState = .free
    @State private var isLicenseActivated = false
    @State private var licenseIsForAnotherOrganization = false
    @State private var isFetchingLicense = false
    @State private var licenseMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                appearanceSection
                appLockSection
                if hasSession {
                    userNamesSection
                    rotationSection
                    privilegedAccessSection
                    macOSSection
                }
                freeTierSection
                subscriptionSection
                licenseSection
                diagnosticsSection
                aboutSection
                sessionSection
                #if DEBUG
                debugSection
                #endif
            }
            .task {
                refreshMeter()
                refreshLicense()
                // Defensive: if a previous visit left the purchase spinner up because
                // StoreKit never answered, reopening Settings must not inherit it.
                subscriptions?.stopWaiting()
            }
            .navigationTitle("Settings")
            .toolbarBackground(.visible, for: .navigationBar)
            // Attached to the NavigationStack, not to the Section. A Section re-renders
            // on every form state change, which dismissed the sheet the instant it opened.
            .sheet(isPresented: $showingReport) {
                reportPreview
            }
            .sheet(isPresented: $showingPrivilegedSheet) {
                if let privilegedSheet { privilegedSheet() }
            }
            // On the NavigationStack for the same reason as the two above: a Section
            // re-renders on every form state change, which dismissed a sheet the instant it
            // opened once before.
            .manageSubscriptionsSheet(isPresented: $showingManageSubscriptions)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    // MARK: - appearance

    private var appearanceSection: some View {
        Section("Appearance") {
            Picker("Theme", selection: $settings.appearance) {
                ForEach(AppearancePreference.allCases) { pref in
                    Text(pref.label).tag(pref)
                }
            }
            .pickerStyle(.segmented)
        }
    }

    // MARK: - app lock

    /// Holds the whole app behind Face ID.
    ///
    /// Unlike the other toggles this asks Microsoft for nothing — it is entirely local, so
    /// there is no consent prompt and no new permission on anybody's consent screen.
    private var appLockSection: some View {
        Section {
            Toggle("Require Face ID to open LAPSlock", isOn: $settings.appLockEnabled)
        } header: {
            Text("App lock")
        } footer: {
            Text("""
                Off by default. Separate from the check before each password reveal, which \
                always runs. This one protects the device list itself — hostnames, primary \
                users and compliance state are worth something to an attacker even with no \
                password on screen.

                LAPSlock re-locks after a few minutes in the background, not instantly, so \
                switching to Microsoft Authenticator and back does not ask twice.
                """)
        }
    }

    // MARK: - user names

    /// Display names for device rows, behind an opt-in toggle.
    ///
    /// Intune often leaves `userDisplayName` empty, so rows show the UPN. Filling the gap
    /// means reading user objects from Entra, which puts `User.ReadBasic.All` on the
    /// customer's consent screen — a password app asking to read the user list. That is a
    /// choice for the customer, so it has the same shape as rotation: off by default, consent
    /// requested at the moment of the decision, and the footer says exactly what it adds.
    private var userNamesSection: some View {
        Section {
            Toggle("Show user names", isOn: Binding(
                get: { settings.userNamesEnabled },
                set: { newValue in
                    if newValue {
                        Task { await enableUserNames() }
                    } else {
                        settings.userNamesEnabled = false
                        namesConsentError = nil
                    }
                }
            ))
            .disabled(isRequestingNamesConsent)

            if isRequestingNamesConsent {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Requesting permission…").font(.footnote).foregroundStyle(.secondary)
                }
            }

            if let namesConsentError {
                Text(namesConsentError)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Device list")
        } footer: {
            Text("""
                Off by default. Intune often leaves a device's primary user as a sign-in \
                address rather than a name. Turning this on looks the name up in Microsoft \
                Entra ID, which adds one permission to what LAPSlock requests from your \
                organization: reading basic user profiles (User.ReadBasic.All). Names are \
                kept in memory for this session and never stored.

                Leaving it off means LAPSlock never reads your user directory.
                """)
        }
    }

    private func enableUserNames() async {
        namesConsentError = nil
        if isDemo {
            settings.userNamesEnabled = true
            namesConsentError = "Demo mode: no permission was actually requested."
            return
        }
        guard let requestUserNamesConsent else { return }
        isRequestingNamesConsent = true
        defer { isRequestingNamesConsent = false }

        if let error = await requestUserNamesConsent() {
            settings.userNamesEnabled = false
            namesConsentError = error
        } else {
            settings.userNamesEnabled = true
        }
    }

    // MARK: - BitLocker rotation

    private var rotationSection: some View {
        Section {
            Toggle("Allow BitLocker key rotation", isOn: Binding(
                get: { settings.bitLockerRotationEnabled },
                set: { newValue in
                    if newValue {
                        // Ask for consent NOW, at the moment of the decision, rather than
                        // later when the admin is standing at a broken machine. Finding
                        // out your org blocked the permission should not happen mid-repair.
                        Task { await enableRotation() }
                    } else {
                        settings.bitLockerRotationEnabled = false
                        consentError = nil
                    }
                }
            ))
            .disabled(isRequestingConsent)

            if isRequestingConsent {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Requesting permission…").font(.footnote).foregroundStyle(.secondary)
                }
            }

            if let consentError {
                Text(consentError)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("BitLocker")
        } footer: {
            Text("""
                Off by default. Turning this on asks Microsoft Entra ID for permission to \
                **modify** devices in your tenant, not just read them — your administrator \
                may need to approve it. Rotation is queued and applies the next time the \
                device checks in with Intune.

                Leaving it off means LAPSlock only ever requests read access.
                """)
        }
    }

    private func enableRotation() async {
        consentError = nil
        if isDemo {
            // No real tenant to consent against; let the toggle work so the UI is
            // explorable, and say so plainly.
            settings.bitLockerRotationEnabled = true
            consentError = "Demo mode: no permission was actually requested."
            return
        }
        isRequestingConsent = true
        defer { isRequestingConsent = false }

        if let error = await requestRotationConsent() {
            settings.bitLockerRotationEnabled = false
            consentError = error
        } else {
            settings.bitLockerRotationEnabled = true
        }
    }

    // MARK: - privileged access

    /// Just-in-time role activation, behind an opt-in toggle.
    ///
    /// Same shape as the rotation toggle above, and the same reason: the permission this
    /// asks for — requesting a privilege escalation — reads worse on a consent screen than
    /// reading a password does. A customer who never turns it on never sees it requested.
    ///
    /// The button appears only once the toggle is on, because offering an action whose
    /// permission has not been granted just produces a failure the user cannot act on.
    @ViewBuilder
    private var privilegedAccessSection: some View {
        if requestPrivilegedConsent != nil {
            Section {
                Toggle("Allow role activation", isOn: Binding(
                    get: { settings.privilegedActivationEnabled },
                    set: { newValue in
                        if newValue {
                            // Ask at the moment of the decision, like rotation. Discovering
                            // your organization blocked it while standing at a broken
                            // machine is the wrong time to find out.
                            Task { await enablePrivilegedActivation() }
                        } else {
                            settings.privilegedActivationEnabled = false
                            privilegedConsentError = nil
                        }
                    }
                ))
                .disabled(isRequestingPrivilegedConsent)

                if settings.privilegedActivationEnabled, privilegedSheet != nil {
                    Button {
                        showingPrivilegedSheet = true
                    } label: {
                        Label("Activate a role now", systemImage: "person.badge.key")
                    }
                }

                if let privilegedConsentError {
                    Text(privilegedConsentError)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Privileged access")
            } footer: {
                Text("""
                    If your role is eligible through Privileged Identity Management rather than permanently assigned, LAPSlock can activate it here instead of sending you to the portal.

                    This asks Microsoft for permission to request activation of your own eligible roles — never anyone else's. Leave it off and that permission is never requested.

                    This switch is your preference; the permission itself is granted per organization. Signing in to a different one asks again, and the activation screen offers it there when needed.
                    """)
            }
        }
    }

    private func enablePrivilegedActivation() async {
        privilegedConsentError = nil
        guard let requestPrivilegedConsent else { return }

        if isDemo {
            settings.privilegedActivationEnabled = true
            privilegedConsentError = "Demo mode: no permission was actually requested."
            return
        }

        isRequestingPrivilegedConsent = true
        defer { isRequestingPrivilegedConsent = false }

        if let error = await requestPrivilegedConsent() {
            settings.privilegedActivationEnabled = false
            privilegedConsentError = error
        } else {
            settings.privilegedActivationEnabled = true
        }
    }

    // MARK: - macOS

    /// Shown DISABLED rather than hidden. A hidden toggle is dead code nobody remembers,
    /// and an admin wondering "why can't I see Mac passwords?" deserves an answer instead
    /// of an absence. When Microsoft ships an API, this becomes live.
    private var macOSSection: some View {
        Section {
            Toggle("macOS local admin passwords", isOn: .constant(false))
                .disabled(true)
        } header: {
            Text("macOS")
        } footer: {
            Text("""
                Unavailable. Microsoft doesn't currently offer an API for reading macOS \
                local administrator passwords — Intune keeps them encrypted on its own \
                service, and only the admin center can display them. LAPSlock will enable \
                this automatically if that changes.

                Rotation schedules for macOS devices are still shown where Microsoft \
                returns them.
                """)
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

                    This tally is kept on this device and nowhere else. LAPSlock does not \
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
    /// and no link — see `docs/APP-STORE-3-1-3.md`. Apple's own in-app purchase is the one
    /// place selling is permitted, and Apple in fact requires the price to be shown. So the
    /// two sections follow opposite rules on purpose. Do not "harmonise" them.
    @ViewBuilder
    private var subscriptionSection: some View {
        // VISIBLE IN DEMO MODE, and that is deliberate rather than an oversight.
        //
        // App Review cannot sign into a customer's Entra tenant — that is the whole reason
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
                                // NOT secondary — faded grey on a dark background made the
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
    /// Founder bought MSP on device and the tenant switcher appeared with nothing to explain
    /// it — a purchase that silently alters the toolbar reads as either broken or magic. This
    /// is deliberately NOT a tutorial: it names the capability and the one place it lives,
    /// once, at the moment it becomes true.
    static func unlockedMessage(for plan: SubscriptionProduct) -> String {
        switch plan {
        case .mspYearly:
            return "MSP is active. Reveals are unlimited, and the building icon in the device list toolbar now switches between customer organizations."
        case .proMonthly, .proYearly:
            return "Pro is active. Reveals are unlimited — the monthly count is gone."
        }
    }

    private func activePlanName(_ store: SubscriptionStore) -> String {
        switch store.entitlement.tier {
        case .msp:  return "LAPSlock MSP"
        case .pro:  return "LAPSlock Pro"
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

    // MARK: - organization license

    /// Contract section 7.1: the app contacts Kainor's server only after the user taps
    /// Activate here (or Refresh, later, or on the monthly schedule once activated). This
    /// section is the whole user-facing surface of that decision, so the footer says it out
    /// loud: until you activate, the app talks to Microsoft and nothing else.
    ///
    /// No pitch, no price. The same rule as the reveals section — this is a status readout
    /// and an action, for an audience that resents being sold to inside a settings screen.
    @ViewBuilder
    private var licenseSection: some View {
        if let entitlement, !isDemo {
            Section {
                if isLicenseActivated, licenseIsForAnotherOrganization {
                    // Activated, but for a different tenant. Not unlicensed — so do not
                    // show a bare Activate button as if nothing had happened — but the
                    // license does not apply here, so Refresh would fetch for the wrong
                    // organization. Say which situation this is and offer the way out.
                    LabeledContent("Plan", value: "Free here")
                    Button {
                        guard let tenantId else { return }
                        Task { await runLicenseAction { await entitlement.activate(tenantId: tenantId) } }
                    } label: {
                        Label(Self.activateLabel(signedInDomain), systemImage: "checkmark.seal")
                    }
                    .disabled(isFetchingLicense || tenantId == nil)
                    Button(role: .destructive) {
                        entitlement.remove()
                        licenseMessage = nil
                        refreshLicense()
                        entitlementDidChange?()
                    } label: {
                        Label("Remove license", systemImage: "xmark.circle")
                    }
                    .disabled(isFetchingLicense)
                } else if isLicenseActivated {
                    LabeledContent("Plan", value: Self.tierName(license.tier))
                    if let expires = license.expiresAt {
                        LabeledContent(
                            license.isInGrace ? "Could not refresh" : "Renews by",
                            value: Self.relative(expires)
                        )
                    }
                    Button {
                        Task { await runLicenseAction { await entitlement.refreshNow() } }
                    } label: {
                        Label("Refresh license", systemImage: "arrow.clockwise")
                    }
                    .disabled(isFetchingLicense)
                    Button(role: .destructive) {
                        entitlement.remove()
                        licenseMessage = nil
                        refreshLicense()
                        entitlementDidChange?()
                    } label: {
                        Label("Remove license", systemImage: "xmark.circle")
                    }
                    .disabled(isFetchingLicense)
                } else {
                    Button {
                        guard let tenantId else { return }
                        Task { await runLicenseAction { await entitlement.activate(tenantId: tenantId) } }
                    } label: {
                        Label(Self.activateLabel(signedInDomain), systemImage: "checkmark.seal")
                    }
                    .disabled(isFetchingLicense || tenantId == nil)
                }
                if let licenseMessage {
                    Text(licenseMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Organization license")
            } footer: {
                Text(licenseIsForAnotherOrganization
                    ? """
                      This license belongs to a different Microsoft organization, so it does \
                      not apply while you are signed in here. Activating replaces it; an \
                      install holds one license at a time.

                      If you manage several organizations, activate against your own \
                      instead. An MSP license covers you in every tenant you sign into, \
                      with nothing to re-activate.
                      """
                    : isLicenseActivated
                    ? """
                      Your license is keyed to this Microsoft tenant and checked against \
                      Kainor about once a month. Nothing about which devices or credentials \
                      you look at is ever sent.
                      """
                    : """
                      An organization license is keyed to your Microsoft tenant. Until you \
                      activate one, LAPSlock never contacts Kainor: it talks to Microsoft and \
                      nothing else, which you can confirm with a network proxy.

                      If you manage several organizations, activate while signed in to your \
                      own. An MSP license then covers every tenant you sign into.
                      """)
            }
        }
    }

    /// Names the organization being licensed. Falls back to generic wording rather than
    /// showing a GUID, which would mean nothing to the person reading it.
    static func activateLabel(_ domain: String?) -> String {
        guard let domain else { return "Activate organization license" }
        return "Activate license for \(domain)"
    }

    private func refreshLicense() {
        guard let entitlement else { return }
        isLicenseActivated = entitlement.isActivated
        license = entitlement.state(signedInTenantId: tenantId)
        licenseIsForAnotherOrganization = entitlement.isBoundToAnotherTenant(signedInTenantId: tenantId)
    }

    private func runLicenseAction(_ action: () async -> EntitlementFetchOutcome?) async {
        isFetchingLicense = true
        defer { isFetchingLicense = false }
        let outcome = await action()
        licenseMessage = Self.describe(outcome)
        refreshLicense()
        entitlementDidChange?()
    }

    static func tierName(_ tier: EntitlementTier) -> String {
        switch tier {
        case .free: return "Free"
        case .pro: return "Pro"
        case .msp: return "MSP"
        case .enterprise: return "Enterprise"
        }
    }

    /// One line, no drama. Contract section 7.6: every failure lands the user on the free
    /// tier, and none of them is an alert.
    static func describe(_ outcome: EntitlementFetchOutcome?) -> String? {
        switch outcome {
        case nil: return nil
        case .updated(.free): return "No organization license was found for this tenant."
        case .updated(let tier): return "\(tierName(tier)) license active."
        case .offline: return "Couldn't reach the license service. Your current license still applies."
        case .serverError: return "The license service is temporarily unavailable. Try again later."
        case .rejected: return "The license service returned something this app could not accept."
        }
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
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: date, relativeTo: Date())
    }

    // MARK: - debug

    #if DEBUG
    /// DEBUG ONLY, and structurally so: the whole section is inside `#if DEBUG`, not
    /// hidden behind a runtime flag. A reset button that reaches a Release build makes
    /// the meter decorative, and a runtime flag is one careless edit away from shipping.
    ///
    /// It exists because testing anything about metering otherwise means waiting out a
    /// 30 day window or reinstalling, and reinstalling does not help — the ledger lives
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

    // MARK: - diagnostics

    private var diagnosticsSection: some View {
        Section {
            Toggle("Include tenant ID", isOn: $includeTenantId)
                .disabled(tenantId == nil)

            Button {
                Task { await buildReport() }
            } label: {
                if isBuildingReport {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("Gathering…")
                    }
                } else {
                    Label("Gather diagnostics", systemImage: "stethoscope")
                }
            }
            .disabled(isBuildingReport)

            if let report {
                // Email first, since that's the path most people will take.
                Button {
                    emailReport(report)
                } label: {
                    Label("Email to support", systemImage: "envelope")
                }

                if let mailError {
                    Text(mailError)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                // Share carries the complete report with no length limit.
                ShareLink(item: report) {
                    Label("Share full report", systemImage: "square.and.arrow.up")
                }
                Button {
                    showingReport = true
                } label: {
                    Label("Review before sending", systemImage: "doc.text.magnifyingglass")
                }
            }
        } header: {
            Text("Diagnostics")
        } footer: {
            VStack(alignment: .leading, spacing: 8) {
                Text("Collects what happened, not what you saw: operation outcomes, HTTP status codes, and Microsoft Graph request IDs. It contains no passwords, recovery keys, usernames, device names, or response data — those cannot be represented in the report at all.")
                Text("Kept in memory only and cleared when the app closes, so reproduce the problem first, then gather.")
            }
        }
    }

    /// Let people read exactly what they're about to send. For an audience that audits
    /// source code, "trust us, it's redacted" is the wrong posture.
    private var reportPreview: some View {
        NavigationStack {
            ScrollView {
                Text(report ?? "")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
            }
            .navigationTitle("Diagnostic report")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { showingReport = false }
                }
            }
        }
    }

    /// Opens the default mail client with the report prefilled. Reports failure rather
    /// than doing nothing: on the simulator (and on a device with no mail account) there
    /// is nothing to open, and a silent no-op looks like a broken button.
    private func emailReport(_ report: String) {
        mailError = nil
        guard let url = DiagnosticsExport.mailtoURL(
            subject: DiagnosticsExport.subject(appVersion: Self.versionString),
            body: DiagnosticsExport.trimmedForEmail(report)
        ) else {
            mailError = "Couldn't build the email. Use Share full report instead."
            return
        }
        openURL(url) { accepted in
            if !accepted {
                mailError = "No mail app is set up on this device. Use Share full report instead, or send it to \(DiagnosticsExport.supportAddress)."
            }
        }
    }

    private func buildReport() async {
        isBuildingReport = true
        defer { isBuildingReport = false }
        let env = DiagnosticsExport.environment(tenantId: tenantId)
        var text = await DiagnosticsRecorder.shared.buildReport(
            environment: env,
            includeTenantId: includeTenantId && tenantId != nil
        )
        // The single most useful line for an auth problem. `reportFragment` is fixed keys
        // and allowlisted values only; there is no free text for a description to hide in.
        if let detail = await lastAuthFailure?() {
            text += "\n\nLast sign-in or token failure\n  \(detail.reportFragment)"
        }
        report = text
    }

    // MARK: - about

    private var aboutSection: some View {
        Section("About") {
            LabeledContent("Version", value: Self.versionString)
            if let tenantId, !isDemo {
                // Feeds the organization purchase flow, which is keyed to the tenant. A
                // plain copy, not the expiring local-only pasteboard used for credentials:
                // a tenant ID is public — any domain's is returned by unauthenticated OIDC
                // discovery — and the buyer needs to paste it into a web form.
                Button {
                    UIPasteboard.general.string = tenantId
                    copiedTenantId = true
                } label: {
                    LabeledContent("Tenant ID", value: copiedTenantId ? "Copied" : "Copy")
                }
                .buttonStyle(.plain)
            }
            Link("Privacy policy", destination: URL(string: "https://kainor.com/privacy")!)
            Link("Terms", destination: URL(string: "https://kainor.com/terms")!)
            Link("Source code", destination: URL(string: "https://github.com/Kainor-LLC/LAPSlock")!)
            Text("LAPSlock is not affiliated with, endorsed by, or sponsored by Microsoft Corporation.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - session

    /// Sign out, or leave demo.
    ///
    /// This was missing entirely until 2026-09-02: `signOut()` existed on the root model and
    /// was only reachable from an error-recovery path, so there was no way for a user to end
    /// a session at all. For a tool that reveals administrator passwords that is not a
    /// missing convenience — you could not hand the phone back, and an MSP could not change
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
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "—"
        return "\(v) (\(b))"
    }
}

#Preview("Settings") {
    SettingsView(
        settings: AppSettings.shared,
        requestRotationConsent: { nil },
        isDemo: true,
        tenantId: nil
    )
}
