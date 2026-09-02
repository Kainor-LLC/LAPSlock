import SwiftUI
import Combine
import AuthKit
import CredentialKit
import DiagnosticsKit
import LicensingKit

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

    @Published var appearance: AppearancePreference {
        didSet { UserDefaults.standard.set(appearance.rawValue, forKey: Keys.appearance) }
    }

    private enum Keys {
        static let rotation = "settings.bitLockerRotationEnabled"
        static let appearance = "settings.appearance"
    }

    private init() {
        self.bitLockerRotationEnabled = UserDefaults.standard.bool(forKey: Keys.rotation)
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

    // Organization license
    @State private var license: EntitlementState = .free
    @State private var isLicenseActivated = false
    @State private var isFetchingLicense = false
    @State private var licenseMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                appearanceSection
                rotationSection
                macOSSection
                freeTierSection
                licenseSection
                diagnosticsSection
                aboutSection
                #if DEBUG
                debugSection
                #endif
            }
            .task { refreshMeter(); refreshLicense() }
            .navigationTitle("Settings")
            .toolbarBackground(.visible, for: .navigationBar)
            // Attached to the NavigationStack, not to the Section. A Section re-renders
            // on every form state change, which dismissed the sheet the instant it opened.
            .sheet(isPresented: $showingReport) {
                reportPreview
            }
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
                if isLicenseActivated {
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
                        Label("Activate organization license", systemImage: "checkmark.seal")
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
                Text(isLicenseActivated
                    ? """
                      Your license is keyed to this Microsoft tenant and checked against \
                      Kainor about once a month. Nothing about which devices or credentials \
                      you look at is ever sent.
                      """
                    : """
                      An organization license is keyed to your Microsoft tenant. Until you \
                      activate one, LAPSlock never contacts Kainor: it talks to Microsoft and \
                      nothing else, which you can confirm with a network proxy.
                      """)
            }
        }
    }

    private func refreshLicense() {
        guard let entitlement else { return }
        isLicenseActivated = entitlement.isActivated
        license = entitlement.state(signedInTenantId: tenantId)
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
