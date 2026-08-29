import SwiftUI
import Combine
import AuthKit
import CredentialKit
import DiagnosticsKit

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

    var body: some View {
        NavigationStack {
            Form {
                appearanceSection
                rotationSection
                macOSSection
                diagnosticsSection
                aboutSection
            }
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
        report = await DiagnosticsRecorder.shared.buildReport(
            environment: env,
            includeTenantId: includeTenantId && tenantId != nil
        )
    }

    // MARK: - about

    private var aboutSection: some View {
        Section("About") {
            LabeledContent("Version", value: Self.versionString)
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
