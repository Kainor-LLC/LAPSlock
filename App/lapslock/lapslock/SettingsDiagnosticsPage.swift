import SwiftUI
import AuthKit
import DiagnosticsKit

/// The diagnostics report: gather, read, then email or share.
struct SettingsDiagnosticsPage: View {
    /// Tenant id of the signed-in account, offered as an opt-in field in the report.
    let tenantId: String?
    /// The most recent MSAL failure, allowlisted, read at export time.
    var lastAuthFailure: (() async -> AuthFailureDetail?)? = nil

    @State private var includeTenantId = false
    @State private var report: String?
    @State private var isBuildingReport = false
    @State private var showingReport = false
    @State private var mailError: String?
    @Environment(\.openURL) private var openURL

    var body: some View {
        Form {
            diagnosticsSection
        }
        .navigationTitle("Diagnostics")
        // On the page, not the Section, for the same reason as the role activation sheet.
        .sheet(isPresented: $showingReport) {
            reportPreview
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
        } footer: {
            VStack(alignment: .leading, spacing: 8) {
                Text("Collects what happened, not what you saw: operation outcomes, HTTP status codes, and Microsoft Graph request IDs. It contains no passwords, recovery keys, usernames, device names, or response data. Those cannot be represented in the report at all.")
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
            subject: DiagnosticsExport.subject(appVersion: SettingsView.versionString),
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
}
