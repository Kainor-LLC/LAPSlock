import SwiftUI

struct SettingsAboutPage: View {
    let tenantId: String?
    let isDemo: Bool
    @State private var copiedTenantId = false

    var body: some View {
        Form {
            aboutSection
        }
        .navigationTitle("About")
    }

    // MARK: - about

    private var aboutSection: some View {
        Section {
            LabeledContent("Version", value: SettingsView.versionString)
            if let tenantId, !isDemo {
                // Feeds the organization purchase flow, which is keyed to the tenant. A
                // plain copy, not the expiring local-only pasteboard used for credentials:
                // a tenant ID is public, any domain's is returned by unauthenticated OIDC
                // discovery, and the buyer needs to paste it into a web form.
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
            Text("TenantKeep On-Call is not affiliated with, endorsed by, or sponsored by Microsoft Corporation.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
