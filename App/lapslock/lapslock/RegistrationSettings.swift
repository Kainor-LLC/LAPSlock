import SwiftUI
import AuthKit

/// What Settings needs to know about the app registrations, injected so Settings does not
/// know about the sign-in manager. Nil in demo mode and while signed out.
struct SettingsRegistrations {
    /// This install signed in before the split and its organization has not approved the
    /// read-only app yet.
    var readsThroughOriginal: Bool
    /// How many customer organizations this person has saved. Finishing the update moves
    /// reads to the read-only app for all of them at once, so a provider is told first.
    var customerCount: Int = 0
    /// Signs into the read-only app. Nil on success, or a sentence to show.
    var finishReadUpgrade: () async -> String?
    /// The link an administrator approves the read-only app with.
    var readConsentURL: URL?
    var writeRouteChoice: WriteRouteChoice
    var setWriteRouteChoice: (WriteRouteChoice) async -> Void
}

/// Shown at the top of Settings while an install from before the split waits for its
/// organization to approve the read-only app.
struct ReadUpgradeSection: View {
    let registrations: SettingsRegistrations

    @State private var working = false
    @State private var message: String?

    var body: some View {
        Section {
            Text("TenantKeep now signs in through a read-only app, with separate apps for actions. Your organization has not approved the read-only app yet, so this device still uses the earlier sign-in. Everything you could do before still works.")
                .font(.callout)
            if registrations.customerCount > 0 {
                Label {
                    Text("You also work in customer organizations. Finish updating moves this device to the read-only app for every one of them, so approve it in each customer first. A customer that has not approved it stops working on this device until it does.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle")
                }
                .font(.callout)
            }
            Button {
                Task {
                    working = true
                    message = await registrations.finishReadUpgrade()
                    working = false
                }
            } label: {
                HStack {
                    Text("Finish updating")
                    if working { Spacer(); ProgressView() }
                }
            }
            .disabled(working)
            if let url = registrations.readConsentURL {
                ShareLink(item: url) {
                    Label("Share the approval link", systemImage: "square.and.arrow.up")
                }
            }
            if let message {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Update Waiting")
        } footer: {
            Text("An Entra administrator approves the read-only app once, at tenantkeep.app/consent or with the link above. Then choose Finish updating.")
        }
    }
}

/// Which app registration this organization's actions go through, for the rare case the
/// app cannot read it.
struct WriteRouteSection: View {
    let registrations: SettingsRegistrations

    @State private var choice: WriteRouteChoice = .automatic

    var body: some View {
        Section {
            Picker("Apps for actions", selection: $choice) {
                ForEach(WriteRouteChoice.allCases) { option in
                    Text(option.label).tag(option)
                }
            }
            .onChange(of: choice) { _, new in
                Task { await registrations.setWriteRouteChoice(new) }
            }
        } header: {
            Text("How Your Organization Approved Actions")
        } footer: {
            Text("An organization approves actions one of two ways: a separate app for each kind of action, or one app, TenantKeep Actions, for all of them. Automatic reads which it chose. Set it yourself only if TenantKeep cannot read it and a switch below says approval is needed when it is not.")
        }
        .onAppear { choice = registrations.writeRouteChoice }
    }
}

/// One line across the top of the app while the read-only app waits for approval.
struct ReadUpgradeBanner: View {
    var body: some View {
        Label("Update waiting: your organization needs to approve the new TenantKeep app. See Settings.",
              systemImage: "arrow.triangle.2.circlepath.circle")
            .font(.footnote)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(.thinMaterial)
            .accessibilityAddTraits(.isStaticText)
    }
}
