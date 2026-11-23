import SwiftUI
import AuthKit

/// What Settings needs to know about the app registrations, injected so Settings does not
/// know about the sign-in manager. Nil in demo mode and while signed out.
struct SettingsRegistrations {
    /// This install signed in before the split, and this has not moved to the read-only
    /// app yet: the person's own organization, or afterwards the customer being worked in.
    /// Nil when nothing is waiting.
    var waiting: ReadUpdate?
    /// The person is working in a customer organization, not their own.
    var awayFromHome = false
    /// How many customer organizations this person has saved. Each moves on its own, when
    /// its administrator approves, so a provider is told that none of them stops working.
    var customerCount: Int = 0
    /// Signs into the read-only app, in the organization `waiting` names. Nil on success,
    /// or a sentence to show.
    var finishReadUpgrade: () async -> String?
    /// The link that organization's administrator approves the read-only app with.
    var readConsentURL: URL?
    var writeRouteChoice: WriteRouteChoice
    var setWriteRouteChoice: (WriteRouteChoice) async -> Void
}

/// Shown at the top of Settings while an install from before the split waits for an
/// organization to approve the read-only app: the person's own first, then each customer
/// in its own time.
struct ReadUpgradeSection: View {
    let registrations: SettingsRegistrations

    @State private var working = false
    @State private var message: String?

    private var forCustomer: Bool { registrations.waiting == .thisCustomer }

    var body: some View {
        Section {
            if forCustomer {
                Text("Your own organization has moved to the read-only TenantKeep app. This customer has not approved it yet, so here this device still uses the earlier sign-in. Everything you could do before still works.")
                    .font(.callout)
            } else {
                Text("TenantKeep now signs in through a read-only app, with separate apps for actions. Your organization has not approved the read-only app yet, so this device still uses the earlier sign-in. Everything you could do before still works.")
                    .font(.callout)
                if registrations.awayFromHome {
                    Text("Finish updating signs in to your own organization, not the customer you are working in. Your own organization moves first.")
                        .font(.callout)
                }
                if registrations.customerCount > 0 {
                    Label {
                        Text("You also work in customer organizations. Each one keeps the earlier sign-in until its own administrator approves the read-only app, so none of them stops working when you finish here.")
                    } icon: {
                        Image(systemName: "building.2")
                    }
                    .font(.callout)
                }
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
            if forCustomer {
                Text("This customer's Entra administrator approves the read-only app once, at tenantkeep.app/consent or with the link above. It moves the next time you switch to it, or when you choose Finish updating.")
            } else {
                Text("An Entra administrator approves the read-only app once, at tenantkeep.app/consent or with the link above. Then choose Finish updating.")
            }
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
    var waiting: ReadUpdate = .ownOrganization

    var body: some View {
        Label(waiting == .thisCustomer
                ? "Update waiting: this customer needs to approve the new TenantKeep app. See Settings."
                : "Update waiting: your organization needs to approve the new TenantKeep app. See Settings.",
              systemImage: "arrow.triangle.2.circlepath.circle")
            .font(.footnote)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(.thinMaterial)
            .accessibilityAddTraits(.isStaticText)
    }
}
