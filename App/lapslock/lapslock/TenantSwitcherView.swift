import SwiftUI
import AuthKit

// The MSP tenant picker.
//
// WRITTEN FOR A USER NOBODY CAN HELP.
//
// The end-to-end MSP path cannot be tested here: guest access needs a second tenant that
// has invited this account, and GDAP needs a real partner relationship. So the first person
// to exercise this screen is a paying customer, with no support channel yet and no way to
// ask what a failure meant.
//
// That sets the design rule for this file: **every failure names what happened and what to
// do next, on screen, with no reference to anything outside it.** The one that matters most
// is consent — app consent is per-tenant, so an MSP cannot self-serve into a customer's
// directory, and "it didn't work" would be an unanswerable support email. That case gets a
// full explanation and a shareable approval link.

struct TenantSwitcherView: View {

    /// The signed-in account's own organization. Always the first row, never removable.
    let homeTenantId: String
    let homeLabel: String
    /// The tenant currently being operated in.
    let operatingTenantId: String?
    let saved: [TenantReference]

    /// Resolves a domain or GUID. Returns the tenant ID.
    let resolve: (String) async -> Result<String, TenantDirectoryError>
    /// Switches to a tenant, or back home when nil. Returns nil on success.
    let switchTo: (String?) async -> AuthError?
    let remember: (TenantReference) -> Void
    let forget: (String) -> Void
    /// Builds the per-tenant admin consent URL.
    let consentURL: (String) -> URL?

    @Environment(\.dismiss) private var dismiss
    @State private var entry = ""
    @State private var isWorking = false
    @State private var failure: SwitchFailure?
    @State private var pendingConsentTenant: String?

    var body: some View {
        NavigationStack {
            Form {
                currentSection
                addSection
                if let failure { failureSection(failure) }
                savedSection
                explanationSection
            }
            .navigationTitle("Organization")
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .disabled(isWorking)
            .overlay { if isWorking { ProgressView().controlSize(.large) } }
        }
    }

    // MARK: - current

    private var currentSection: some View {
        Section {
            row(label: homeLabel, tenantId: homeTenantId, isHome: true)
        } header: {
            Text("Your organization")
        }
    }

    @ViewBuilder
    private func row(label: String, tenantId: String, isHome: Bool) -> some View {
        let isCurrent = tenantId.lowercased() == operatingTenantId?.lowercased()
        Button {
            Task { await performSwitch(to: isHome ? nil : tenantId, label: label) }
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(label)
                    // The GUID, small and secondary. An admin needs it when talking to a
                    // customer or to Microsoft support, and it is the only unambiguous
                    // identifier for a directory.
                    Text(tenantId).font(Brand.data(11)).foregroundStyle(.secondary)
                }
                Spacer()
                if isCurrent {
                    Image(systemName: "checkmark").foregroundStyle(Brand.accent)
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(isCurrent)
    }

    // MARK: - add

    private var addSection: some View {
        Section {
            TextField("contoso.com", text: $entry)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .submitLabel(.go)
                .onSubmit { Task { await addAndSwitch() } }
            Button {
                Task { await addAndSwitch() }
            } label: {
                Label("Add and switch", systemImage: "plus.circle")
            }
            .disabled(entry.trimmingCharacters(in: .whitespaces).isEmpty || isWorking)
        } header: {
            Text("Add a customer organization")
        } footer: {
            Text("A domain such as contoso.com, or a tenant ID if you have it.")
        }
    }

    // MARK: - failure, which is the part that has to work without help

    @ViewBuilder
    private func failureSection(_ failure: SwitchFailure) -> some View {
        Section {
            Text(failure.title).font(.subheadline.weight(.semibold))
            Text(failure.explanation).font(.footnote).foregroundStyle(.secondary)

            if failure.isConsent, let tenant = pendingConsentTenant, let url = consentURL(tenant) {
                // The whole reason this section exists. Consent is granted per tenant by
                // that tenant's own administrator, so there is nothing the MSP can do in
                // this app except get the link to the right person.
                ShareLink(item: url) {
                    Label("Send the approval link to their administrator", systemImage: "square.and.arrow.up")
                }
                Link(destination: url) {
                    Label("Open the approval page", systemImage: "safari")
                }
            }
        } header: {
            Text("Couldn't switch")
        }
    }

    // MARK: - saved

    @ViewBuilder
    private var savedSection: some View {
        if !saved.isEmpty {
            Section {
                ForEach(saved) { tenant in
                    row(label: tenant.label, tenantId: tenant.tenantId, isHome: false)
                        .swipeActions {
                            Button(role: .destructive) { forget(tenant.tenantId) } label: {
                                Label("Forget", systemImage: "trash")
                            }
                        }
                }
            } header: {
                Text("Customer organizations")
            } footer: {
                Text("""
                    Kept on this device only. LAPSlock never sends this list anywhere — \
                    which organizations you work with is your business, not ours.
                    """)
            }
        }
    }

    private var explanationSection: some View {
        Section {
            Text("""
                Switching changes which organization's devices you see. The device list is \
                cleared, and any password on screen is discarded.

                Each customer's Entra administrator has to approve LAPSlock in their own \
                organization once before you can work in it. That is Microsoft's consent \
                model, not a LAPSlock setting.

                LAPSlock returns to your own organization when you reopen it.
                """)
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    // MARK: - actions

    private func addAndSwitch() async {
        let typed = entry.trimmingCharacters(in: .whitespaces)
        guard !typed.isEmpty else { return }

        isWorking = true
        failure = nil
        pendingConsentTenant = nil

        switch await resolve(typed) {
        case .failure(let error):
            isWorking = false
            failure = SwitchFailure(directory: error, typed: typed)
        case .success(let tenantId):
            isWorking = false
            await performSwitch(to: tenantId, label: typed, rememberOnSuccess: true)
        }
    }

    private func performSwitch(to tenantId: String?, label: String, rememberOnSuccess: Bool = false) async {
        isWorking = true
        failure = nil
        defer { isWorking = false }

        if let error = await switchTo(tenantId) {
            pendingConsentTenant = tenantId
            failure = SwitchFailure(auth: error, typed: label)
            return
        }

        if rememberOnSuccess, let tenantId {
            remember(TenantReference(tenantId: tenantId, label: label))
        }
        dismiss()
    }
}

/// A failure the user can act on, in their words rather than Microsoft's.
struct SwitchFailure: Equatable {
    let title: String
    let explanation: String
    let isConsent: Bool

    init(directory error: TenantDirectoryError, typed: String) {
        isConsent = false
        switch error {
        case .malformedInput:
            title = "That doesn't look like a domain"
            explanation = "Enter a domain such as contoso.com, or a tenant ID. \"\(typed)\" is neither."
        case .notFound:
            title = "No Microsoft organization found for \(typed)"
            explanation = """
                Check the spelling. If it is right, the domain may not be a verified domain \
                in that organization's Microsoft tenant — ask them for their tenant ID and \
                enter that instead.
                """
        case .network:
            title = "Couldn't reach Microsoft"
            explanation = "Check the connection and try again. Nothing was changed."
        }
    }

    init(auth error: AuthError, typed: String) {
        switch error {
        case .consentRequired:
            isConsent = true
            title = "\(typed) hasn't approved LAPSlock yet"
            explanation = """
                Microsoft requires each organization's own administrator to approve an app \
                before anyone can use it there — including you, and including with delegated \
                admin rights. Send them the link below. They approve once, and it works from \
                then on.
                """
        case .tenantMismatch:
            isConsent = false
            title = "Microsoft returned the wrong organization"
            explanation = """
                LAPSlock asked for \(typed) and got a token for a different organization, so \
                it refused it. Nothing was changed. This is a safety check working; if it \
                keeps happening, send a diagnostics report from Settings.
                """
        case .userCancelled:
            isConsent = false
            title = "Sign-in was cancelled"
            explanation = "Nothing was changed. You are still in the organization you started in."
        case .noAccount:
            isConsent = false
            title = "Not signed in"
            explanation = "Sign in before switching organizations."
        case .interactionRequired:
            isConsent = false
            title = "Microsoft needs you to sign in again"
            explanation = "Your access to \(typed) needs a fresh sign-in. Try once more."
        case .underlying:
            isConsent = false
            title = "Couldn't switch to \(typed)"
            explanation = """
                Microsoft refused the request. The most common reasons are that your account \
                has no access to that organization, or that its administrator has not \
                approved LAPSlock there. A diagnostics report from Settings will say which.
                """
        }
    }
}
