import SwiftUI
import AuthKit

// Build Spec §4, §8 — the first screen anyone sees.
//
// DESIGN DECISION: the explainer is the sign-in screen, not a separate interstitial.
// An extra screen before a button gets skipped or resented. Here the same information
// is read while the person is deciding whether to tap, at zero added friction.
//
// This is also the rare product where a pre-auth explainer is worth the space:
//   * the entire audience is IT administrators, who read permission text
//   * the consent screen for an app that reads administrator passwords is alarming
//     without context, and an abandoned consent is a lost customer
//   * admin-ness can't be detected before sign-in, so the "you may need approval"
//     framing has to come first
//
// The copy states what the app can do and, more importantly, what it structurally
// cannot: there is no Kainor server in the credential path.

public struct SignInView: View {
    /// Called when the user taps the primary button.
    let onSignIn: () -> Void
    /// Non-nil when a previous attempt failed in a way the user can act on.
    let consentState: ConsentState?
    /// Shareable admin-approval link, when we have one to offer.
    let consentURL: URL?
    let isBusy: Bool

    @State private var showingApprovalSheet = false

    public init(
        consentState: ConsentState? = nil,
        consentURL: URL? = nil,
        isBusy: Bool = false,
        onSignIn: @escaping () -> Void
    ) {
        self.consentState = consentState
        self.consentURL = consentURL
        self.isBusy = isBusy
        self.onSignIn = onSignIn
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                header

                if let consentState, consentState != .granted {
                    consentBanner(consentState)
                }

                capabilities
                assurances
                approvalNote

                Spacer(minLength: 8)
            }
            .padding(24)
        }
        .safeAreaInset(edge: .bottom) {
            signInButton
                .padding(.horizontal, 24)
                .padding(.top, 12)
                .padding(.bottom, 24)
                .background(.bar)
        }
        .sheet(isPresented: $showingApprovalSheet) {
            AdminApprovalSheet(consentURL: consentURL)
        }
    }

    // MARK: - sections

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("PitLAPS")
                .font(.largeTitle.bold())
            Text("Local administrator passwords from Microsoft Entra ID and Intune, on the device you actually carry.")
                .font(.body)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 12)
    }

    private func consentBanner(_ state: ConsentState) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(state.title, systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)
            Text(state.explanation)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            if let label = state.actionLabel {
                Button(label) { showingApprovalSheet = true }
                    .font(.subheadline.weight(.semibold))
            }
        }
        .padding(16)
        .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
    }

    private var capabilities: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("What PitLAPS asks for")
                .font(.headline)
            InfoRow(
                icon: "laptopcomputer.and.iphone",
                title: "Read your device inventory",
                detail: "So you can search for a device by name, user, or serial number."
            )
            InfoRow(
                icon: "key.fill",
                title: "Read local administrator passwords",
                detail: "Requested separately, the first time you tap Reveal — not when you sign in."
            )
        }
    }

    private var assurances: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("How it stays safe")
                .font(.headline)
            InfoRow(
                icon: "network.slash",
                title: "No Kainor server in the path",
                detail: "Passwords travel from Microsoft Graph straight to this device. We can't see, store, or log them."
            )
            InfoRow(
                icon: "person.badge.key.fill",
                title: "Your roles still decide",
                detail: "PitLAPS acts as you. Without a directory role that can read passwords, it can't either — including just-in-time roles activated through PIM."
            )
            InfoRow(
                icon: "doc.text.magnifyingglass",
                title: "Every retrieval is audited",
                detail: "Reads appear in your own tenant's audit log, exactly as they would from the admin center."
            )
            InfoRow(
                icon: "faceid",
                title: "Face ID before every reveal",
                detail: "Passwords stay hidden until you confirm, auto-hide after a minute, and are cleared when the app leaves the foreground."
            )
        }
    }

    private var approvalNote: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("First time in your organization?")
                .font(.headline)
            Text("An Entra administrator approves PitLAPS once for everyone. If you're approving now, choose **Consent on behalf of your organization** — without it, PitLAPS will work only for your own account and your team will be blocked.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Button("Send the approval link to an administrator") {
                showingApprovalSheet = true
            }
            .font(.subheadline.weight(.semibold))
        }
        .padding(16)
        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }

    private var signInButton: some View {
        Button(action: onSignIn) {
            HStack {
                if isBusy {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "person.crop.circle.badge.checkmark")
                }
                Text(isBusy ? "Signing in…" : "Sign in with Microsoft")
                    .fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
        }
        .buttonStyle(.borderedProminent)
        .disabled(isBusy)
    }
}

// MARK: - supporting views

private struct InfoRow: View {
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .font(.title3)
                .frame(width: 28)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.subheadline.weight(.semibold))
                Text(detail).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}

/// Presents the forwardable approval request so an admin can hand it to whoever holds
/// Global Administrator or Privileged Role Administrator.
struct AdminApprovalSheet: View {
    let consentURL: URL?
    @Environment(\.dismiss) private var dismiss

    private var message: String {
        AdminConsentLink.requestMessage(consentURL: consentURL)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text("Approving PitLAPS")
                        .font(.title2.bold())

                    Text("PitLAPS needs a one-time approval from a Microsoft Entra administrator. Approving from the link below grants access for the whole organization.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    if let consentURL {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Approval link").font(.headline)
                            Text(consentURL.absoluteString)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .padding(12)
                                .background(Color.secondary.opacity(0.08),
                                            in: RoundedRectangle(cornerRadius: 8))
                        }
                        ShareLink(item: consentURL, message: Text(message)) {
                            Label("Share with an administrator", systemImage: "square.and.arrow.up")
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                        }
                        .buttonStyle(.borderedProminent)
                    } else {
                        // Without a resolved tenant we can't build a tenant-specific link,
                        // so hand over the message and let them sign in to resolve it.
                        ShareLink(item: message) {
                            Label("Share the request", systemImage: "square.and.arrow.up")
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                        }
                        .buttonStyle(.borderedProminent)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Who can approve").font(.headline)
                        Text("Global Administrator or Privileged Role Administrator. Reading local administrator passwords is an admin-restricted permission in Microsoft Entra ID, so it can't be self-approved by an ordinary user.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(24)
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

// MARK: - previews

#Preview("Sign in") {
    SignInView { }
}

#Preview("Approval required") {
    SignInView(
        consentState: .organizationApprovalRequired,
        consentURL: AdminConsentLink.url(clientId: "abc-123", tenant: "contoso.com")
    ) { }
}

#Preview("Granted for one user only") {
    SignInView(
        consentState: .grantedForThisUserOnly,
        consentURL: AdminConsentLink.url(clientId: "abc-123", tenant: "contoso.com")
    ) { }
}
