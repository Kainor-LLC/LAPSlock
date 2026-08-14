import SwiftUI
import Combine          // ObservableObject / @Published are defined here.
import AuthKit
import AuthKitMSAL
import CredentialKit

// AUTH SMOKE TEST — the smallest thing that proves MSALAuthManager works.
//
// Purpose: MSALAuthManager compiles but has never run. This screen exercises exactly
// the untested path — interactive sign-in, tenant resolution, silent token acquisition,
// and incremental consent — and nothing else. When it works, we build the real app.
//
// What SUCCESS looks like on the Kainor tenant:
//   1. Tap Sign in -> Microsoft web sheet -> sign in as connor@kainor.com
//   2. Consent prompt appears (already granted tenant-wide, so it may be skipped)
//   3. Screen shows your UPN and the Kainor tenant ID
//   4. "Get browse token" succeeds
//   5. "Get reveal token (incremental consent)" succeeds — this proves the scope is
//      requested separately from sign-in (Build Spec §4)
//
// What is EXPECTED to look broken but isn't: there are no devices in the Kainor tenant,
// so nothing here lists devices. Device data comes later, from a tenant with Intune.

@main
struct AuthSmokeTestApp: App {
    var body: some Scene {
        WindowGroup {
            AuthSmokeTestView()
        }
    }
}

@MainActor
final class AuthSmokeTestModel: ObservableObject {
    @Published var status: String = "Not signed in"
    @Published var account: AdminAccount?
    @Published var log: [String] = []
    @Published var busy = false

    private var auth: MSALAuthManager?

    /// Log lines are metadata only. Never log a token or a password (§3.4).
    private func note(_ s: String) {
        log.insert("\(Self.timestamp())  \(s)", at: 0)
    }

    private static func timestamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: Date())
    }

    func prepare() {
        guard auth == nil else { return }
        do {
            auth = try MSALAuthManager(config: .vendorDefault)
            note("MSALAuthManager created. clientId=\(AuthConfiguration.vendorDefault.clientId.prefix(8))…")
            status = "Ready to sign in"
        } catch {
            note("INIT FAILED: \(error)")
            status = "Initialization failed"
        }
    }

    func signIn() async {
        guard let auth else { note("No auth manager"); return }
        busy = true
        defer { busy = false }
        note("Starting interactive sign-in…")
        do {
            let acct = try await auth.signIn()
            account = acct
            status = "Signed in"
            note("SUCCESS. tenantId=\(acct.tenantId)")
        } catch {
            status = "Sign-in failed"
            note("FAILED: \(Self.describe(error))")
        }
    }

    /// Low-privilege scopes granted at sign-in.
    func getBrowseToken() async {
        await getToken(
            scopes: ["DeviceManagementManagedDevices.Read.All"],
            label: "browse token",
            allowInteractive: false
        )
    }

    /// High-privilege scope. Should trigger incremental consent on first use (§4).
    func getRevealToken() async {
        await getToken(
            scopes: [LapsCredentialScopes.reveal],
            label: "reveal token (incremental consent)",
            allowInteractive: true
        )
    }

    private func getToken(scopes: [String], label: String, allowInteractive: Bool) async {
        guard let auth else { note("No auth manager"); return }
        busy = true
        defer { busy = false }
        note("Requesting \(label)…")
        do {
            let token = try await auth.token(scopes: scopes, allowInteractive: allowInteractive)
            // Log only the LENGTH, never any part of the token itself.
            note("SUCCESS: \(label) acquired (\(token.count) chars)")
        } catch {
            note("FAILED (\(label)): \(Self.describe(error))")
        }
    }

    func signOut() async {
        guard let auth, let acct = account else { return }
        busy = true
        defer { busy = false }
        do {
            try await auth.signOut(account: acct)
            account = nil
            status = "Signed out"
            note("Signed out and MSAL cache cleared")
        } catch {
            note("Sign-out FAILED: \(Self.describe(error))")
        }
    }

    /// Human-readable error text. Never includes secret material.
    private static func describe(_ error: Error) -> String {
        if let authError = error as? AuthError {
            switch authError {
            case .noAccount:            return "no account signed in"
            case .interactionRequired:  return "interaction required (silent failed — expected on first run)"
            case .consentRequired:      return "consent required"
            case .userCancelled:        return "cancelled by user"
            case .tenantMismatch:       return "TENANT MISMATCH — cross-tenant guard fired (§3.3)"
            case .underlying(let msg):  return "underlying: \(msg)"
            }
        }
        return String(describing: error)
    }
}

struct AuthSmokeTestView: View {
    @StateObject private var model = AuthSmokeTestModel()

    var body: some View {
        NavigationStack {
            List {
                Section("Status") {
                    LabeledContent("State", value: model.status)
                    if let acct = model.account {
                        LabeledContent("Account", value: acct.username)
                        LabeledContent("Tenant") {
                            Text(acct.tenantId).font(.system(.caption, design: .monospaced))
                        }
                    }
                }

                Section("Actions") {
                    Button("Sign in") { Task { await model.signIn() } }
                        .disabled(model.busy || model.account != nil)

                    Button("Get browse token (silent)") { Task { await model.getBrowseToken() } }
                        .disabled(model.busy || model.account == nil)

                    Button("Get reveal token (incremental consent)") { Task { await model.getRevealToken() } }
                        .disabled(model.busy || model.account == nil)

                    Button("Sign out", role: .destructive) { Task { await model.signOut() } }
                        .disabled(model.busy || model.account == nil)
                }

                Section("Log") {
                    if model.log.isEmpty {
                        Text("No events yet").foregroundStyle(.secondary)
                    }
                    ForEach(model.log, id: \.self) { line in
                        Text(line)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }

                Section {
                    Text("No devices are listed here on purpose. The Kainor tenant has no "
                         + "Intune-managed devices; this screen only validates authentication.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("PitLAPS Auth Test")
            .overlay {
                if model.busy { ProgressView().controlSize(.large) }
            }
        }
        .task { model.prepare() }
    }
}
