import SwiftUI
import Combine
import AuthKit
import AuthKitMSAL
import CredentialKit
import InventoryKit

// App root. Owns the one decision the rest of the app depends on: which data source
// is in play — a live tenant, or demo mode.
//
// Demo mode exists for three reasons (§ App Store Review Guideline 2.1):
//   1. App Store reviewers cannot sign into a customer's Entra tenant.
//   2. UI can be developed and demonstrated without touching a real tenant.
//   3. Sales conversations can show the product without borrowing someone's devices.
// It is never silent: DemoBanner is pinned to every screen while it's on.

@main
struct PitLAPSApp: App {
    var body: some Scene {
        WindowGroup {
            AppRootView()
                .tint(Brand.signal)
                .preferredColorScheme(AppSettings.shared.appearance.colorScheme)
        }
    }
}

@MainActor
final class AppRootModel: ObservableObject {
    enum Mode: Equatable {
        case signedOut
        case demo
        case live(AdminAccount)
    }

    @Published var mode: Mode = .signedOut
    @Published var isSigningIn = false
    @Published var consentState: ConsentState?
    @Published var signInError: String?

    /// The authenticated manager. Exposed (read-only) so provider construction can
    /// share the same session rather than creating a second one.
    private(set) var auth: MSALAuthManager?

    /// Live inventory, created after sign-in so it shares the authenticated session.
    private(set) var liveInventory: DeviceInventoryService?

    /// Tenant of the signed-in account, offered as an opt-in field in diagnostics.
    var signedInTenantId: String? {
        if case .live(let account) = mode { return account.tenantId }
        return nil
    }

    var consentURL: URL? {
        let tenant: String? = {
            if case .live(let account) = mode { return account.tenantId }
            return nil
        }()
        return AdminConsentLink.url(
            clientId: AuthConfiguration.vendorDefault.clientId,
            tenant: tenant
        )
    }

    func prepare() {
        guard auth == nil else { return }
        do {
            auth = try MSALAuthManager(config: .vendorDefault)
        } catch {
            signInError = "PitLAPS couldn't start its sign-in system. Reinstalling the app usually fixes this."
        }
    }

    func signIn() async {
        guard let auth else { return }
        isSigningIn = true
        signInError = nil
        consentState = nil
        defer { isSigningIn = false }

        do {
            let account = try await auth.signIn()
            let inventory = DeviceInventoryService(auth: auth)
            liveInventory = inventory
            mode = .live(account)
        } catch let error as AuthError {
            // Consent problems get a recovery path, not just an error (§8).
            if let state = ConsentDiagnostics.state(from: error) {
                consentState = state
            } else if case .userCancelled = error {
                return                      // user chose not to continue; not an error
            } else if case .tenantMismatch = error {
                signInError = "The sign-in came back for a different organization than expected. Sign in again."
            } else {
                signInError = "Sign-in didn't complete. Check your connection and try again."
            }
        } catch {
            signInError = "Sign-in didn't complete. Check your connection and try again."
        }
    }

    func signOut() async {
        if case .live(let account) = mode, let auth {
            try? await auth.signOut(account: account)
        }
        // Tenant-scoped data must not survive an account change (§7).
        await liveInventory?.reset()
        liveInventory = nil
        mode = .signedOut
        consentState = nil
    }

    func enterDemoMode() {
        mode = .demo
    }

    /// Requests incremental consent for the device-write scope, used when the user turns
    /// on BitLocker rotation. Returns nil on success or a user-facing message on failure.
    ///
    /// Asking here — at the moment the toggle flips — means an admin discovers a blocked
    /// permission while sitting at their desk, not while standing at a broken machine.
    func requestRotationConsent() async -> String? {
        guard let auth else { return "Sign in first." }
        do {
            _ = try await auth.token(scopes: [LapsCredentialScopes.deviceWrite], allowInteractive: true)
            return nil
        } catch let error as AuthError {
            if ConsentDiagnostics.state(from: error) != nil {
                return "Your organization hasn't approved permission for PitLAPS to modify devices. An Entra administrator needs to grant it."
            }
            if case .userCancelled = error { return "Permission wasn't granted." }
            return "Couldn't request permission. Check your connection and try again."
        } catch {
            return "Couldn't request permission. Check your connection and try again."
        }
    }

    /// Live BitLocker service, sharing the authenticated session.
    func liveBitLocker() -> (any BitLockerKeyProviding)? {
        guard let auth else { return nil }
        return BitLockerService(auth: auth)
    }

    /// Live credential provider for one platform, sharing the authenticated session.
    /// Returns nil before sign-in, which the view treats as "recover to signed out"
    /// rather than silently substituting demo data.
    func liveProvider(for platform: DevicePlatform) -> (any LocalAdminCredentialProviding)? {
        guard let auth else { return nil }
        switch platform {
        case .windows:
            return WindowsLapsProvider(auth: auth)
        case .macOS:
            return MacOSLapsProvider(auth: auth)
        case .other:
            // MacOSLapsProvider is not used for iOS devices; the platform seam reports
            // .other as unsupported before any request is made.
            return MacOSLapsProvider(auth: auth)
        }
    }
}

struct AppRootView: View {
    @StateObject private var root = AppRootModel()

    var body: some View {
        content
            .task { root.prepare() }
    }

    @ViewBuilder
    private var content: some View {
        switch root.mode {
        case .signedOut:
            signedOut

        case .demo:
            DeviceListView(
                model: DeviceListModel(inventory: DemoInventoryProvider()),
                isDemo: true,
                settingsBuilder: {
                    SettingsView(
                        settings: AppSettings.shared,
                        requestRotationConsent: { nil },   // no tenant in demo mode
                        isDemo: true,
                        tenantId: nil
                    )
                },
                detailBuilder: { device in
                    DeviceDetailView(
                        model: DeviceDetailModel(
                            device: device,
                            provider: DemoLapsProvider(platform: device.platform),
                            bitLocker: DemoBitLockerService(),
                            isDemo: true,
                            rotationEnabled: AppSettings.shared.bitLockerRotationEnabled
                        )
                    )
                }
            )

        case .live:
            if let inventory = root.liveInventory {
                DeviceListView(
                    model: DeviceListModel(inventory: inventory),
                    isDemo: false,
                    settingsBuilder: {
                        SettingsView(
                            settings: AppSettings.shared,
                            requestRotationConsent: { await root.requestRotationConsent() },
                            isDemo: false,
                            tenantId: root.signedInTenantId
                        )
                    },
                    detailBuilder: { device in
                        DeviceDetailView(
                            model: DeviceDetailModel(
                                device: device,
                                // Falls back to the macOS provider's "unsupported"
                                // reporting if the session vanished mid-navigation.
                                provider: root.liveProvider(for: device.platform)
                                    ?? DemoLapsProvider(platform: device.platform),
                                bitLocker: root.liveBitLocker() ?? DemoBitLockerService(),
                                isDemo: false,
                                rotationEnabled: AppSettings.shared.bitLockerRotationEnabled
                            )
                        )
                    }
                )
            } else {
                // Shouldn't happen; recover rather than showing a blank screen.
                ProgressView().task { await root.signOut() }
            }
        }
    }

    private var signedOut: some View {
        VStack(spacing: 0) {
            SignInView(
                consentState: root.consentState,
                consentURL: root.consentURL,
                isBusy: root.isSigningIn
            ) {
                Task { await root.signIn() }
            }

            if let error = root.signInError {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal, 24)
                    .padding(.bottom, 8)
            }

            // Demo entry lives here so a reviewer (or a prospect) can evaluate the app
            // without a tenant. Understated on purpose — it isn't the primary path.
            Button("Explore with demo data") {
                root.enterDemoMode()
            }
            .font(.footnote.weight(.medium))
            .padding(.bottom, 20)
        }
    }

}

// MARK: - previews

#Preview("Device list (demo)") {
    DeviceListView(
        model: DeviceListModel(inventory: DemoInventoryProvider(latency: .milliseconds(1))),
        isDemo: true,
        settingsBuilder: {
            SettingsView(settings: AppSettings.shared, requestRotationConsent: { nil }, isDemo: true, tenantId: nil)
        },
        detailBuilder: { device in
            DeviceDetailView(
                model: DeviceDetailModel(
                    device: device,
                    provider: DemoLapsProvider(platform: device.platform),
                    bitLocker: DemoBitLockerService(),
                    isDemo: true,
                    rotationEnabled: AppSettings.shared.bitLockerRotationEnabled
                )
            )
        }
    )
}

#Preview("Windows detail (demo)") {
    NavigationStack {
        DeviceDetailView(
            model: DeviceDetailModel(
                device: DemoInventoryProvider.fleet[0],
                provider: DemoLapsProvider(platform: .windows, latency: .milliseconds(1)),
                bitLocker: DemoBitLockerService(latency: .milliseconds(1)),
                isDemo: true,
                rotationEnabled: true
            )
        )
    }
}

#Preview("Windows, not Entra-joined") {
    NavigationStack {
        DeviceDetailView(
            model: DeviceDetailModel(
                device: DemoInventoryProvider.fleet[4],
                provider: DemoLapsProvider(platform: .windows, latency: .milliseconds(1)),
                bitLocker: DemoBitLockerService(latency: .milliseconds(1)),
                isDemo: true,
                rotationEnabled: true
            )
        )
    }
}

#Preview("macOS detail (reveal unavailable)") {
    NavigationStack {
        DeviceDetailView(
            model: DeviceDetailModel(
                device: DemoInventoryProvider.fleet[5],
                provider: DemoLapsProvider(platform: .macOS, latency: .milliseconds(1)),
                bitLocker: DemoBitLockerService(latency: .milliseconds(1)),
                isDemo: true,
                rotationEnabled: true
            )
        )
    }
}
