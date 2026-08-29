import SwiftUI
import UIKit
import Combine
import AuthKit
import AuthKitMSAL
import CredentialKit
import InventoryKit
import LicensingKit

// App root. Owns the one decision the rest of the app depends on: which data source
// is in play — a live tenant, or demo mode.
//
// Demo mode exists for three reasons (§ App Store Review Guideline 2.1):
//   1. App Store reviewers cannot sign into a customer's Entra tenant.
//   2. UI can be developed and demonstrated without touching a real tenant.
//   3. Sales conversations can show the product without borrowing someone's devices.
// It is never silent: DemoBanner is pinned to every screen while it's on.
//
// The demo types are reachable from exactly one place: the `.demo` branch of
// AppRootView.content. The `.live` branch cannot construct one, because every service
// it needs comes off a LiveSession and none of those accessors is optional. There is
// no optional left to coalesce a demo double into, which is the point.

@main
struct LAPSlockApp: App {
    // Present only to receive broker redirects. See AppDelegate below.
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            AppRootView()
                .tint(Brand.signal)
                .preferredColorScheme(AppSettings.shared.appearance.colorScheme)
                // THIS is the handler that actually runs. See the note on AppDelegate.
                .onOpenURL { url in
                    MSALRedirect.handle(url, sourceApplication: nil)
                }
        }
    }
}

/// Catches the redirect Microsoft Authenticator sends back after a broker sign-in.
///
/// Read this before deleting either handler.
///
/// This app is scene-based (UIApplicationSceneManifest is in the Info.plist), and SwiftUI
/// installs its own scene delegate. When a scene delegate exists, iOS routes incoming URLs
/// to `scene(_:openURLContexts:)` and never calls `application(_:open:options:)`. So on
/// this app as currently configured, the delegate method below does not fire, and the
/// `.onOpenURL` above is what handles the redirect.
///
/// The symptom when nothing handles it: MSAL invokes the broker, the user authenticates in
/// Authenticator, control returns, and MSAL reports
/// "application did not receive response from broker" (MSALErrorDomain -50000), which the
/// app surfaces as a generic sign-in failure. Invisible in the simulator, which has no
/// broker installed and keeps the whole flow in-process.
///
/// The delegate is kept because it is the correct path if this app ever stops being
/// scene-based or gains a custom scene delegate, and because a duplicate delivery is
/// harmless: MSAL returns false for a URL it has already consumed.
///
/// On `sourceApplication: nil` in the `.onOpenURL` path: SwiftUI does not expose it. MSAL
/// validates broker responses with a nonce instead (the logs show V2-broker-nonce), which
/// is what makes nil acceptable here rather than merely tolerated.
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ app: UIApplication,
        open url: URL,
        options: [UIApplication.OpenURLOptionsKey: Any] = [:]
    ) -> Bool {
        MSALRedirect.handle(
            url,
            sourceApplication: options[.sourceApplication] as? String
        )
    }
}

/// One meter for the whole app, per mode.
///
/// LIVE uses the Keychain store, so the count survives a delete-and-reinstall. That is
/// the entire reason for choosing the Keychain over UserDefaults, and it is the one
/// assumption in the design that has to be verified on real hardware rather than trusted.
///
/// DEMO uses an in-memory store. A reviewer or a prospect exploring fake data must not
/// burn the five reveals they will want for evaluating against their own tenant. It is
/// still metered rather than unlimited, deliberately: App Store review then exercises the
/// countdown and the blocked state, so a reviewer meeting the wall has already seen the
/// count going down and understands what happened. A reviewer surprised by a block they
/// were never warned about is a rejection risk.
@MainActor
enum RevealMeters {
    static let live = RevealMeter(store: KeychainRevealLedgerStore())
    static let demo = RevealMeter(store: InMemoryRevealLedgerStore())
}

@MainActor
final class AppRootModel: ObservableObject {
    enum Mode: Equatable {
        case signedOut
        case demo
        case live(AdminAccount)
    }

    /// Everything the live path needs, bundled so it can only exist as a set.
    ///
    /// The existence of a LiveSession is the proof that authentication succeeded, so
    /// every accessor here returns a non-optional live service. That is deliberate:
    /// the previous shape returned optionals, and the call site — a non-@ViewBuilder
    /// closure returning a concrete DeviceDetailView, which cannot branch — had no way
    /// to handle nil except to coalesce in a demo provider while still reporting
    /// isDemo: false. A revealed value with no banner and no way to tell it was fake
    /// is the one bug this app cannot ship. Hoisting the check up to a place that can
    /// branch removes the possibility rather than documenting it.
    struct LiveSession {
        let auth: MSALAuthManager
        let inventory: DeviceInventoryService

        /// Live credential provider for one platform, sharing the authenticated session.
        func provider(for platform: DevicePlatform) -> any LocalAdminCredentialProviding {
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

        /// Live BitLocker service, sharing the authenticated session.
        func bitLocker() -> any BitLockerKeyProviding {
            BitLockerService(auth: auth)
        }
    }

    @Published var mode: Mode = .signedOut
    @Published var isSigningIn = false
    @Published var consentState: ConsentState?
    @Published var signInError: String?

    /// The authenticated manager. Exposed (read-only) so provider construction can
    /// share the same session rather than creating a second one.
    private(set) var auth: MSALAuthManager?

    /// Live services, created after sign-in so they share the authenticated session.
    /// Nil whenever the app is not signed in.
    private(set) var liveSession: LiveSession?

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
            signInError = "LAPSlock couldn't start its sign-in system. Reinstalling the app usually fixes this."
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
            liveSession = LiveSession(
                auth: auth,
                inventory: DeviceInventoryService(auth: auth)
            )
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
        await liveSession?.inventory.reset()
        liveSession = nil
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
                return "Your organization hasn't approved permission for LAPSlock to modify devices. An Entra administrator needs to grant it."
            }
            if case .userCancelled = error { return "Permission wasn't granted." }
            return "Couldn't request permission. Check your connection and try again."
        } catch {
            return "Couldn't request permission. Check your connection and try again."
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
                model: DeviceListModel(
                    inventory: DemoInventoryProvider(),
                    meter: RevealMeters.demo
                ),
                isDemo: true,
                settingsBuilder: {
                    SettingsView(
                        settings: AppSettings.shared,
                        requestRotationConsent: { nil },   // no tenant in demo mode
                        isDemo: true,
                        tenantId: nil,
                        meter: RevealMeters.demo
                    )
                },
                detailBuilder: { device in
                    DeviceDetailView(
                        model: DeviceDetailModel(
                            device: device,
                            provider: DemoLapsProvider(platform: device.platform),
                            bitLocker: DemoBitLockerService(),
                            isDemo: true,
                            rotationEnabled: AppSettings.shared.bitLockerRotationEnabled,
                            meter: RevealMeters.demo
                        )
                    )
                }
            )

        case .live:
            if let session = root.liveSession {
                DeviceListView(
                    model: DeviceListModel(
                        inventory: session.inventory,
                        meter: RevealMeters.live,
                        isPro: false          // TODO: wire to /entitlement
                    ),
                    isDemo: false,
                    settingsBuilder: {
                        SettingsView(
                            settings: AppSettings.shared,
                            requestRotationConsent: { await root.requestRotationConsent() },
                            isDemo: false,
                            tenantId: root.signedInTenantId,
                            meter: RevealMeters.live,
                            isPro: false          // TODO: wire to /entitlement
                        )
                    },
                    detailBuilder: { device in
                        DeviceDetailView(
                            model: DeviceDetailModel(
                                device: device,
                                provider: session.provider(for: device.platform),
                                bitLocker: session.bitLocker(),
                                isDemo: false,
                                rotationEnabled: AppSettings.shared.bitLockerRotationEnabled,
                                meter: RevealMeters.live,
                                // TODO: wire to the entitlement check once /entitlement
                                // exists. Hardcoded false means everyone is metered,
                                // which is the safe default while there is nothing to
                                // sell — nobody is wrongly given Pro for free.
                                isPro: false
                            )
                        )
                    }
                )
            } else {
                // A .live mode with no session shouldn't happen. Recover to signed out
                // rather than showing a blank screen or substituting a data source.
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
