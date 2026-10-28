import SwiftUI
import UIKit
import PlatformSecurity

// App lock: Face ID over the whole app, distinct from the per-reveal gate.
//
// What it protects: not a credential. Those have their own gate, which always runs and is
// not affected by this setting. This protects the DEVICE LIST: hostnames, primary users,
// compliance state, which machines exist. That is reconnaissance for a whole tenant, and it
// is exactly what somebody holding a borrowed unlocked phone would page through.
//
// THE HAZARD THIS IS BUILT AROUND, AND WHY THE GRACE PERIOD IS NOT A UX NICETY
//
// Signing in sends the app to the background: MSAL invokes Microsoft Authenticator, the
// user approves, and control returns. Locking on that return would put a Face ID prompt in
// the middle of a sign-in, over a flow that is already the most fragile thing in this app, 
// "broker redirects never handled" is a documented past bug here that took two failed fixes.
//
// So the lock does NOT engage on every background. It engages after `graceInterval`, which
// a broker round trip never approaches, and it is additionally suppressed outright while a
// sign-in is in progress. Belt and braces, because the failure mode is a user who cannot
// sign in at all.
//
// It also never re-locks while merely INACTIVE, a notification banner, Control Centre, or
// the Face ID prompt of a credential reveal all pass through `.inactive`, and treating that
// as "the app was put away" would fight the reveal publishing logic in DeviceDetailModel.

@MainActor
@Observable
final class AppLockModel {

    /// How long the app may sit in the background before it re-locks.
    ///
    /// Long enough that a broker round trip, an Authenticator push, or a glance at a
    /// calendar never costs a second prompt. Short enough that a phone left on a desk is
    /// protected within the span anybody would leave it unattended.
    ///
    /// A DEBUG build launched with `-LAPSlockLockGraceSeconds N` uses N instead, so an
    /// automated pass can see the lock engage without leaving the app for five minutes.
    static let graceInterval: TimeInterval = {
        #if DEBUG
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "-LAPSlockLockGraceSeconds"), i + 1 < args.count, let n = TimeInterval(args[i + 1]) {
            return max(1, n)
        }
        #endif
        return 5 * 60
    }()

    /// True when the app must be unlocked before anything is shown.
    private(set) var isLocked = false
    /// Set when authentication failed, so the screen can offer a retry rather than sit blank.
    private(set) var failureMessage: String?
    private(set) var isAuthenticating = false

    @ObservationIgnored private let gate = BiometricGate()
    @ObservationIgnored private var backgroundedAt: Date?

    /// Locks at launch if the setting is on. Called once, before anything is rendered.
    func armAtLaunch(enabled: Bool) {
        guard enabled else { return }
        isLocked = true
    }

    /// Records scene changes and decides whether to re-lock.
    ///
    /// - Parameter isSigningIn: suppresses locking entirely. A sign-in that takes longer
    ///   than the grace period, hunting for a phone to approve a push, must not come back
    ///   to a lock screen sitting on top of MSAL's flow.
    func sceneChanged(to phase: ScenePhase, enabled: Bool, isSigningIn: Bool) {
        guard enabled else {
            isLocked = false
            return
        }
        switch phase {
        case .background:
            // Only `.background` starts the clock. `.inactive` covers notification banners,
            // Control Centre and the reveal's own Face ID prompt, none of which means the
            // app was put away.
            backgroundedAt = Date()
        case .active:
            guard !isSigningIn, let since = backgroundedAt else { return }
            backgroundedAt = nil
            if Date().timeIntervalSince(since) >= Self.graceInterval {
                isLocked = true
            }
        case .inactive:
            break
        @unknown default:
            break
        }
    }

    /// Prompts for Face ID. Failure leaves the app locked, there is no path that unlocks
    /// without a successful authentication.
    func unlock() async {
        guard !isAuthenticating else { return }
        isAuthenticating = true
        failureMessage = nil
        defer { isAuthenticating = false }

        switch await gate.authenticate(deviceName: nil) {
        case .authenticated:
            isLocked = false
        case .cancelledByUser, .fallbackDismissed:
            // Silent: the user dismissed the prompt and can tap Unlock again.
            break
        case .failed:
            failureMessage = "That didn't match. Try again."
        case .unavailable(let reason):
            // The device lost its passcode or biometrics after the setting was turned on.
            // Staying locked forever would strand somebody out of their own app, so this
            // explains the situation and lets them through, the per-reveal gate still
            // stands between them and any credential.
            failureMessage = reason
            isLocked = false
        }
    }
}

/// The lock, in a window of its own above everything else in its scene.
///
/// Drawn as a view in the app's own hierarchy, the lock sat UNDER anything that hierarchy
/// presents: a sheet left open when the phone was put down (Settings with Sign out, the
/// organization list, cross-tenant results naming devices and people) stayed visible and
/// usable on top of it, and so did alerts and the switch notice. A window above the alert
/// level covers all of them. It is made key while locked, so a hardware keyboard's
/// shortcuts reach the lock rather than the app behind it, and its content is modal to
/// VoiceOver. Unlocking hides it and hands key status back to the app's window, so the
/// admin lands exactly where they were, open sheet included.
///
/// One per scene: each iPad window has its own root view, its own lock and its own
/// presenter.
@MainActor
final class AppLockPresenter {
    private weak var scene: UIWindowScene?
    private var model: AppLockModel?
    private var window: UIWindow?
    private var locked = false
    /// The app's own windows, hidden from VoiceOver while locked. Hiding the window rather
    /// than a view reaches what the window presents too: a sheet is not inside the root
    /// view, so marking the root view hidden left an open sheet readable under the lock.
    private var silenced: [UIWindow] = []

    func attach(to scene: UIWindowScene, model: AppLockModel) {
        guard self.scene !== scene else { return }
        self.scene = scene
        self.model = model
        apply()
    }

    func setLocked(_ locked: Bool) {
        self.locked = locked
        apply()
    }

    private func apply() {
        if locked {
            guard window == nil, let scene, let model else { return }
            let host = UIHostingController(rootView: AppLockScreen(model: model))
            host.view.accessibilityViewIsModal = true
            let lockWindow = UIWindow(windowScene: scene)
            lockWindow.overrideUserInterfaceStyle = AppSettings.shared.appearance.interfaceStyle
            lockWindow.windowLevel = .alert + 1
            lockWindow.rootViewController = host
            silenced = scene.windows.filter { $0.windowLevel == .normal && !$0.accessibilityElementsHidden }
            silenced.forEach { $0.accessibilityElementsHidden = true }
            lockWindow.makeKeyAndVisible()
            window = lockWindow
        } else if let lockWindow = window {
            lockWindow.isHidden = true
            window = nil
            silenced.forEach { $0.accessibilityElementsHidden = false }
            silenced = []
            scene?.windows
                .first { $0 !== lockWindow && $0.windowLevel == .normal && !$0.isHidden }?
                .makeKey()
        }
    }
}

/// Reports the window and scene a view is shown in: the window at once, during the layout
/// pass that adds the view, so a setting applied to it is there for the first frame; the
/// scene a moment later, so the lock can put its own window there.
struct WindowSceneReader: UIViewRepresentable {
    var window: (@MainActor (UIWindow) -> Void)? = nil
    let found: @MainActor (UIWindowScene) -> Void

    func makeUIView(context: Context) -> ReaderView { ReaderView(window: window, found: found) }
    func updateUIView(_ view: ReaderView, context: Context) {}

    final class ReaderView: UIView {
        private let onWindow: (@MainActor (UIWindow) -> Void)?
        private let found: @MainActor (UIWindowScene) -> Void

        init(window: (@MainActor (UIWindow) -> Void)?, found: @escaping @MainActor (UIWindowScene) -> Void) {
            self.onWindow = window
            self.found = found
            super.init(frame: .zero)
            isUserInteractionEnabled = false
            isAccessibilityElement = false
        }

        required init?(coder: NSCoder) { nil }

        override func didMoveToWindow() {
            super.didMoveToWindow()
            guard let window, let scene = window.windowScene else { return }
            onWindow?(window)
            // After this layout pass, not during it: attaching can create and key a window.
            Task { @MainActor [found] in found(scene) }
        }
    }
}

/// The lock screen. Deliberately says nothing about the tenant, the account, or how many
/// devices are behind it, a lock screen that leaks what it is protecting is decoration.
struct AppLockScreen: View {
    let model: AppLockModel
    /// Off for the fallback copy drawn inside the app, so only the window's copy prompts.
    var promptsOnAppear = true

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.fill")
                .font(.system(size: 44))
                .foregroundStyle(Brand.accent)
            Text("TenantKeep is locked")
                .font(.title3.weight(.semibold))
            Text("Unlock to continue.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            if let failure = model.failureMessage {
                Text(failure)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Button {
                Task { await model.unlock() }
            } label: {
                HStack(spacing: 8) {
                    if model.isAuthenticating { ProgressView() }
                    Text(model.isAuthenticating ? "Unlocking…" : "Unlock")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.isAuthenticating)
            .padding(.horizontal, 40)
            .padding(.top, 8)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.systemBackground))
        // Prompt immediately, so the common case is Face ID appearing on its own and the
        // button existing only for a retry.
        .task {
            guard promptsOnAppear else { return }
            await model.unlock()
        }
    }
}
