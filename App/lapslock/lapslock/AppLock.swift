import SwiftUI
import Combine
import PlatformSecurity

// App lock: Face ID over the whole app, distinct from the per-reveal gate.
//
// WHAT IT PROTECTS. Not a credential — those have their own gate, which always runs and is
// not affected by this setting. This protects the DEVICE LIST: hostnames, primary users,
// compliance state, which machines exist. That is reconnaissance for a whole tenant, and it
// is exactly what somebody holding a borrowed unlocked phone would page through.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE HAZARD THIS IS BUILT AROUND, AND WHY THE GRACE PERIOD IS NOT A UX NICETY
//
// Signing in sends the app to the background: MSAL invokes Microsoft Authenticator, the
// user approves, and control returns. Locking on that return would put a Face ID prompt in
// the middle of a sign-in, over a flow that is already the most fragile thing in this app —
// "broker redirects never handled" is a documented past bug here that took two failed fixes.
//
// So the lock does NOT engage on every background. It engages after `graceInterval`, which
// a broker round trip never approaches, and it is additionally suppressed outright while a
// sign-in is in progress. Belt and braces, because the failure mode is a user who cannot
// sign in at all.
//
// It also never re-locks while merely INACTIVE — a notification banner, Control Centre, or
// the Face ID prompt of a credential reveal all pass through `.inactive`, and treating that
// as "the app was put away" would fight the reveal publishing logic in DeviceDetailModel.
// ─────────────────────────────────────────────────────────────────────────────

@MainActor
final class AppLockModel: ObservableObject {

    /// How long the app may sit in the background before it re-locks.
    ///
    /// Long enough that a broker round trip, an Authenticator push, or a glance at a
    /// calendar never costs a second prompt. Short enough that a phone left on a desk is
    /// protected within the span anybody would leave it unattended.
    static let graceInterval: TimeInterval = 5 * 60

    /// True when the app must be unlocked before anything is shown.
    @Published private(set) var isLocked = false
    /// Set when authentication failed, so the screen can offer a retry rather than sit blank.
    @Published private(set) var failureMessage: String?
    @Published private(set) var isAuthenticating = false

    private let gate = BiometricGate()
    private var backgroundedAt: Date?

    /// Locks at launch if the setting is on. Called once, before anything is rendered.
    func armAtLaunch(enabled: Bool) {
        guard enabled else { return }
        isLocked = true
    }

    /// Records scene changes and decides whether to re-lock.
    ///
    /// - Parameter isSigningIn: suppresses locking entirely. A sign-in that takes longer
    ///   than the grace period — hunting for a phone to approve a push — must not come back
    ///   to a lock screen sitting on top of MSAL's flow.
    func sceneChanged(to phase: ScenePhase, enabled: Bool, isSigningIn: Bool) {
        guard enabled else {
            isLocked = false
            return
        }
        switch phase {
        case .background:
            // Only `.background` starts the clock. `.inactive` covers notification banners,
            // Control Centre and the reveal's own Face ID prompt — none of which means the
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

    /// Prompts for Face ID. Failure leaves the app locked — there is no path that unlocks
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
            // explains the situation and lets them through — the per-reveal gate still
            // stands between them and any credential.
            failureMessage = reason
            isLocked = false
        }
    }
}

/// The lock screen. Deliberately says nothing about the tenant, the account, or how many
/// devices are behind it — a lock screen that leaks what it is protecting is decoration.
struct AppLockScreen: View {
    @ObservedObject var model: AppLockModel

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.fill")
                .font(.system(size: 44))
                .foregroundStyle(Brand.accent)
            Text("LAPSlock is locked")
                .font(.title3.weight(.semibold))
            Text("Unlock to see your devices.")
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
        .task { await model.unlock() }
    }
}
