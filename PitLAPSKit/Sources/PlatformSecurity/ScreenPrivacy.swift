import Foundation
#if canImport(UIKit)
import UIKit
import SwiftUI
import UniformTypeIdentifiers   // UTType, used for the pasteboard item type.
#endif

// Build Spec §6 — screen-level protections around a revealed credential.
//
// Three distinct leaks, three distinct defenses:
//   1. App-switcher snapshot. iOS photographs your UI when the app backgrounds. If a
//      password is on screen, that image lands in the snapshot cache on disk.
//      Defense: cover the window before the snapshot is taken.
//   2. Screen recording / AirPlay mirroring. A revealed password is streaming to
//      wherever the mirror goes. Defense: detect and revoke.
//   3. Screenshots. Cannot be prevented on iOS. Defense: detect, tell the truth about
//      what just happened, and recommend rotation.
//
// Note on ordering: the snapshot cover must be applied on `.inactive`, not `.background`.
// By the time an app reaches `.background` the snapshot has already been taken.

#if canImport(UIKit)

/// Observes the conditions that make displaying a credential unsafe.
@MainActor
public final class ScreenPrivacyMonitor: ObservableObject {

    /// True while the screen is being recorded, mirrored, or otherwise captured.
    @Published public private(set) var isCaptured: Bool = false
    /// Increments each time the user takes a screenshot. The app observes changes.
    @Published public private(set) var screenshotCount: Int = 0

    /// Called when capture starts, or when a screenshot is taken. The app wires this
    /// to RevealSession.revoke(_:).
    public var onUnsafeCondition: ((RevealRevocation) -> Void)?

    private var observers: [NSObjectProtocol] = []

    public init() {}

    public func start() {
        guard observers.isEmpty else { return }
        let center = NotificationCenter.default

        // Screen capture (recording, mirroring, some remote-control sessions).
        observers.append(center.addObserver(
            forName: UIScreen.capturedDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] note in
            // Read from the notification's screen rather than UIScreen.main, which is
            // deprecated on newer iOS and wrong on multi-screen setups.
            let captured = (note.object as? UIScreen)?.isCaptured ?? false
            Task { @MainActor in
                guard let self else { return }
                self.isCaptured = captured
                if captured { self.onUnsafeCondition?(.screenRecording) }
            }
        })

        // Screenshots. Cannot be blocked — only detected, after the fact.
        observers.append(center.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.screenshotCount += 1
                self.onUnsafeCondition?(.screenshotTaken)
            }
        })

        // Seed the initial capture state from the active scene's screen.
        if let screen = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first?.screen {
            isCaptured = screen.isCaptured
        }
    }

    public func stop() {
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        observers.removeAll()
    }

    /// True when it is safe to display a credential right now.
    public var isSafeToReveal: Bool { !isCaptured }

    /// Explanation when it isn't.
    public var unsafeReason: String? {
        isCaptured ? RevealRevocation.screenRecording.message : nil
    }
}

// MARK: - app-switcher redaction

/// Covers sensitive content when the app leaves the foreground, so the iOS
/// app-switcher snapshot never contains a credential.
///
/// Applied via `.privacyCover(isProtected:)` on any view that can show a password.
///
/// ─────────────────────────────────────────────────────────────────────────────
/// KNOWN COSMETIC BUG, and two fixes that did NOT work. Read before attempting a third.
///
/// Symptom: after tapping reveal, the "Hidden" cover appears for roughly two seconds and
/// is then replaced by the credential. Cause is the order a reveal happens in (§6):
///
///   1. clear any existing secret, so nothing is on screen
///   2. run the biometric gate   ← the Face ID prompt takes the scene to .inactive
///   3. call Graph
///   4. publish the secret       ← isProtected flips true, scene is STILL .inactive
///   5. scene returns to .active ← only now does the cover clear
///
/// Between 4 and 5 the condition below is satisfied even though the user never left the
/// app. SwiftUI's scenePhase simply has not caught up with the system prompt dismissing.
///
/// FAILED ATTEMPT 1 — @State captured in .onChange(of: scenePhase), covering .inactive
/// only when a credential was on screen at the transition. Change handlers run AFTER the
/// render they describe, and that render is the one iOS photographs, so the state was one
/// frame stale exactly when it mattered.
///
/// FAILED ATTEMPT 2 — same idea, recorded during body evaluation into a reference type to
/// remove the deferral. Also failed the switcher test on device.
///
/// Both attempts failed in the dangerous direction: the credential appeared in the app
/// switcher. Reverted to the condition below, which errs toward hiding.
///
/// The likely correct fix is not in this file at all. Hold the fetched secret in
/// DeviceDetailModel and publish it only once scenePhase is .active. Then isProtected is
/// simply false during the inactive tail, the condition below needs no qualification, and
/// there is no render-timing hazard to get wrong. It also stops the 60-second reveal
/// window from starting while the credential is still behind a cover.
///
/// Whatever is attempted, verify ON DEVICE, in this order, and treat the second as
/// blocking: (1) reveal shows no flash, (2) credential up, swipe to the app switcher,
/// the card must show "Hidden".
/// ─────────────────────────────────────────────────────────────────────────────
public struct PrivacyCoverModifier: ViewModifier {
    /// Only cover when there is something worth hiding — a permanent cover would make
    /// the app switcher useless for ordinary browsing.
    let isProtected: Bool

    @Environment(\.scenePhase) private var scenePhase

    public init(isProtected: Bool) {
        self.isProtected = isProtected
    }

    /// Cover on `.inactive` as well as `.background`: the snapshot is taken during the
    /// transition, so waiting for `.background` is too late.
    private var shouldCover: Bool {
        isProtected && scenePhase != .active
    }

    public func body(content: Content) -> some View {
        content
            .overlay {
                if shouldCover {
                    ZStack {
                        Rectangle()
                            .fill(.background)
                        VStack(spacing: 12) {
                            Image(systemName: "lock.fill")
                                .font(.largeTitle)
                            Text("Hidden")
                                .font(.headline)
                            Text("PitLAPS hides credentials when it isn't in the foreground.")
                                .font(.footnote)
                                .multilineTextAlignment(.center)
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 32)
                        }
                    }
                    .ignoresSafeArea()
                    .transition(.opacity)
                }
            }
    }
}

public extension View {
    /// Hides this view's content in the app-switcher snapshot while `isProtected` is true.
    func privacyCover(isProtected: Bool) -> some View {
        modifier(PrivacyCoverModifier(isProtected: isProtected))
    }
}

// MARK: - clipboard

/// Copying a password is the single most common way it escapes the app, so the copy
/// is deliberately constrained.
public enum SecureClipboard {

    /// How long a copied credential remains on the clipboard.
    public static let defaultExpiry: TimeInterval = 90

    /// Copies with two protections:
    ///   * `localOnly: true` — keeps it off Universal Clipboard, so it does not sync to
    ///     the admin's Mac or iPad, where it would sit in another pasteboard entirely.
    ///   * `expirationDate` — iOS clears the item automatically, so a password doesn't
    ///     linger for the next app that reads the pasteboard.
    ///
    /// Returns the moment the item will expire, for UI copy.
    @discardableResult
    @MainActor
    public static func copyCredential(_ value: String, expiresIn seconds: TimeInterval = defaultExpiry) -> Date {
        let expiry = Date().addingTimeInterval(seconds)
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: value]],
            options: [
                .localOnly: true,
                .expirationDate: expiry
            ]
        )
        return expiry
    }

    /// Clears the pasteboard if it still holds the value we put there. Called when the
    /// reveal window ends, so the clipboard doesn't outlive the on-screen password.
    @MainActor
    public static func clearIfHolding(_ value: String) {
        if UIPasteboard.general.string == value {
            UIPasteboard.general.items = []
        }
    }

    /// Copy confirmation text. Being explicit about expiry sets the right expectation.
    public static func copyConfirmation(expiresIn seconds: TimeInterval = defaultExpiry) -> String {
        "Copied. It'll clear from the clipboard in \(Int(seconds)) seconds."
    }
}

#endif
