import Foundation

// Build Spec §6 — the reveal window: a password is visible for a bounded time, then
// the app re-masks it and wipes the value.
//
// DESIGN: this is a pure state machine over an injected clock. No Timer, no UIKit, no
// singletons — which means the auto-hide behavior can be tested deterministically
// instead of with sleeps. The app layer drives `tick()` from a SwiftUI timer and wires
// `onExpire` to SensitiveValue.wipe().
//
// WHY A TIMER AT ALL: the realistic threat isn't a remote attacker, it's the phone
// sitting unlocked on a workbench with a domain admin password on screen. A bounded
// window means walking away is survivable.

/// Abstracts the clock so tests don't sleep.
public protocol RevealClock: Sendable {
    var now: Date { get }
}

public struct SystemRevealClock: RevealClock {
    public init() {}
    public var now: Date { Date() }
}

/// A test clock the caller advances by hand.
public final class ManualRevealClock: RevealClock, @unchecked Sendable {
    private var current: Date
    public init(start: Date = Date(timeIntervalSince1970: 1_000_000)) { self.current = start }
    public var now: Date { current }
    public func advance(_ seconds: TimeInterval) { current = current.addingTimeInterval(seconds) }
}

public enum RevealState: Sendable, Equatable {
    /// Nothing revealed. The steady state.
    case masked
    /// Visible, with the moment it will auto-hide.
    case revealed(until: Date)
    /// Hidden because the window elapsed. Distinguished from `masked` so the UI can
    /// explain why it disappeared instead of appearing to lose the value.
    case expired
    /// Hidden because something unsafe happened (backgrounding, screen recording).
    case revokedForSafety(reason: RevealRevocation)
}

public enum RevealRevocation: String, Sendable, Equatable {
    case appBackgrounded
    case screenRecording
    case screenshotTaken
    case signedOut

    /// User-facing explanation. Says what happened and what to do, without scolding.
    public var message: String {
        switch self {
        case .appBackgrounded:
            return "Hidden because PitLAPS went to the background. Reveal it again when you're ready."
        case .screenRecording:
            return "Hidden because this screen is being recorded or mirrored. Stop the recording to reveal it."
        case .screenshotTaken:
            return "A screenshot was taken. That image now contains an administrator password — delete it, and consider rotating the password."
        case .signedOut:
            return "Hidden because the session ended."
        }
    }
}

/// Drives one reveal window. Not thread-safe by design: own it from the main actor.
public final class RevealSession {
    public private(set) var state: RevealState = .masked

    /// How long a password stays visible. 60s is the default: long enough to type a
    /// long random password into a console, short enough that an unattended phone
    /// isn't a standing exposure.
    public let visibleDuration: TimeInterval

    private let clock: RevealClock

    /// Called whenever the value must be destroyed. The app wires this to
    /// SensitiveValue.wipe(). Invoked exactly once per reveal.
    public var onWipe: (() -> Void)?

    public init(visibleDuration: TimeInterval = 60, clock: RevealClock = SystemRevealClock()) {
        self.visibleDuration = max(5, visibleDuration)
        self.clock = clock
    }

    // MARK: - transitions

    /// Begin the visible window. Caller must have already passed the biometric gate.
    public func reveal() {
        state = .revealed(until: clock.now.addingTimeInterval(visibleDuration))
    }

    /// Drive from a UI timer. Returns true when this call caused expiry.
    @discardableResult
    public func tick() -> Bool {
        guard case .revealed(let until) = state else { return false }
        if clock.now >= until {
            state = .expired
            wipe()
            return true
        }
        return false
    }

    /// Hide because of an unsafe condition. Idempotent per reason.
    public func revoke(_ reason: RevealRevocation) {
        // A screenshot is a special case: the pixels already escaped, so hiding now is
        // about limiting further exposure, and the message must be honest about that.
        guard isVisible || reason == .screenshotTaken else { return }
        state = .revokedForSafety(reason: reason)
        wipe()
    }

    /// User dismissed the reveal manually.
    public func mask() {
        guard isVisible else { return }
        state = .masked
        wipe()
    }

    /// Reset to a clean masked state (e.g. leaving the screen).
    public func reset() {
        if isVisible { wipe() }
        state = .masked
    }

    // MARK: - derived

    public var isVisible: Bool {
        if case .revealed = state { return true }
        return false
    }

    /// Whole seconds left, for a countdown label. Zero when not visible.
    public var secondsRemaining: Int {
        guard case .revealed(let until) = state else { return 0 }
        return max(0, Int(until.timeIntervalSince(clock.now).rounded(.up)))
    }

    /// Fraction of the window elapsed, 0...1, for a progress ring.
    public var progress: Double {
        guard case .revealed(let until) = state else { return 0 }
        let remaining = until.timeIntervalSince(clock.now)
        return min(1, max(0, 1 - (remaining / visibleDuration)))
    }

    private var didWipe = false
    private func wipe() {
        guard !didWipe else { return }
        didWipe = true
        onWipe?()
        // Allow a subsequent reveal to wipe again.
        didWipe = false
    }
}
