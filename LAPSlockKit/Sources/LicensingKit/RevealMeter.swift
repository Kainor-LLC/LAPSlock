import Foundation
import CryptoKit

/// Counts free-tier reveals against a rolling window.
///
/// TWO CALLS, IN THIS ORDER, AND THE ORDER MATTERS:
///
///   1. `check(deviceIdentifier:isPro:)` BEFORE the biometric gate.
///   2. `recordReveal(deviceIdentifier:isPro:)` AFTER a successful Graph response.
///
/// Checking before the gate means a blocked reveal fails immediately with an explanation
/// instead of making somebody complete Face ID and *then* telling them they are out. An
/// admin standing at a broken workstation discovering they are blocked, after
/// authenticating, is exactly the surprise that earns one-star reviews.
///
/// Charging after the fetch means an abandoned reveal, a cancelled Face ID prompt, a
/// permission error or a network failure never burns a credit. The user only pays for
/// reveals that actually produced a password.
///
/// The two are separate calls precisely so they can sit at those two different points.
/// Collapsing them into one would force a choice between the two failure modes above.
@MainActor
public final class RevealMeter {

    /// Public so UI can report "n of 5" without hardcoding the 5 in two places.
    public let policy: RevealAllowancePolicy
    private let store: RevealLedgerStore
    private let clock: MeterClock

    public init(
        policy: RevealAllowancePolicy = .standard,
        store: RevealLedgerStore,
        clock: MeterClock = SystemMeterClock()
    ) {
        self.policy = policy
        self.store = store
        self.clock = clock
    }

    // MARK: - queries

    /// Reveals left in the current window. For the count shown in the device list and on
    /// the detail screen, BEFORE the user taps anything.
    ///
    /// Showing this in advance is the whole point. "2 reveals left this month" on screen is
    /// fine; discovering you are blocked at the moment you need a password is not.
    public func remaining(isPro: Bool) -> Int {
        if isPro { return .max }
        let ledger = prunedLedger()
        return max(0, policy.freeRevealsPerWindow - ledger.entries.count)
    }

    /// When the allowance frees up again, or nil if it has not run out.
    ///
    /// Exists for the Settings readout, which has no particular device in hand and so
    /// cannot go through `check(deviceIdentifier:isPro:)`. A customer asking "why can't I
    /// reveal" needs a date, not just a zero.
    public func nextAvailable(isPro: Bool) -> Date? {
        guard !isPro else { return nil }
        let ledger = prunedLedger()
        guard ledger.entries.count >= policy.freeRevealsPerWindow,
              let oldest = ledger.entries.map(\.at).min() else { return nil }
        return oldest.addingTimeInterval(policy.window)
    }

    /// Whether a reveal may proceed. Call BEFORE the biometric gate.
    public func check(deviceIdentifier: String, isPro: Bool) -> RevealAllowance {
        if isPro { return .unlimited }

        let ledger = prunedLedger()
        let hash = Self.hash(deviceIdentifier, salt: ledger.salt)
        let now = clock.now

        // Repeat of a device already revealed inside the grace period: free.
        if ledger.entries.contains(where: {
            $0.deviceHash == hash && now.timeIntervalSince($0.at) < policy.repeatGrace
        }) {
            return .allowed(willCharge: false)
        }

        if ledger.entries.count < policy.freeRevealsPerWindow {
            return .allowed(willCharge: true)
        }

        // Blocked. The window frees up when the oldest counted reveal ages out.
        let oldest = ledger.entries.map(\.at).min() ?? now
        return .exhausted(nextAvailable: oldest.addingTimeInterval(policy.window))
    }

    // MARK: - mutation

    /// Records a reveal that actually succeeded. Call AFTER the Graph response, never
    /// before. Repeats inside the grace period are deliberately not recorded again.
    ///
    /// Returns what remains afterwards, so the caller can update the UI without a second
    /// round trip through the store.
    @discardableResult
    public func recordReveal(deviceIdentifier: String, isPro: Bool) -> Int {
        if isPro { return .max }

        var ledger = prunedLedger()
        let hash = Self.hash(deviceIdentifier, salt: ledger.salt)
        let now = clock.now

        let withinGrace = ledger.entries.contains {
            $0.deviceHash == hash && now.timeIntervalSince($0.at) < policy.repeatGrace
        }
        if !withinGrace {
            ledger.entries.append(RevealLedgerEntry(deviceHash: hash, at: now))
        }

        persist(ledger)
        return max(0, policy.freeRevealsPerWindow - ledger.entries.count)
    }

    /// Wipes the ledger. Not reachable from the UI; present for tests and for support to
    /// talk somebody through if the meter is ever provably wrong.
    public func resetLedger() {
        try? store.reset()
    }

    // MARK: - internals

    /// Loads the ledger, drops entries that have aged out, and creates one on first use.
    ///
    /// FAILS OPEN. If the Keychain read throws, this returns an empty ledger, which means
    /// the user gets their reveals rather than being blocked by a storage hiccup. Blocking
    /// a legitimate user because of an I/O error is a far worse outcome than losing count,
    /// and it is the correct trade for a nudge rather than an enforcement boundary.
    private func prunedLedger() -> RevealLedger {
        var ledger: RevealLedger
        do {
            ledger = try store.load() ?? RevealLedger(salt: Self.newSalt())
        } catch {
            return RevealLedger(salt: Self.newSalt())
        }

        let cutoff = clock.now.addingTimeInterval(-policy.window)
        let kept = ledger.entries.filter { $0.at > cutoff }
        if kept.count != ledger.entries.count {
            ledger.entries = kept
        }
        return ledger
    }

    private func persist(_ ledger: RevealLedger) {
        // Same reasoning as the read path: a failed write loses a count, it does not
        // block anybody, and it is not worth surfacing an error to the user over.
        try? store.save(ledger)
    }

    /// Salted SHA-256 of the device identifier, hex encoded.
    static func hash(_ identifier: String, salt: Data) -> String {
        var data = salt
        data.append(contentsOf: Array(identifier.utf8))
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func newSalt() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        // SecRandomCopyBytes would pull in Security here for no benefit; SystemRandom is
        // cryptographically secure on Apple platforms and this salt only needs to be
        // unguessable, not secret.
        for i in 0..<bytes.count { bytes[i] = UInt8.random(in: 0...255) }
        return Data(bytes)
    }
}
