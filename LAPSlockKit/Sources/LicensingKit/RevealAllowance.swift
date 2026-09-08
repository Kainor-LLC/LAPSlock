import Foundation

// Free-tier metering.
//
// The free tier exists for evaluation. An administrator has to be able to search a device,
// reveal a password and watch the read land in their own Entra audit log before paying, so
// reveals are metered rather than blocked, and convenience is what the paid tiers add.
//
// The count lives on the device and never on a server. A server-side counter would mean
// learning how often each tenant retrieves passwords, which is usage telemetry, and the
// privacy policy says none is collected.
//
// This is a nudge, not DRM. The ledger lives in the Keychain rather than UserDefaults so a
// reinstall does not reset it; a device wipe or a new phone does, and moving the system
// clock can age entries out early. All of that is accepted rather than hardened against.
//
// Isolation (§3.1): this module imports Foundation and CryptoKit only. It never imports
// CredentialKit and CredentialKit never imports it. The meter counts events; no type here
// has anywhere to hold a credential.

/// The rules of the free tier. Injected rather than hardcoded so tests can use small
/// numbers and short windows instead of waiting thirty days.
public struct RevealAllowancePolicy: Sendable, Equatable {

    /// Reveals allowed per rolling window, LAPS and BitLocker combined.
    ///
    /// Five, because evaluation takes about three. Somebody proving the app works never
    /// hits the wall; somebody doing real work hits it in week one. It also keeps the app
    /// installed for the light user who genuinely needs it twice a month, and that person
    /// is worth more as a recommender than as a blocked user who deletes it.
    public let freeRevealsPerWindow: Int

    /// Length of the rolling window.
    public let window: TimeInterval

    /// Re-revealing the SAME device inside this period does not cost a second credit.
    ///
    /// An admin standing at a broken machine who fumbles a long random password should not
    /// be punished for looking twice. It cannot be gamed to any real effect either: the
    /// limit is still five distinct devices per window.
    public let repeatGrace: TimeInterval

    public init(
        freeRevealsPerWindow: Int = 5,
        window: TimeInterval = 30 * 24 * 60 * 60,
        repeatGrace: TimeInterval = 60 * 60
    ) {
        self.freeRevealsPerWindow = max(0, freeRevealsPerWindow)
        self.window = max(60, window)
        self.repeatGrace = max(0, repeatGrace)
    }

    public static let standard = RevealAllowancePolicy()
}

/// Whether a reveal may proceed.
public enum RevealAllowance: Sendable, Equatable {

    /// Pro. No metering applies at all.
    case unlimited

    /// Proceed. `willCharge` is false when this is a repeat of a device already revealed
    /// inside the grace period, so it costs nothing.
    case allowed(willCharge: Bool)

    /// Blocked. `nextAvailable` is when the oldest counted reveal ages out of the window,
    /// which is the honest answer to "when can I do this again".
    case exhausted(nextAvailable: Date)

    public var isAllowed: Bool {
        switch self {
        case .unlimited, .allowed: return true
        case .exhausted: return false
        }
    }
}

/// One counted reveal.
///
/// The device is stored as a salted hash, never as an identifier. Device identifiers are
/// not secret, but a durable list of *which devices had their administrator password
/// revealed* is reconnaissance, and this ledger deliberately survives sign-out, tenant
/// switches and app deletion. Hashing keeps the dedupe behaviour while making the stored
/// data useless to anyone who reads it.
public struct RevealLedgerEntry: Codable, Sendable, Equatable {
    public let deviceHash: String
    public let at: Date

    public init(deviceHash: String, at: Date) {
        self.deviceHash = deviceHash
        self.at = at
    }
}

/// Everything persisted for the meter.
public struct RevealLedger: Codable, Sendable, Equatable {
    /// Per-install random salt. Makes the hashes above unlinkable across installs and
    /// prevents anyone precomputing hashes for a known device inventory.
    public var salt: Data
    public var entries: [RevealLedgerEntry]

    public init(salt: Data, entries: [RevealLedgerEntry] = []) {
        self.salt = salt
        self.entries = entries
    }
}

/// Abstracts the clock so tests do not sleep. Mirrors `RevealClock` in PlatformSecurity
/// deliberately rather than importing it: LicensingKit stays dependency-free, and the
/// duplication is three lines.
public protocol MeterClock: Sendable {
    var now: Date { get }
}

public struct SystemMeterClock: MeterClock {
    public init() {}
    public var now: Date { Date() }
}

/// A clock the caller advances by hand.
public final class ManualMeterClock: MeterClock, @unchecked Sendable {
    private var current: Date
    public init(start: Date = Date(timeIntervalSince1970: 1_700_000_000)) { current = start }
    public var now: Date { current }
    public func advance(_ seconds: TimeInterval) { current = current.addingTimeInterval(seconds) }
}

/// Where the ledger is kept. The Keychain implementation is the shipping one; tests use an
/// in-memory double.
public protocol RevealLedgerStore: Sendable {
    func load() throws -> RevealLedger?
    func save(_ ledger: RevealLedger) throws
    func reset() throws
}

/// In-memory store, for tests and previews.
public final class InMemoryRevealLedgerStore: RevealLedgerStore, @unchecked Sendable {
    private var ledger: RevealLedger?
    public init(_ ledger: RevealLedger? = nil) { self.ledger = ledger }
    public func load() throws -> RevealLedger? { ledger }
    public func save(_ ledger: RevealLedger) throws { self.ledger = ledger }
    public func reset() throws { ledger = nil }
}
