import Foundation

// Build Spec — the rules that make the contract's privacy claims true. Section 7.
//
// The wire format is half the contract. THIS FILE IS THE OTHER HALF. Sections 7.1 to 7.3,
// 7.5 and 7.7 are normative for the client, and a client that violates them breaks the
// contract even if every byte on the wire is well-formed.
//
// The rule that matters most, from section 7.1 and 7.2:
//
//   A FREE-TIER INSTALL NEVER CONTACTS THE ENDPOINT. And an activated install contacts it
//   on the CALENDAR, never in response to what the administrator did.
//
// Every call to the network in this file goes through `attemptFetch`, and there are exactly
// three callers: Activate, Refresh (manual), and `refreshIfDue`. `refreshIfDue` is gated on
// a stored activation, a schedule, and a 24-hour floor. Nothing here is reachable from a
// reveal, a search, a device open, or sign-in. If a future change wires one of those to this
// manager, request timing becomes usage telemetry and section 8.2 stops being true.

/// What the app gets back. Never an error: failure degrades to `.free`, silently, and the
/// user finds out where they already look — the license row in Settings.
public struct EntitlementState: Sendable, Equatable {
    public let tier: EntitlementTier
    /// True when the tier came from an expired token kept alive by the offline grace window.
    /// Shown in Settings as "could not refresh"; never as an alert.
    public let isInGrace: Bool
    /// Present when a license has been activated, whatever the current tier resolved to.
    public let boundTenantId: String?
    /// For the Settings row. Nil when there is no verified token.
    public let expiresAt: Date?
    /// For diagnostics only. The user is never shown this.
    public let lastFailure: EntitlementVerificationFailure?

    public static let free = EntitlementState(tier: .free, isInGrace: false, boundTenantId: nil, expiresAt: nil, lastFailure: nil)

    public init(tier: EntitlementTier, isInGrace: Bool, boundTenantId: String?, expiresAt: Date?, lastFailure: EntitlementVerificationFailure?) {
        self.tier = tier
        self.isInGrace = isInGrace
        self.boundTenantId = boundTenantId
        self.expiresAt = expiresAt
        self.lastFailure = lastFailure
    }
}

/// Result of an explicit Activate or Refresh. Surfaced in Settings as a single line.
public enum EntitlementFetchOutcome: Sendable, Equatable {
    case updated(EntitlementTier)
    case offline
    case serverError(status: Int)
    case rejected(EntitlementVerificationFailure)
}

@MainActor
public final class EntitlementManager {

    /// Section 7.5. Seven days past `exp`, network failure only.
    public static let gracePeriod: TimeInterval = 7 * 24 * 60 * 60
    /// Section 7.3. At most one automatic attempt per 24 hours.
    public static let automaticAttemptFloor: TimeInterval = 24 * 60 * 60
    /// Section 7.3. Refresh when inside this many seconds of `exp`.
    public static let refreshLead: TimeInterval = 7 * 24 * 60 * 60

    private let store: EntitlementStoring
    private let client: EntitlementFetching
    private let verifier: EntitlementVerifier
    private let clock: MeterClock

    public init(
        store: EntitlementStoring,
        client: EntitlementFetching,
        verifier: EntitlementVerifier = EntitlementVerifier(),
        clock: MeterClock = SystemMeterClock()
    ) {
        self.store = store
        self.client = client
        self.verifier = verifier
        self.clock = clock
    }

    // MARK: - reading

    /// Whether a license has ever been activated on this install. Drives whether Settings
    /// shows Activate or Remove, and whether `refreshIfDue` may touch the network at all.
    public var isActivated: Bool {
        (try? store.load()) != nil
    }

    /// The current entitlement, re-verified from scratch. Section 7.4 and 7.5.
    ///
    /// - Parameter signedInTenantId: the tenant currently signed in. For `free`, `pro` and
    ///   `enterprise` the license must have been activated against this same tenant. For
    ///   `msp` it need not: an MSP signs into customer tenants, and revoking their license
    ///   for doing their job would be absurd. This is the one deliberate loosening, on the
    ///   tier that is sold on an honor-system seat count anyway.
    public func state(signedInTenantId: String?) -> EntitlementState {
        guard let record = try? store.load() else { return .free }
        guard let token = record.token else {
            return EntitlementState(tier: .free, isInGrace: false, boundTenantId: record.boundTenantId, expiresAt: nil, lastFailure: nil)
        }

        let now = clock.now
        let verified: VerifiedEntitlement
        var inGrace = false

        do {
            verified = try verifier.verify(token: token, boundTenantId: record.boundTenantId, now: now)
        } catch let failure as EntitlementVerificationFailure {
            // Grace is narrow on purpose: ONLY expiry, ONLY when the last attempt to refresh
            // failed to reach the server, ONLY for seven days. A signature failure, an
            // iss/aud/sub mismatch, or a server that answered "free" gets no grace at all.
            guard case .expired(let expiredAt) = failure,
                  record.lastFailureWasNetwork,
                  now < expiredAt.addingTimeInterval(Self.gracePeriod),
                  let graced = try? verifier.verify(token: token, boundTenantId: record.boundTenantId, now: expiredAt.addingTimeInterval(-1))
            else {
                return EntitlementState(tier: .free, isInGrace: false, boundTenantId: record.boundTenantId, expiresAt: nil, lastFailure: failure)
            }
            verified = graced
            inGrace = true
        } catch {
            return EntitlementState(tier: .free, isInGrace: false, boundTenantId: record.boundTenantId, expiresAt: nil, lastFailure: .malformedToken)
        }

        // Section 7.4 step 8, second half: the tenant binding to the CURRENT sign-in.
        // Nobody signed in is not the licensed tenant either: a non-msp license is only
        // live while somebody from that tenant is actually here.
        if !verified.tier.allowsTenantSwitching {
            guard let signedIn = signedInTenantId?.lowercased(), signedIn == verified.subject else {
                return EntitlementState(tier: .free, isInGrace: false, boundTenantId: record.boundTenantId, expiresAt: verified.expiresAt, lastFailure: .subjectMismatch)
            }
        }

        return EntitlementState(
            tier: verified.tier,
            isInGrace: inGrace,
            boundTenantId: record.boundTenantId,
            expiresAt: verified.expiresAt,
            lastFailure: nil
        )
    }

    /// True when a license is activated, but for a DIFFERENT organization than the one
    /// currently signed in.
    ///
    /// Activation binds an install to one tenant. An administrator who activates in tenant A
    /// and later signs into tenant B is not unlicensed — they hold a license, it just does
    /// not apply here. Without this distinction the UI shows the activated branch with a
    /// Refresh button that would fetch for tenant A while the user is looking at tenant B,
    /// and offers no way to activate B at all.
    ///
    /// The `msp` tier is exempt, because working across customer tenants is the whole point
    /// of that tier (section 7.4).
    public func isBoundToAnotherTenant(signedInTenantId: String?) -> Bool {
        guard let record = try? store.load() else { return false }
        guard let signedIn = signedInTenantId?.lowercased(), !signedIn.isEmpty else { return false }
        if state(signedInTenantId: signedInTenantId).tier.allowsTenantSwitching { return false }
        return record.boundTenantId.lowercased() != signedIn
    }

    /// Section 7.7. StoreKit and the tenant license are independent; either suffices.
    public func isPro(signedInTenantId: String?, storeKitEntitlementActive: Bool) -> Bool {
        storeKitEntitlementActive || state(signedInTenantId: signedInTenantId).tier.isPaid
    }

    // MARK: - the three ways to reach the network

    /// User tapped Activate. The ONLY way an install goes from never-calling to calling.
    public func activate(tenantId: String) async -> EntitlementFetchOutcome {
        let record = EntitlementRecord(boundTenantId: tenantId)
        try? store.save(record)
        return await attemptFetch(record: record)
    }

    /// User tapped Refresh in Settings. Explicit, so no schedule applies.
    public func refreshNow() async -> EntitlementFetchOutcome? {
        guard let record = try? store.load() else { return nil }
        return await attemptFetch(record: record)
    }

    /// The scheduled refresh. Section 7.3, all of it:
    ///   * only if a license has been activated — a free install never reaches the network
    ///   * at most once per 24 hours, counting failures as attempts
    ///   * only when the token is missing, past `refreshAfter`, or inside 7 days of `exp`
    ///
    /// Call this from ONE place, on a calendar-shaped trigger such as app launch, and from
    /// nowhere that is a user action. Returns nil when nothing was due, which is nearly always.
    @discardableResult
    public func refreshIfDue() async -> EntitlementFetchOutcome? {
        guard let record = try? store.load() else { return nil }
        let now = clock.now

        if let last = record.lastAttemptAt, now.timeIntervalSince(last) < Self.automaticAttemptFloor {
            return nil
        }

        guard isRefreshDue(record, now: now) else { return nil }
        return await attemptFetch(record: record)
    }

    /// User tapped Remove. Back to never-calling.
    public func remove() {
        try? store.clear()
    }

    // MARK: - internals

    func isRefreshDue(_ record: EntitlementRecord, now: Date) -> Bool {
        guard let token = record.token else { return true }

        // Read exp without trusting anything else. If the token does not even verify, it
        // is due for replacement regardless.
        guard let verified = try? verifier.verify(token: token, boundTenantId: record.boundTenantId, now: now) else {
            return true
        }

        if now >= verified.expiresAt.addingTimeInterval(-Self.refreshLead) { return true }

        // The server's hint, clamped to [iat + 1 day, exp] so a silly value cannot cause a
        // storm or suppress refresh forever. Section 4.1: advisory only.
        if let hint = record.refreshAfter {
            let floor = verified.issuedAt.addingTimeInterval(24 * 60 * 60)
            let clamped = min(max(hint, floor), verified.expiresAt)
            if now >= clamped { return true }
        }

        return false
    }

    private func attemptFetch(record: EntitlementRecord) async -> EntitlementFetchOutcome {
        var updated = record
        updated.lastAttemptAt = clock.now

        do {
            let response = try await client.fetch(tenantId: record.boundTenantId)

            // Verify BEFORE storing. A token that does not verify is not stored, so the
            // Keychain never holds something we already know is bad, and a hostile server
            // cannot replace a good token with garbage.
            let verified = try verifier.verify(token: response.token, boundTenantId: record.boundTenantId, now: clock.now)

            updated.token = response.token
            updated.refreshAfter = response.refreshAfter.flatMap(Self.parseDate)
            updated.lastFailureWasNetwork = false
            try? store.save(updated)
            return .updated(verified.tier)

        } catch EntitlementFetchError.network {
            // The one failure that earns grace. The existing token, if any, stays put.
            updated.lastFailureWasNetwork = true
            try? store.save(updated)
            return .offline

        } catch EntitlementFetchError.server(let status, _) {
            // The server answered. Grace does NOT apply, but the existing token stays: a
            // 503 from Key Vault is not a reason to throw away a valid license.
            updated.lastFailureWasNetwork = false
            try? store.save(updated)
            return .serverError(status: status)

        } catch let failure as EntitlementVerificationFailure {
            // The server sent a token we refuse. Keep the old one if there was one — it may
            // still be good — but record that the server is answering.
            updated.lastFailureWasNetwork = false
            try? store.save(updated)
            return .rejected(failure)

        } catch {
            updated.lastFailureWasNetwork = false
            try? store.save(updated)
            return .rejected(.malformedToken)
        }
    }

    private static let iso8601: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    static func parseDate(_ value: String) -> Date? {
        iso8601.date(from: value)
    }
}
