import Foundation
import LicensingKit

// Apple subscriptions: which products exist, and what each one grants.
//
// WHY THIS IS A SEPARATE MODULE FROM LicensingKit. `isolation-check.sh` caps LicensingKit at
// Foundation + CryptoKit + Security, so the module that verifies signed entitlements cannot
// grow a payments SDK. The seam was designed for this from the start:
// `EntitlementManager.isPro(signedInTenantId:storeKitEntitlementActive:)` already took the
// Apple side as a plain input it never computes itself. This module computes it.
//
// AND IT MUST NEVER SEE A CREDENTIAL. The guard forbids SubscriptionKit from importing
// CredentialKit, for the same reason LicensingKit is forbidden: a receipt and a local
// administrator password have no business in one link graph.

/// The subscriptions LAPSlock sells through Apple.
///
/// **Product IDs are permanent.** Apple does not allow an ID to be renamed or reused, in this
/// app or any other, ever. They are pinned by a test for that reason: a typo shipped once is
/// a product line that has to be abandoned and recreated under a new name.
public enum SubscriptionProduct: String, CaseIterable, Sendable {
    case proMonthly = "com.kainor.lapslock.pro.monthly"
    case proYearly  = "com.kainor.lapslock.pro.yearly"
    case mspYearly  = "com.kainor.lapslock.msp.yearly"

    /// What owning this grants.
    ///
    /// MSP is **not** "Pro with extras" — see `SubscriptionEntitlement.merge`. It is a
    /// different capability, which is why it sits in its own subscription group at Apple
    /// rather than as a higher rung of the individual one.
    public var tier: EntitlementTier {
        switch self {
        case .proMonthly, .proYearly: return .pro
        case .mspYearly:              return .msp
        }
    }

    /// **All three products share ONE Apple subscription group, and that is deliberate.**
    ///
    /// A customer may hold only one subscription per group, and Apple grants exactly one
    /// introductory offer per group per customer, ever. Both of those matter here:
    ///
    ///   * MSP is a strict SUPERSET of Pro — everything Pro grants plus tenant switching. In
    ///     separate groups a customer could hold Pro *and* MSP simultaneously and pay
    ///     $19.99 + $49.99 for overlapping benefits. One group makes that impossible
    ///     structurally rather than relying on anyone noticing.
    ///   * Separate groups would also mean a **second 30-day free trial** — 60 days free by
    ///     taking the Pro trial, cancelling, then taking the MSP one.
    ///   * And a Pro subscriber who becomes an MSP gets an immediate, prorated upgrade
    ///     instead of having to cancel and rebuy with no credit for unused time.
    ///
    /// Service level within the group, highest first: MSP Yearly, Pro Yearly, Pro Monthly.
    /// Yearly sits above monthly so monthly-to-yearly is an upgrade that applies at once.
    ///
    /// An earlier version of this file put MSP in its own group on the theory that it is "a
    /// different capability, not a bigger Pro". That was wrong: the tier LATTICE in
    /// `merge` concerns the organization licence, where Enterprise is paid but cannot switch
    /// tenants. Between the two things Apple sells, MSP strictly dominates Pro.
    public static let subscriptionGroup = "lapslock.pro"

    public var groupIdentifier: String { Self.subscriptionGroup }

    /// Where this sits in the group, 1 being the highest level of service. Mirrors the order
    /// configured in App Store Connect, which is what drives Apple's upgrade and downgrade
    /// behaviour — so a mismatch here and there is a billing surprise, not a cosmetic bug.
    public var serviceLevel: Int {
        switch self {
        case .mspYearly:  return 1
        case .proYearly:  return 2
        case .proMonthly: return 3
        }
    }

    public static var allIdentifiers: [String] { allCases.map(\.rawValue) }

    /// Nil for anything we do not sell, so an unrecognised transaction grants nothing rather
    /// than defaulting to a paid tier.
    public init?(identifier: String) {
        self.init(rawValue: identifier)
    }
}

/// What Apple says this Apple ID currently owns.
public struct SubscriptionEntitlement: Sendable, Equatable {

    /// Products with an active entitlement right now.
    public let activeProducts: Set<SubscriptionProduct>

    public init(activeProducts: Set<SubscriptionProduct> = []) {
        self.activeProducts = activeProducts
    }

    public static let none = SubscriptionEntitlement()

    /// Highest-value tier Apple is vouching for. `.free` when nothing is active.
    ///
    /// Deliberately not used for merging — see `merge`. It exists for display.
    public var tier: EntitlementTier {
        if activeProducts.contains(.mspYearly) { return .msp }
        if activeProducts.contains(where: { $0.tier == .pro }) { return .pro }
        return .free
    }

    public var isActive: Bool { !activeProducts.isEmpty }

    // MARK: - merging with the organization licence

    /// Combines an Apple subscription with an organization entitlement, **capability by
    /// capability rather than by picking a winner.**
    ///
    /// This is the part worth reading twice. The tiers are NOT a ladder:
    ///
    /// | Tier | Unmetered reveals | Tenant switching |
    /// |---|---|---|
    /// | free | no | no |
    /// | pro | yes | no |
    /// | msp | yes | **yes** |
    /// | enterprise | yes | no |
    ///
    /// Enterprise costs more than MSP Pro and still does not switch tenants, because
    /// switching is what an MSP needs and an enterprise does not. So "take the higher tier"
    /// has no correct answer: an admin with an Enterprise org licence who also buys MSP Pro
    /// must end up with both unmetered reveals AND switching, and any single-tier result
    /// loses one of them.
    ///
    /// Each capability is therefore granted if EITHER side grants it.
    public static func merge(
        subscription: SubscriptionEntitlement,
        organizationTier: EntitlementTier
    ) -> MergedEntitlement {
        MergedEntitlement(
            isPro: subscription.tier.isPaid || organizationTier.isPaid,
            allowsTenantSwitching: subscription.tier.allowsTenantSwitching
                || organizationTier.allowsTenantSwitching)
    }
}

/// The capabilities in force, after Apple and the organization licence are combined.
public struct MergedEntitlement: Sendable, Equatable {
    /// Reveals are unmetered.
    public let isPro: Bool
    /// The MSP tenant switcher is available.
    public let allowsTenantSwitching: Bool

    public init(isPro: Bool, allowsTenantSwitching: Bool) {
        self.isPro = isPro
        self.allowsTenantSwitching = allowsTenantSwitching
    }

    /// Nothing granted. The state a free install is in, and the state anything unreadable
    /// resolves to.
    public static let free = MergedEntitlement(isPro: false, allowsTenantSwitching: false)
}
