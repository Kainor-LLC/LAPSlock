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

    /// Apple subscription group. Products in ONE group are mutually exclusive and a customer
    /// can move between them freely, so monthly and yearly individual plans belong together —
    /// otherwise somebody switching from monthly to yearly would hold both and pay twice.
    ///
    /// MSP is its own group precisely because it is not an upgrade path from individual Pro.
    public var groupIdentifier: String {
        switch self {
        case .proMonthly, .proYearly: return "lapslock.pro"
        case .mspYearly:              return "lapslock.msp"
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
