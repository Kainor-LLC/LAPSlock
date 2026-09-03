import XCTest
import LicensingKit
@testable import SubscriptionKit

final class SubscriptionCatalogueTests: XCTestCase {

    // MARK: - the identifiers, which can never change

    func test_productIdentifiersArePinned() {
        // Apple does not allow a product ID to be renamed or reused, in this app or any
        // other, ever. A typo shipped once is a product line that must be abandoned and
        // recreated under a new name, and existing subscribers do not follow. These strings
        // must match App Store Connect exactly, so they are asserted rather than trusted.
        XCTAssertEqual(SubscriptionProduct.proMonthly.rawValue, "com.kainor.lapslock.pro.monthly")
        XCTAssertEqual(SubscriptionProduct.proYearly.rawValue, "com.kainor.lapslock.pro.yearly")
        XCTAssertEqual(SubscriptionProduct.mspYearly.rawValue, "com.kainor.lapslock.msp.yearly")
        XCTAssertEqual(SubscriptionProduct.allIdentifiers.count, 3)
    }

    func test_everyProductSharesOneSubscriptionGroup() {
        // A customer may hold only ONE subscription per group, and Apple grants exactly one
        // introductory offer per group per customer. Both matter: MSP is a strict superset
        // of Pro, so separate groups would let somebody hold both and pay $19.99 + $49.99
        // for overlapping benefits — and would hand out a second 30-day trial, 60 days free.
        XCTAssertEqual(Set(SubscriptionProduct.allCases.map(\.groupIdentifier)).count, 1)
    }

    func test_serviceLevelsRankMSPHighestAndYearlyAboveMonthly() {
        // This order must match App Store Connect, because it is what drives Apple's
        // upgrade and downgrade behaviour. MSP top, so Pro-to-MSP is an immediate prorated
        // upgrade; yearly above monthly, so monthly-to-yearly applies at once rather than
        // waiting for the next renewal.
        XCTAssertEqual(SubscriptionProduct.mspYearly.serviceLevel, 1)
        XCTAssertEqual(SubscriptionProduct.proYearly.serviceLevel, 2)
        XCTAssertEqual(SubscriptionProduct.proMonthly.serviceLevel, 3)
        XCTAssertEqual(Set(SubscriptionProduct.allCases.map(\.serviceLevel)).count,
                       SubscriptionProduct.allCases.count,
                       "no two products may share a level, or the order is ambiguous")
    }

    func test_anUnknownIdentifierGrantsNothing() {
        // A transaction for something we do not sell — a renamed product, another app's ID,
        // a tampered payload — must not resolve to a paid tier.
        XCTAssertNil(SubscriptionProduct(identifier: "com.kainor.lapslock.pro"))
        XCTAssertNil(SubscriptionProduct(identifier: ""))
        XCTAssertNil(SubscriptionProduct(identifier: "com.someone.else.pro.monthly"))
    }

    // MARK: - what each product grants

    func test_tiersMatchWhatIsSold() {
        XCTAssertEqual(SubscriptionProduct.proMonthly.tier, .pro)
        XCTAssertEqual(SubscriptionProduct.proYearly.tier, .pro)
        XCTAssertEqual(SubscriptionProduct.mspYearly.tier, .msp)
    }

    func test_noEntitlementIsFree() {
        XCTAssertEqual(SubscriptionEntitlement.none.tier, .free)
        XCTAssertFalse(SubscriptionEntitlement.none.isActive)
    }

    func test_mspWinsOverProForDisplay() {
        let both = SubscriptionEntitlement(activeProducts: [.proMonthly, .mspYearly])
        XCTAssertEqual(both.tier, .msp)
    }

    // MARK: - the merge, which is a lattice and not a ladder

    func test_enterpriseOrgPlusMSPSubscriptionGrantsBoth() {
        // THE test in this file. Enterprise costs more than MSP Pro and still does not
        // switch tenants; MSP switches but is not "higher". Picking a single winning tier
        // loses a capability whichever way it picks.
        let merged = SubscriptionEntitlement.merge(
            subscription: SubscriptionEntitlement(activeProducts: [.mspYearly]),
            organizationTier: .enterprise)
        XCTAssertTrue(merged.isPro, "enterprise already unmeters reveals")
        XCTAssertTrue(merged.allowsTenantSwitching, "and the MSP subscription adds switching")
    }

    func test_anIndividualSubscriptionAloneUnmetersButDoesNotSwitchTenants() {
        for product in [SubscriptionProduct.proMonthly, .proYearly] {
            let merged = SubscriptionEntitlement.merge(
                subscription: SubscriptionEntitlement(activeProducts: [product]),
                organizationTier: .free)
            XCTAssertTrue(merged.isPro)
            XCTAssertFalse(merged.allowsTenantSwitching,
                           "tenant switching is the MSP capability, not a Pro one")
        }
    }

    func test_anMSPSubscriptionAloneGrantsBoth() {
        let merged = SubscriptionEntitlement.merge(
            subscription: SubscriptionEntitlement(activeProducts: [.mspYearly]),
            organizationTier: .free)
        XCTAssertTrue(merged.isPro)
        XCTAssertTrue(merged.allowsTenantSwitching)
    }

    func test_anOrganizationLicenceAloneStillWorksWithNoSubscription() {
        // The path that shipped first and must not regress: an org licence with no Apple
        // purchase at all.
        let proOrg = SubscriptionEntitlement.merge(
            subscription: .none, organizationTier: .pro)
        XCTAssertTrue(proOrg.isPro)
        XCTAssertFalse(proOrg.allowsTenantSwitching)

        let mspOrg = SubscriptionEntitlement.merge(
            subscription: .none, organizationTier: .msp)
        XCTAssertTrue(mspOrg.isPro)
        XCTAssertTrue(mspOrg.allowsTenantSwitching)
    }

    func test_nothingOnEitherSideIsFree() {
        XCTAssertEqual(
            SubscriptionEntitlement.merge(subscription: .none, organizationTier: .free),
            MergedEntitlement.free)
    }

    func test_mergeIsNeverDowngradedByTheOtherSide() {
        // Whatever one side grants, the merge keeps. Exhaustive across both axes, because
        // this is the function every gate in the app will eventually read.
        for orgTier in EntitlementTier.allCases {
            for products in [Set<SubscriptionProduct>(), [.proMonthly], [.mspYearly]] {
                let subscription = SubscriptionEntitlement(activeProducts: products)
                let merged = SubscriptionEntitlement.merge(
                    subscription: subscription, organizationTier: orgTier)
                if orgTier.isPaid || subscription.tier.isPaid {
                    XCTAssertTrue(merged.isPro, "\(orgTier) + \(products) should be Pro")
                }
                if orgTier.allowsTenantSwitching || subscription.tier.allowsTenantSwitching {
                    XCTAssertTrue(merged.allowsTenantSwitching, "\(orgTier) + \(products)")
                }
            }
        }
    }
}
