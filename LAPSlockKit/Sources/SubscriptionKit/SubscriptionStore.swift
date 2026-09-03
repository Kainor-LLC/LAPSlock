import Foundation
import StoreKit

// The live StoreKit layer: what Apple says this Apple ID owns, and how to buy.
//
// DELIBERATELY THIN. Every decision worth testing lives in `SubscriptionCatalogue` as a pure
// function over plain values, because StoreKit's types cannot be faked — `Transaction` and
// `Product` are concrete, not protocols, so a unit test cannot manufacture one. What is left
// here is the minimum glue, and it is verified against a local StoreKit configuration file
// rather than by unit tests. Anything that can be decided without StoreKit belongs next door.
//
// THE RULE THAT MATTERS: an UNVERIFIED transaction grants nothing. StoreKit hands back
// `VerificationResult`, and the `.unverified` case exists because a receipt can be forged or
// replayed on a jailbroken device. Reading the payload without checking is the standard way
// apps get their paid tier unlocked for free, and it is one `case .unverified` away.

@MainActor
public final class SubscriptionStore: ObservableObject {

    /// What Apple currently vouches for. Starts empty and stays empty until proven otherwise.
    @Published public private(set) var entitlement: SubscriptionEntitlement = .none

    /// What can be bought, in the order the UI should show it.
    @Published public private(set) var offers: [SubscriptionOffer] = []

    /// True while a purchase or restore is in flight, so the UI can disable its buttons.
    @Published public private(set) var isWorking = false

    /// Set when Apple could not be reached for the product list. Not an error worth an
    /// alarming screen: the app works fine unpaid, so this degrades to "plans unavailable".
    @Published public private(set) var loadFailed = false

    private var updatesTask: Task<Void, Never>?

    public init() {}

    /// Starts listening for entitlement changes and reads the current state.
    ///
    /// **The listener must outlive any one screen.** Renewals, cancellations, refunds, family
    /// sharing changes and Ask-to-Buy approvals all arrive through `Transaction.updates`,
    /// often while no purchase screen is open. Start this once at launch, not from a paywall.
    public func start() {
        guard updatesTask == nil else { return }
        updatesTask = Task { [weak self] in
            for await update in Transaction.updates {
                guard let self else { return }
                // A transaction must be finished or StoreKit redelivers it forever.
                if case .verified(let transaction) = update {
                    await transaction.finish()
                }
                await self.refreshEntitlement()
            }
        }
        Task { await refreshEntitlement() }
        Task { await loadOffers() }
    }

    deinit {
        updatesTask?.cancel()
    }

    // MARK: - reading what is owned

    /// Recomputes the entitlement from Apple's current entitlements.
    ///
    /// `currentEntitlements` already excludes expired and revoked transactions, but
    /// `revocationDate` is checked anyway: a refunded subscription must stop granting
    /// immediately, and belt-and-braces costs one line.
    public func refreshEntitlement() async {
        var active: Set<SubscriptionProduct> = []
        for await result in Transaction.currentEntitlements {
            // An unverified transaction is not evidence of anything. Skipped, not read.
            guard case .verified(let transaction) = result else { continue }
            guard transaction.revocationDate == nil else { continue }
            guard let product = SubscriptionProduct(identifier: transaction.productID) else {
                // Something we do not sell. Never grants a tier by default.
                continue
            }
            active.insert(product)
        }
        entitlement = SubscriptionEntitlement(activeProducts: active)
    }

    // MARK: - what is for sale

    public func loadOffers() async {
        do {
            let products = try await Product.products(for: SubscriptionProduct.allIdentifiers)
            var resolved: [SubscriptionOffer] = []
            for product in products {
                guard var offer = SubscriptionOffer(product: product) else { continue }
                // Eligibility is asked of StoreKit rather than assumed, and it accounts for
                // the whole subscription group: somebody who already used their trial on the
                // monthly plan must not be shown "first month free" on the yearly one.
                if let subscription = product.subscription,
                   let intro = subscription.introductoryOffer,
                   await subscription.isEligibleForIntroOffer,
                   let description = SubscriptionOffer.introductoryDescription(intro) {
                    offer = offer.withIntroductoryOffer(description)
                }
                resolved.append(offer)
            }
            offers = resolved.sorted { $0.plan.serviceLevel < $1.plan.serviceLevel }
            // An EMPTY list after a successful call is the App Store Connect symptom, not a
            // network one: products stuck at "Missing Metadata" simply are not returned.
            loadFailed = offers.isEmpty
        } catch {
            offers = []
            loadFailed = true
        }
    }

    // MARK: - buying

    public enum PurchaseOutcome: Sendable, Equatable {
        case purchased
        /// The user backed out. Not an error, and must produce no message.
        case cancelled
        /// Ask to Buy, or a bank step that has not finished. **Not success**: nothing is
        /// owned yet, and saying otherwise sends somebody looking for a feature they do
        /// not have. The entitlement arrives later through `Transaction.updates`.
        case pending
        case failed(String)
    }

    public func purchase(_ plan: SubscriptionProduct) async -> PurchaseOutcome {
        guard let offer = offers.first(where: { $0.plan == plan }) else {
            return .failed("That plan isn't available right now.")
        }
        isWorking = true
        defer { isWorking = false }

        do {
            switch try await offer.storeProduct.purchase() {
            case .success(let verification):
                guard case .verified(let transaction) = verification else {
                    // Apple could not vouch for it, so neither do we.
                    return .failed("Apple couldn't verify that purchase. Nothing was charged that we can see — check your Apple Account, and contact support if it was.")
                }
                await transaction.finish()
                await refreshEntitlement()
                return .purchased
            case .userCancelled:
                return .cancelled
            case .pending:
                return .pending
            @unknown default:
                await refreshEntitlement()
                return .failed("That didn't complete. Check your Apple Account subscriptions.")
            }
        } catch {
            return .failed("The purchase couldn't be completed. Check your connection and try again.")
        }
    }

    /// Restores purchases made on another device or after a reinstall.
    ///
    /// Kept as an explicit button because Apple requires one, and because entitlements are
    /// per Apple ID: somebody signed into a different Apple ID than the one that bought will
    /// otherwise see no explanation for why their subscription vanished.
    public func restore() async -> Bool {
        isWorking = true
        defer { isWorking = false }
        do {
            try await AppStore.sync()
            await refreshEntitlement()
            return entitlement.isActive
        } catch {
            await refreshEntitlement()
            return entitlement.isActive
        }
    }
}

/// One purchasable plan, formatted for display.
///
/// Wraps StoreKit's `Product` rather than exposing it, so the UI never has to know StoreKit
/// exists and the price string always comes from Apple's own locale-aware formatting instead
/// of anything hand-rolled.
public struct SubscriptionOffer: Identifiable, Sendable {
    public let plan: SubscriptionProduct
    public let displayName: String
    /// Apple's localized price, already in the viewer's currency.
    public let displayPrice: String
    /// "month" or "year", for the "$1.99 / month" line.
    public let periodLabel: String
    /// Set when this Apple ID is eligible for the free trial, so the UI never advertises a
    /// trial to somebody who has already used theirs.
    public let introductoryOffer: String?

    public var id: String { plan.rawValue }

    let storeProduct: Product

    init?(product: Product) {
        guard let plan = SubscriptionProduct(identifier: product.id) else { return nil }
        self.plan = plan
        self.storeProduct = product
        self.displayName = product.displayName
        self.displayPrice = product.displayPrice
        self.periodLabel = Self.periodLabel(product.subscription?.subscriptionPeriod)
        self.introductoryOffer = nil
    }

    /// Copy of this offer with trial eligibility resolved. Separate because eligibility is an
    /// async lookup and the list should render before it returns.
    public func withIntroductoryOffer(_ description: String?) -> SubscriptionOffer {
        SubscriptionOffer(
            plan: plan, displayName: displayName, displayPrice: displayPrice,
            periodLabel: periodLabel, introductoryOffer: description, storeProduct: storeProduct)
    }

    private init(
        plan: SubscriptionProduct, displayName: String, displayPrice: String,
        periodLabel: String, introductoryOffer: String?, storeProduct: Product
    ) {
        self.plan = plan
        self.displayName = displayName
        self.displayPrice = displayPrice
        self.periodLabel = periodLabel
        self.introductoryOffer = introductoryOffer
        self.storeProduct = storeProduct
    }

    /// Copy for an introductory offer, or nil if it is not something to advertise.
    ///
    /// Only a FREE TRIAL is described. Apple's other introductory modes — pay-as-you-go and
    /// pay-up-front — are discounts rather than free access, and calling one of those "free"
    /// on a purchase button is the kind of wrong that gets an app rejected.
    static func introductoryDescription(_ offer: Product.SubscriptionOffer) -> String? {
        guard offer.paymentMode == .freeTrial else { return nil }
        return "Free for the first " + periodLabel(offer.period)
    }

    static func periodLabel(_ period: Product.SubscriptionPeriod?) -> String {
        guard let period else { return "" }
        let unit: String
        switch period.unit {
        case .day:   unit = "day"
        case .week:  unit = "week"
        case .month: unit = "month"
        case .year:  unit = "year"
        @unknown default: unit = "period"
        }
        return period.value == 1 ? unit : "\(period.value) \(unit)s"
    }
}
