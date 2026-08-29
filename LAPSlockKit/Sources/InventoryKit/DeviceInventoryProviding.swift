import Foundation
import CredentialKit

// Build Spec §5 + App Store Review Guideline 2.1.
//
// WHY A PROTOCOL HERE
// Three consumers need device inventory from different sources:
//
//   1. The live app          → DeviceInventoryService (Microsoft Graph)
//   2. SwiftUI previews/dev  → DemoInventoryProvider (no network, no tenant)
//   3. App Store review      → DemoInventoryProvider
//
// (3) is not a nicety. Apple's reviewers cannot sign into a customer's Entra tenant,
// and Guideline 2.1 requires a reviewer to be able to evaluate an app behind a login.
// For an enterprise tool gated on a tenant, a demo mode is the standard answer, and
// its absence is a common rejection reason. So the seam is a shipping requirement, not
// developer convenience.

public protocol DeviceInventoryProviding: Sendable {
    /// Fetches the first page, replacing whatever was cached.
    @discardableResult
    func loadFirstPage() async throws -> DevicePage
    /// Fetches and appends the next page. Nil when exhausted.
    @discardableResult
    func loadNextPage() async throws -> DevicePage?
    /// Everything loaded so far.
    func cachedDevices() async throws -> [ManagedDeviceSummary]
    /// Whether another page exists.
    func hasMore() async throws -> Bool
    /// Full teardown, called on sign-out and account switch (§7).
    func reset() async
}

extension DeviceInventoryService: DeviceInventoryProviding {}
