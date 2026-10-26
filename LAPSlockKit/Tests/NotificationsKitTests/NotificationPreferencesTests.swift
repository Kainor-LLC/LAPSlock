import XCTest
@testable import NotificationsKit

final class NotificationPreferencesTests: XCTestCase {

    func test_activeKindsNeedTheTenantOnUnpausedAndBreakGlassNeedsAccounts() {
        var prefs = TenantAlertPreferences(tenantId: "T1", label: "contoso.com", enabled: true, kinds: [.securityIncident, .breakGlassSignIn, .serviceIncident])
        XCTAssertEqual(prefs.tenantId, "t1")
        XCTAssertEqual(prefs.activeKinds, [.serviceIncident, .securityIncident], "no accounts, no break-glass check")
        prefs.breakGlassUPNs = ["bg@contoso.com"]
        XCTAssertEqual(prefs.activeKinds, [.serviceIncident, .breakGlassSignIn, .securityIncident])
        prefs.paused = true
        XCTAssertEqual(prefs.activeKinds, [])
        prefs.paused = false
        prefs.enabled = false
        XCTAssertEqual(prefs.activeKinds, [])
    }

    func test_upnCleaning() {
        let cleaned = TenantAlertPreferences.cleanUPNs([" BG1@Contoso.com ", "bg1@contoso.com", "not-an-address", "@contoso.com", "a@b", "x'y@contoso.com", "bg2@contoso.onmicrosoft.com"])
        XCTAssertEqual(cleaned, ["bg1@contoso.com", "bg2@contoso.onmicrosoft.com"])
    }

    func test_upsertAndQueries() {
        var all = NotificationPreferences()
        XCTAssertFalse(all.anythingToCheck)
        all.upsert(TenantAlertPreferences(tenantId: "t1", label: "a", enabled: true, kinds: [.serviceIncident]))
        all.upsert(TenantAlertPreferences(tenantId: "t2", label: "b", enabled: true, kinds: [.serviceIncident], paused: true))
        XCTAssertTrue(all.anythingToCheck)
        XCTAssertEqual(all.paused.map(\.tenantId), ["t2"])
        all.upsert(TenantAlertPreferences(tenantId: "T1", label: "renamed", enabled: false))
        XCTAssertEqual(all.tenants.count, 2)
        XCTAssertEqual(all.tenant("t1")?.label, "renamed")
        XCTAssertFalse(all.tenant("t1")!.enabled)
    }

    func test_preferencesRoundTripThroughJSON() throws {
        let prefs = NotificationPreferences(tenants: [TenantAlertPreferences(tenantId: "t1", label: "a", enabled: true, kinds: [.breakGlassSignIn], breakGlassUPNs: ["bg@a.com"])])
        let data = try JSONEncoder().encode(prefs)
        XCTAssertEqual(try JSONDecoder().decode(NotificationPreferences.self, from: data), prefs)
    }

    func test_inMemoryStore() throws {
        let store = InMemoryNotificationPreferencesStore()
        XCTAssertTrue(try store.load().tenants.isEmpty)
        try store.save(NotificationPreferences(tenants: [TenantAlertPreferences(tenantId: "t", label: "l")]))
        XCTAssertEqual(try store.load().tenants.count, 1)
        try store.clear()
        XCTAssertTrue(try store.load().tenants.isEmpty)
    }
}
