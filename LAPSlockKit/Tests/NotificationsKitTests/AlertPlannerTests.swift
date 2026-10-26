import XCTest
@testable import NotificationsKit

final class AlertPlannerTests: XCTestCase {

    private let tenant = "22222222-2222-4222-8222-222222222222"
    private let planner = AlertPlanner()

    func test_theFirstRunIsABaselineAndAnnouncesNothing() {
        let result = planner.plan(tenantId: tenant, label: "contoso.com",
                                  observations: [Observation(kind: .serviceIncident, keys: ["a", "b", "c"])],
                                  lastSeen: { _ in nil })
        XCTAssertTrue(result.alerts.isEmpty)
        XCTAssertEqual(result.remembered[.serviceIncident], ["a", "b", "c"])
    }

    func test_newKeysOfOneKindBecomeOneNotificationWithACount() {
        let result = planner.plan(tenantId: tenant, label: "contoso.com",
                                  observations: [Observation(kind: .serviceIncident, keys: ["a", "b", "c", "d"])],
                                  lastSeen: { _ in ["a", "b"] })
        XCTAssertEqual(result.alerts.count, 1)
        XCTAssertEqual(result.alerts.first?.body, "contoso.com: 2 new service incidents")
        XCTAssertEqual(result.alerts.first?.title, "Service health incidents")
        XCTAssertEqual(result.alerts.first?.moduleId, "tenantPulse")
        XCTAssertEqual(result.alerts.first?.threadIdentifier, tenant + ".serviceIncident")
        XCTAssertEqual(result.remembered[.serviceIncident], ["a", "b", "c", "d"])
    }

    func test_singularCopyAndTimeSensitivityForBreakGlass() {
        let result = planner.plan(tenantId: tenant, label: "contoso.com",
                                  observations: [Observation(kind: .breakGlassSignIn, keys: ["x"])],
                                  lastSeen: { _ in [] })
        XCTAssertEqual(result.alerts.first?.body, "contoso.com: 1 new break-glass sign-in")
        XCTAssertEqual(result.alerts.first?.timeSensitive, true)
        XCTAssertEqual(result.alerts.first?.userInfo, ["tenantId": tenant, "module": "signInTriage"])
    }

    func test_nothingNewMeansNothingPostedAndKindsAreIndependent() {
        let seen: [AlertKind: Set<String>] = [.serviceIncident: ["a"], .conditionalAccessChange: ["p1"]]
        let result = planner.plan(tenantId: tenant, label: "contoso.com",
                                  observations: [Observation(kind: .serviceIncident, keys: ["a"]),
                                                 Observation(kind: .conditionalAccessChange, keys: ["p1", "p2"]),
                                                 Observation(kind: .securityIncident, keys: ["s1"])],
                                  lastSeen: { seen[$0] })
        XCTAssertEqual(result.alerts.map(\.kind), [.conditionalAccessChange])
        XCTAssertEqual(result.remembered[.securityIncident], ["s1"], "a kind checked for the first time is a baseline")
    }

    func test_rememberedKeysAreCappedKeepingWhatIsCurrent() {
        let old = Set((0..<600).map { "old-\(String(format: "%04d", $0))" })
        let result = planner.plan(tenantId: tenant, label: "x",
                                  observations: [Observation(kind: .expiringCredential, keys: ["now"])],
                                  lastSeen: { _ in old })
        let kept = result.remembered[.expiringCredential]!
        XCTAssertEqual(kept.count, AlertPlanner.rememberedCap)
        XCTAssertTrue(kept.contains("now"))
    }

    func test_copyIsBuiltFromKindCountAndLabelOnly() {
        // The structural guarantee: nothing but a key enters the planner, and a key never
        // reaches the text. A key that looks like a person's address stays out of it.
        let result = planner.plan(tenantId: tenant, label: "contoso.com",
                                  observations: [Observation(kind: .breakGlassSignIn, keys: ["bg-admin@contoso.com"])],
                                  lastSeen: { _ in [] })
        let alert = try! XCTUnwrap(result.alerts.first)
        XCTAssertFalse(alert.title.contains("@"))
        XCTAssertFalse(alert.body.contains("bg-admin"))
        for kind in AlertKind.allCases {
            let text = AlertCopy.alert(tenantId: tenant, label: "L", kind: kind, count: 2)
            XCTAssertFalse(text.body.contains("\u{2014}"))
            XCTAssertFalse(kind.detail.contains("\u{2014}"))
        }
    }

    func test_needsSignInCopy() {
        let alert = AlertCopy.needsSignIn(tenantId: tenant, label: "contoso.com")
        XCTAssertNil(alert.kind)
        XCTAssertNil(alert.moduleId)
        XCTAssertTrue(alert.body.hasPrefix("contoso.com: "))
    }

    func test_opaqueKeysAreStableAndSayNothing() {
        let a = OpaqueKey.make("signin-id-1", "bg@contoso.com")
        XCTAssertEqual(a, OpaqueKey.make("signin-id-1", "bg@contoso.com"))
        XCTAssertNotEqual(a, OpaqueKey.make("signin-id-2", "bg@contoso.com"))
        XCTAssertFalse(a.contains("@"))
    }

    func test_userDefaultsStoreRoundTripsAndClearsOneTenant() {
        let defaults = UserDefaults(suiteName: "alerts-" + UUID().uuidString)!
        let store = UserDefaultsLastSeenStore(defaults: defaults)
        XCTAssertNil(store.keys(tenantId: tenant, kind: .serviceIncident))
        store.setKeys(["a"], tenantId: tenant.uppercased(), kind: .serviceIncident)
        store.setKeys(["b"], tenantId: "other", kind: .serviceIncident)
        XCTAssertEqual(store.keys(tenantId: tenant, kind: .serviceIncident), ["a"])
        store.clear(tenantId: tenant)
        XCTAssertNil(store.keys(tenantId: tenant, kind: .serviceIncident))
        XCTAssertEqual(store.keys(tenantId: "other", kind: .serviceIncident), ["b"])
    }
}
