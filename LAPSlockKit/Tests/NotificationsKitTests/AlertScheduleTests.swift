import XCTest
@testable import NotificationsKit

// Step F (OPTIMIZATION-PLAN.md): which kinds the background run reads when, and where it
// starts. What matters is that nothing due is skipped, nothing is read more than it needs,
// and every tenant is reached.
final class AlertScheduleTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    func test_kindsThatChangeAllTheTimeAreReadEveryRun() {
        for kind in [AlertKind.serviceIncident, .breakGlassSignIn, .conditionalAccessChange, .securityIncident, .pimApproval] {
            XCTAssertNil(AlertSchedule.interval(for: kind), kind.rawValue)
            XCTAssertEqual(AlertSchedule.due([kind], lastChecked: { _ in self.now }, now: now), [kind], kind.rawValue)
        }
    }

    func test_slowKindsWaitTheirInterval() {
        let checked: [AlertKind: TimeInterval] = [.secureScoreDrop: 23 * 3_600, .expiringCredential: 11 * 3_600, .messageDeadline: 4 * 3_600]
        let notYet = AlertSchedule.due(Array(checked.keys), lastChecked: { self.now.addingTimeInterval(-checked[$0]!) }, now: now)
        XCTAssertTrue(notYet.isEmpty, "each was read more recently than its interval")
        let later = AlertSchedule.due(Array(checked.keys), lastChecked: { self.now.addingTimeInterval(-checked[$0]! - 2 * 3_600) }, now: now)
        XCTAssertEqual(Set(later), Set(checked.keys))
    }

    func test_aKindNeverReadIsDue() {
        XCTAssertEqual(AlertSchedule.due([.secureScoreDrop], lastChecked: { _ in nil }, now: now), [.secureScoreDrop])
    }

    private func tenant(_ id: String) -> TenantAlertPreferences {
        TenantAlertPreferences(tenantId: id, label: id, enabled: true, kinds: [.serviceIncident])
    }

    func test_eachRunStartsAfterTheTenantTheLastOneFinished() {
        let tenants = ["a", "b", "c", "d"].map(tenant)
        XCTAssertEqual(AlertSchedule.rotated(tenants, after: nil).map(\.tenantId), ["a", "b", "c", "d"])
        XCTAssertEqual(AlertSchedule.rotated(tenants, after: "b").map(\.tenantId), ["c", "d", "a", "b"])
        XCTAssertEqual(AlertSchedule.rotated(tenants, after: "D").map(\.tenantId), ["a", "b", "c", "d"])
        XCTAssertEqual(AlertSchedule.rotated(tenants, after: "gone").map(\.tenantId), ["a", "b", "c", "d"], "a removed tenant starts at the top")
    }

    func test_theCheckLogKeepsTimesPerTenantAndKindAndClearsWithLastSeen() {
        let defaults = UserDefaults(suiteName: "AlertScheduleTests")!
        defaults.removePersistentDomain(forName: "AlertScheduleTests")
        let store = UserDefaultsLastSeenStore(defaults: defaults)
        store.setChecked(now, tenantId: "T1", kind: .secureScoreDrop)
        store.setFinished(now, tenantId: "t1")
        store.setLastTenant("T1")
        store.setKeys(["k"], tenantId: "t1", kind: .secureScoreDrop)
        XCTAssertEqual(store.lastChecked(tenantId: "t1", kind: .secureScoreDrop), now)
        XCTAssertNil(store.lastChecked(tenantId: "t1", kind: .messageDeadline))
        XCTAssertEqual(store.lastFinished(tenantId: "T1"), now)
        XCTAssertEqual(store.lastTenant, "t1")

        store.clear(tenantId: "t1")
        XCTAssertNil(store.lastChecked(tenantId: "t1", kind: .secureScoreDrop))
        XCTAssertNil(store.lastFinished(tenantId: "t1"))
        XCTAssertNil(store.lastTenant)
        XCTAssertNil(store.keys(tenantId: "t1", kind: .secureScoreDrop))
        defaults.removePersistentDomain(forName: "AlertScheduleTests")
    }

    func test_aSkippedKindLeavesItsLastSeenKeysSoNothingReAlerts() {
        // The planner remembers only the kinds it was given. A kind the schedule skipped is
        // not given, so the next time it is read it compares against what it saw before.
        var stored: [AlertKind: Set<String>] = [.secureScoreDrop: ["s1"], .serviceIncident: ["i1"]]
        let result = AlertPlanner().plan(tenantId: "t", label: "T",
                                         observations: [AlertObservation(kind: .serviceIncident, keys: ["i1"])],
                                         lastSeen: { stored[$0] })
        XCTAssertTrue(result.alerts.isEmpty)
        XCTAssertNil(result.remembered[.secureScoreDrop], "untouched")
        for (kind, keys) in result.remembered { stored[kind] = keys }
        let later = AlertPlanner().plan(tenantId: "t", label: "T",
                                        observations: [AlertObservation(kind: .secureScoreDrop, keys: ["s1"])],
                                        lastSeen: { stored[$0] })
        XCTAssertTrue(later.alerts.isEmpty, "the same drop, seen before the skip, is not news")
    }
}
