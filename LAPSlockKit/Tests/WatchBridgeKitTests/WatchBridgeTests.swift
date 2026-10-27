import XCTest
@testable import WatchBridgeKit

final class WatchBridgeTests: XCTestCase {

    private func sample(approvals: Int = 2) -> WatchGlance {
        WatchGlance(
            updatedAt: Date(timeIntervalSince1970: 1_800_000_000), tenant: "contoso.com", isDemo: false,
            health: .init(degradedServices: 1, openIncidents: 2, expiringSoon: 3, secureScorePercent: 64),
            activeRoles: [.init(name: "Intune Administrator", endsAt: Date(timeIntervalSince1970: 1_800_010_000))],
            eligible: [.init(id: "e1", name: "Global Reader", isGroup: false)],
            approvals: (0..<approvals).map { .init(id: "r\($0)", requester: "Sam", target: "Exchange Administrator", duration: "4 hours", reason: "Change CHG-2207", askedAt: nil) })
    }

    func testRoundTripsThroughTheTransportDictionary() throws {
        let glance = sample()
        let message = try WatchBridge.encode(glance)
        XCTAssertEqual(WatchBridge.decode(WatchGlance.self, from: message), glance)
        for request in [WatchRequest.refresh, .decide(approvalId: "r1", approve: true, reason: "checked"), .activate(eligibleId: "e1", reason: "bench", hours: 2)] {
            XCTAssertEqual(WatchBridge.decode(WatchRequest.self, from: try WatchBridge.encode(request)), request)
        }
        XCTAssertNil(WatchBridge.decode(WatchGlance.self, from: ["other": 1]))
    }

    /// No key anywhere in what crosses to the watch may name a secret. A new field called
    /// `password`, `token` or the like fails here before it can ship.
    func testNothingThatCrossesCanNameASecret() throws {
        let banned = ["password", "secret", "token", "credential", "key", "pass", "recovery", "bearer", "claim"]
        var keys = Set<String>()
        func walk(_ any: Any) {
            if let dict = any as? [String: Any] {
                for (k, v) in dict { keys.insert(k.lowercased()); walk(v) }
            } else if let list = any as? [Any] {
                list.forEach(walk)
            }
        }
        let reply = WatchReply(outcome: .done, message: "ok", glance: sample())
        for value in [try JSONEncoder().encode(sample()), try JSONEncoder().encode(reply),
                      try JSONEncoder().encode(WatchRequest.decide(approvalId: "a", approve: true, reason: "r")),
                      try JSONEncoder().encode(WatchRequest.activate(eligibleId: "e", reason: "r", hours: 1))] {
            walk(try JSONSerialization.jsonObject(with: value))
        }
        for key in keys {
            for word in banned {
                XCTAssertFalse(key.contains(word), "'" + key + "' crosses to the watch")
            }
        }
        XCTAssertTrue(keys.contains("approvals"), "the walk saw the glance")
    }

    func testTheGlanceFitsTheTransport() throws {
        var big = sample(approvals: 200)
        for i in big.approvals.indices { big.approvals[i].reason = String(repeating: "x", count: 2000) }
        let fitted = big.fitted()
        XCTAssertEqual(fitted.approvals.count, 20)
        let size = try JSONEncoder().encode(fitted).count
        XCTAssertLessThan(size, WatchBridge.glanceByteLimit)
    }

    func testRequestsAreCheckedBeforeTheyLeaveTheWrist() {
        XCTAssertNil(WatchRequest.refresh.problem)
        XCTAssertNotNil(WatchRequest.decide(approvalId: "a", approve: false, reason: "no").problem)
        XCTAssertNil(WatchRequest.decide(approvalId: "a", approve: false, reason: "not on rota").problem)
        XCTAssertNotNil(WatchRequest.activate(eligibleId: "e", reason: "bench work", hours: 9).problem)
        XCTAssertNil(WatchRequest.activate(eligibleId: "e", reason: "bench work", hours: 8).problem)
    }
}

final class ComplicationSnapshotTests: XCTestCase {
    func testTheSnapshotHoldsCountsAndATimeOnly() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let glance = WatchGlance(updatedAt: now, tenant: "contoso.com", isDemo: false,
                                 health: .init(degradedServices: 2, openIncidents: 0),
                                 activeRoles: [.init(name: "A", endsAt: now.addingTimeInterval(3600)), .init(name: "B", endsAt: now.addingTimeInterval(600)), .init(name: "C", endsAt: nil)],
                                 approvals: [.init(id: "1", requester: "Sam", target: "X", duration: nil, reason: nil, askedAt: nil)])
        let snap = ComplicationSnapshot(glance)
        XCTAssertEqual(snap.approvalsWaiting, 1)
        XCTAssertEqual(snap.nextRoleEnds, now.addingTimeInterval(600))
        XCTAssertTrue(snap.needsAttention)
        let json = String(data: try JSONEncoder().encode(snap), encoding: .utf8) ?? ""
        XCTAssertFalse(json.contains("contoso"), "no tenant on the watch face")
        XCTAssertFalse(json.contains("Sam"), "no names on the watch face")
    }

    func testSaveLoadAndClear() {
        let defaults = UserDefaults(suiteName: "complication-test-" + UUID().uuidString)
        let snap = ComplicationSnapshot(updatedAt: Date(timeIntervalSince1970: 1), approvalsWaiting: 3, degradedServices: nil, openIncidents: 1, nextRoleEnds: nil, isDemo: true)
        snap.save(to: defaults)
        XCTAssertEqual(ComplicationSnapshot.load(from: defaults), snap)
        ComplicationSnapshot.clear(in: defaults)
        XCTAssertNil(ComplicationSnapshot.load(from: defaults))
    }
}
