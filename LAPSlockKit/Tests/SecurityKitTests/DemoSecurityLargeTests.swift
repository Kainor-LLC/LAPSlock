import XCTest
@testable import SecurityKit

final class DemoSecurityLargeTests: XCTestCase {
    func test_theLargeTenantHas200IncidentsWithEvidenceTheSameOnEveryRun() async throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let incidents = DemoSecurityProvider.largeIncidents(now: now)
        XCTAssertEqual(incidents.count, 200)
        XCTAssertEqual(Set(incidents.map(\.id)).count, 200)
        XCTAssertEqual(incidents.map(\.id), DemoSecurityProvider.largeIncidents(now: now).map(\.id))
        XCTAssertTrue(incidents.contains { $0.isOpen } && incidents.contains { !$0.isOpen })
        XCTAssertGreaterThan(incidents.map(\.evidence.count).reduce(0, +), 3_000)

        let provider = DemoSecurityProvider(latency: .milliseconds(1), now: now, large: true)
        let listed = try await provider.incidents()
        XCTAssertEqual(listed.count, 200)
        let one = try await provider.incident(id: incidents[7].id)
        XCTAssertEqual(one.id, incidents[7].id)
    }
}
