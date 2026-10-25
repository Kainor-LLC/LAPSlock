import XCTest
@testable import TenantPulseKit

final class DemoTenantPulseProviderTests: XCTestCase {

    private let now = Date()

    func test_fixturesCoverEveryCardState() async throws {
        let provider = DemoTenantPulseProvider(latency: .milliseconds(1), now: now)
        let health = try await provider.health()
        XCTAssertEqual(health.degraded.count, 2)
        XCTAssertEqual(health.activeIssues.count, 3)
        XCTAssertTrue(health.activeIssues.contains { !$0.isIncident })

        let messages = try await provider.messages()
        XCTAssertEqual(messages.count, 4, "the plain stay-informed post is filtered out")
        XCTAssertEqual(messages.first?.id, "MC900101", "soonest deadline first")

        let items = try await provider.expiringItems()
        let relevant = ExpiryWindow.relevant(items, now: now)
        XCTAssertEqual(Set(relevant.map { $0.bucket(now: now) }), [.expired, .within30Days, .within90Days])
        XCTAssertEqual(Set(items.map(\.kind)), Set(ExpiringItem.Kind.allCases))

        let score = try await provider.secureScore()
        XCTAssertEqual(score?.latest.currentScore, 612)
        XCTAssertEqual(try XCTUnwrap(score?.change), 14, accuracy: 0.001)
        XCTAssertEqual(try XCTUnwrap(score?.identityChange), 14, accuracy: 0.001)
        XCTAssertEqual(try XCTUnwrap(score?.change(overDays: 30)), 41, accuracy: 0.001)
        XCTAssertEqual(score?.history.count, 31)
    }
}
