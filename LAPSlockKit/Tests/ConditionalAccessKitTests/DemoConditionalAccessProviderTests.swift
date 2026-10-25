import XCTest
@testable import ConditionalAccessKit

final class DemoConditionalAccessProviderTests: XCTestCase {

    private let now = Date()

    func test_fixturesCoverEveryStateAndTheBadgeWindow() async throws {
        let provider = DemoConditionalAccessProvider(latency: .milliseconds(1), now: now)
        let policies = try await provider.policies()
        XCTAssertEqual(policies.count, 8)
        XCTAssertTrue(policies.contains { $0.state == .enabled })
        XCTAssertTrue(policies.contains { $0.state == .disabled })
        XCTAssertTrue(policies.contains { $0.state == .reportOnly })
        XCTAssertTrue(policies.contains { $0.changed(withinDays: 7, now: now) })
        XCTAssertTrue(policies.contains { !$0.changed(withinDays: 7, now: now) })
        XCTAssertEqual(policies.first?.id, DemoConditionalAccessProvider.adminStrengthId)
    }

    func test_everyFixtureReferenceResolvesExceptTheOneMeantNotTo() async throws {
        let provider = DemoConditionalAccessProvider(latency: .milliseconds(1), now: now)
        let policies = try await provider.policies()
        let refs = policies.reduce(into: Set<DirectoryReference>()) { $0.formUnion($1.references) }
        let names = try await provider.names(for: refs)
        let unresolved = refs.filter { names[$0] == nil }
        XCTAssertEqual(unresolved.map(\.id), [DemoConditionalAccessProvider.unresolvedApp])
    }

    func test_changesExistForTheRecentlyChangedPolicy() async throws {
        let provider = DemoConditionalAccessProvider(latency: .milliseconds(1), now: now)
        let changes = try await provider.changes(forPolicyId: DemoConditionalAccessProvider.compliantDeviceId)
        XCTAssertEqual(changes.count, 2)
        XCTAssertEqual(changes.first?.actor, "sec-admin@demo.example")
        let none = try await provider.changes(forPolicyId: DemoConditionalAccessProvider.requireMFAId)
        XCTAssertTrue(none.isEmpty)
    }

    func test_fixtureIdsAreGUIDsSoTheLiveFilterWouldAcceptThem() {
        for policy in DemoConditionalAccessProvider.policies(now: now) {
            XCTAssertTrue(ConditionalAccessVocabulary.isDirectoryId(policy.id), policy.id)
        }
    }
}
