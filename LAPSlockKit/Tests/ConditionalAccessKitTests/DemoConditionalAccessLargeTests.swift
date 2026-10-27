import XCTest
@testable import ConditionalAccessKit

final class DemoConditionalAccessLargeTests: XCTestCase {
    func test_theLargeTenantHas150PoliciesWhoseNamesResolve() async throws {
        let provider = DemoConditionalAccessProvider(latency: .milliseconds(1), large: true)
        let policies = try await provider.policies()
        XCTAssertEqual(policies.count, 150)
        XCTAssertEqual(Set(policies.map(\.id)).count, 150)
        let group = DirectoryReference(kind: .group, id: DemoConditionalAccessProvider.largeId(2, 42))
        let names = try await provider.names(for: [group])
        XCTAssertEqual(names[group], "Group 42")
    }
}
