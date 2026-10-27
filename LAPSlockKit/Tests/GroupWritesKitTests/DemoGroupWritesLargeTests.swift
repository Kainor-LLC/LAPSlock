import XCTest
@testable import GroupWritesKit

final class DemoGroupWritesLargeTests: XCTestCase {
    func test_inTheLargeTenantAPersonIsIn300Groups() async throws {
        let provider = DemoGroupWritesProvider(latency: .milliseconds(1), large: true)
        let groups = try await provider.groups(of: GroupMember(userId: "u1", label: "a@demo.example"))
        XCTAssertEqual(groups.count, 300)
        XCTAssertEqual(Set(groups.map(\.id)).count, 300)
        let found = try await provider.search("hd-0")
        XCTAssertFalse(found.isEmpty)
        XCTAssertLessThanOrEqual(found.count, 25)
    }
}
