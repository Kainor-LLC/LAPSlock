import XCTest
@testable import TenantPulseKit

final class DemoTenantPulseLargeTests: XCTestCase {
    func test_theLargeTenantHasLongMessageAndExpiringLists() async throws {
        let provider = DemoTenantPulseProvider(latency: .milliseconds(1), large: true)
        let expiring = try await provider.expiringItems()
        XCTAssertEqual(expiring.count, 600)
        XCTAssertEqual(Set(expiring.map(\.id)).count, 600)
        let messages = try await provider.messages()
        XCTAssertGreaterThan(messages.count, 50, "the ones worth showing out of 200")
    }
}
