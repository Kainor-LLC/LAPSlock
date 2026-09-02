import XCTest
@testable import AuthKit

/// Ordering and de-duplication for the MSP tenant picker.
final class TenantListTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_788_321_139)

    private func ref(_ id: String, _ label: String, ago: TimeInterval = 0) -> TenantReference {
        TenantReference(tenantId: id, label: label, lastUsedAt: now.addingTimeInterval(-ago))
    }

    private let a = "aaaaaaaa-1111-2222-3333-444455556666"
    private let b = "bbbbbbbb-1111-2222-3333-444455556666"
    private let c = "cccccccc-1111-2222-3333-444455556666"

    func test_mostRecentlyUsedComesFirst() {
        let list = TenantList.sorted([ref(a, "a.com", ago: 100), ref(b, "b.com", ago: 10), ref(c, "c.com", ago: 50)])
        XCTAssertEqual(list.map(\.label), ["b.com", "c.com", "a.com"])
    }

    func test_reAddingATenantUpdatesItRatherThanDuplicating() {
        // Two rows for one directory would be a picker that lies about how many customers
        // you have, and a second tap that silently does nothing different.
        let existing = [ref(a, "old-label.com", ago: 500)]
        let updated = TenantList.upsert(ref(a, "contoso.com"), into: existing)

        XCTAssertEqual(updated.count, 1)
        XCTAssertEqual(updated.first?.label, "contoso.com")
        XCTAssertEqual(updated.first?.tenantId, a)
    }

    func test_tenantIdsAreComparedCaseInsensitively() {
        let existing = [ref(a, "contoso.com")]
        let updated = TenantList.upsert(
            TenantReference(tenantId: a.uppercased(), label: "contoso.com", lastUsedAt: now),
            into: existing)
        XCTAssertEqual(updated.count, 1, "an uppercase GUID is the same directory")
    }

    func test_anUpsertedTenantSortsToTheTop() {
        let existing = [ref(a, "a.com", ago: 1), ref(b, "b.com", ago: 2)]
        let updated = TenantList.upsert(ref(c, "c.com"), into: existing)
        XCTAssertEqual(updated.first?.label, "c.com")
    }

    func test_theListIsCappedAndDropsTheStalest() {
        var list: [TenantReference] = []
        for i in 0..<60 {
            let id = String(format: "%08x-1111-2222-3333-444455556666", i)
            list = TenantList.upsert(ref(id, "t\(i).com", ago: TimeInterval(60 - i)), into: list, limit: 50)
        }
        XCTAssertEqual(list.count, 50)
        // Newest kept, oldest dropped.
        XCTAssertEqual(list.first?.label, "t59.com")
        XCTAssertFalse(list.contains { $0.label == "t0.com" })
    }

    func test_removingATenant() {
        let list = [ref(a, "a.com"), ref(b, "b.com")]
        XCTAssertEqual(TenantList.removing(b, from: list).map(\.label), ["a.com"])
        XCTAssertEqual(TenantList.removing(b.uppercased(), from: list).map(\.label), ["a.com"])
        XCTAssertEqual(TenantList.removing(c, from: list).count, 2, "removing something absent is a no-op")
    }

    func test_aReferenceLowercasesItsTenantId() {
        XCTAssertEqual(TenantReference(tenantId: a.uppercased(), label: "x").tenantId, a)
    }
}
