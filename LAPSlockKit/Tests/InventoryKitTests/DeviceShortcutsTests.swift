import XCTest
@testable import InventoryKit

final class DeviceShortcutsTests: XCTestCase {

    private var store: DeviceShortcutStore!
    private var defaults: UserDefaults!
    private let tenantA = "4470dc21-a4b7-4729-a232-56d4c0eedf73"
    private let tenantB = "9911aa22-bb33-cc44-dd55-ee66ff778899"

    override func setUp() {
        super.setUp()
        // A private suite per test, so nothing leaks between tests or into the real app.
        defaults = UserDefaults(suiteName: "shortcuts-tests-\(UUID().uuidString)")
        store = DeviceShortcutStore(defaults: defaults)
    }

    // MARK: - the list rules

    func test_togglingAddsNewestFirstAndRemovesOnSecondTap() {
        var list = DeviceShortcutStore.toggling("a", in: [])
        XCTAssertEqual(list, ["a"])
        list = DeviceShortcutStore.toggling("b", in: list)
        XCTAssertEqual(list, ["b", "a"], "most recently pinned first")
        list = DeviceShortcutStore.toggling("a", in: list)
        XCTAssertEqual(list, ["b"], "a second tap unpins")
    }

    func test_revisitingMovesUpRatherThanDuplicating() {
        // Otherwise five recents become five copies of the machine you are working on,
        // which is the opposite of useful.
        var list = DeviceShortcutStore.recording("a", in: [])
        list = DeviceShortcutStore.recording("b", in: list)
        list = DeviceShortcutStore.recording("a", in: list)
        XCTAssertEqual(list, ["a", "b"])
    }

    func test_recentsAreCappedAndDropTheOldest() {
        var list: [String] = []
        for id in ["1", "2", "3", "4", "5", "6", "7"] {
            list = DeviceShortcutStore.recording(id, in: list)
        }
        XCTAssertEqual(list, ["7", "6", "5", "4", "3"])
        XCTAssertEqual(list.count, DeviceShortcutStore.maxRecents)
    }

    func test_aZeroCapIsHandledRatherThanCrashing() {
        XCTAssertEqual(DeviceShortcutStore.recording("a", in: ["b"], cap: 0), [])
    }

    // MARK: - tenant isolation, which is the one that matters for MSPs

    func test_tenantsDoNotSeeEachOthersShortcuts() {
        // THE test in this file. An MSP switches customers inside one install; favourites
        // from customer A appearing while operating in customer B leaks which machines
        // matter to whom.
        store.toggleFavourite("device-in-a", tenantId: tenantA)
        store.recordVisit("visited-in-a", tenantId: tenantA)

        let b = store.shortcuts(tenantId: tenantB)
        XCTAssertTrue(b.isEmpty, "customer B must start empty")

        let a = store.shortcuts(tenantId: tenantA)
        XCTAssertEqual(a.favourites, ["device-in-a"])
        XCTAssertEqual(a.recents, ["visited-in-a"])
    }

    func test_tenantIdCasingDoesNotSplitTheList() {
        // Graph and MSAL disagree about GUID casing. A case difference silently giving one
        // tenant two separate lists would look like shortcuts randomly vanishing.
        store.toggleFavourite("d1", tenantId: tenantA.uppercased())
        XCTAssertEqual(store.shortcuts(tenantId: tenantA.lowercased()).favourites, ["d1"])
    }

    func test_clearingOneTenantLeavesTheOtherAlone() {
        // Sign-out wipes the signed-in tenant, not an MSP's whole customer list.
        store.toggleFavourite("d-a", tenantId: tenantA)
        store.toggleFavourite("d-b", tenantId: tenantB)
        store.clear(tenantId: tenantA)
        XCTAssertTrue(store.shortcuts(tenantId: tenantA).isEmpty)
        XCTAssertEqual(store.shortcuts(tenantId: tenantB).favourites, ["d-b"])
    }

    // MARK: - persistence and shape

    func test_shortcutsSurviveANewStoreOverTheSameDefaults() {
        store.toggleFavourite("d1", tenantId: tenantA)
        let reopened = DeviceShortcutStore(defaults: defaults)
        XCTAssertEqual(reopened.shortcuts(tenantId: tenantA).favourites, ["d1"])
    }

    func test_favouritesAndRecentsAreIndependent() {
        store.recordVisit("d1", tenantId: tenantA)
        let after = store.shortcuts(tenantId: tenantA)
        XCTAssertEqual(after.recents, ["d1"])
        XCTAssertTrue(after.favourites.isEmpty, "visiting a device does not pin it")
    }

    func test_isFavouriteAnswersForTheStoredList() {
        store.toggleFavourite("d1", tenantId: tenantA)
        let shortcuts = store.shortcuts(tenantId: tenantA)
        XCTAssertTrue(shortcuts.isFavourite("d1"))
        XCTAssertFalse(shortcuts.isFavourite("d2"))
    }

    func test_onlyIdentifiersAreEverStored() {
        // The stored keys must contain nothing but the tenant and a suffix, and the stored
        // values nothing but device IDs. A hostname on disk would be tenant data held for
        // no reason.
        store.toggleFavourite("device-id-only", tenantId: tenantA)
        let keys = defaults.dictionaryRepresentation().keys.filter { $0.hasPrefix("shortcuts.") }
        XCTAssertEqual(Set(keys), [
            DeviceShortcutStore.key(tenantA, "favourites"),
            DeviceShortcutStore.key(tenantA, "recents"),
        ])
        XCTAssertEqual(defaults.stringArray(forKey: DeviceShortcutStore.key(tenantA, "favourites")),
                       ["device-id-only"])
    }
}
