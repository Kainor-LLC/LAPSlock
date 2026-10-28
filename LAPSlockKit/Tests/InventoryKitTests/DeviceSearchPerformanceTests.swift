import XCTest
@testable import InventoryKit

/// The device list's cost at the size of a large customer, as numbers rather than guesses.
/// Optimization plan step C: the baseline the later steps are measured against. Run them
/// with `swift test -c release --filter DeviceSearchPerformanceTests` for figures close to
/// the shipping build; a debug run is slower but compares fairly with another debug run.
final class DeviceSearchPerformanceTests: XCTestCase {

    private static let fleet = DemoInventoryProvider.largeFleet()

    func test_theLargeFleetIsTheSameOnEveryRunAndShapedLikeATenant() {
        let again = DemoInventoryProvider.largeFleet()
        XCTAssertEqual(Self.fleet.count, 20_000)
        XCTAssertEqual(Self.fleet.map(\.id), again.map(\.id))
        XCTAssertEqual(Set(Self.fleet.map(\.id)).count, 20_000, "ids are unique")
        let windows = Self.fleet.filter { $0.platform == .windows }.count
        XCTAssertEqual(windows, 14_000)
        XCTAssertEqual(Set(Self.fleet.compactMap(\.userPrincipalName)).count, 5_000)
    }

    /// One debounced keystroke in the search field.
    func test_performance_aSearchOverTwentyThousandDevices() {
        let fleet = Self.fleet
        measure {
            _ = DeviceSearch.filter(fleet, query: "sales")
        }
    }

    /// An empty query sorts the whole list; today this runs as every fill page lands.
    func test_performance_theEmptyQuerySortOfTwentyThousandDevices() {
        let fleet = Self.fleet
        measure {
            _ = DeviceSearch.filter(fleet, query: "")
        }
    }

    /// The step C fill: 50 pages of 100, and after each one the whole accumulated list
    /// filtered again for the screen. Kept to compare against the one below.
    func test_performance_todaysFillRefiltersEveryPage() {
        let fleet = Array(Self.fleet.prefix(5_000))
        measure {
            var loaded: [ManagedDeviceSummary] = []
            for start in stride(from: 0, to: fleet.count, by: 100) {
                loaded.append(contentsOf: fleet[start..<min(start + 100, fleet.count)])
                _ = DeviceSearch.filter(loaded, query: "")
            }
        }
    }

    /// The step E fill over the whole tenant: 20 pages of 1,000, each merged into the
    /// sorted list rather than the list sorted again.
    func test_performance_theFillMergesEachPage() {
        let fleet = Self.fleet
        measure {
            var list: [ManagedDeviceSummary] = []
            for start in stride(from: 0, to: fleet.count, by: 1_000) {
                list = DeviceSearch.merged(list, adding: Array(fleet[start..<min(start + 1_000, fleet.count)]))
            }
        }
    }

    /// A page landing while something is typed: only the page is matched, then merged.
    func test_performance_aPageMergedIntoSearchResults() {
        let fleet = Self.fleet
        let results = DeviceSearch.filter(Array(fleet.prefix(19_000)), query: "sales")
        let page = Array(fleet.suffix(1_000))
        measure {
            _ = DeviceSearch.merged(results: results, query: "sales", adding: page)
        }
    }

    /// What moved out of every keystroke: folding each device's fields, now once when the
    /// device is built, on the inventory actor rather than the main thread.
    func test_performance_buildingTheSearchKeysForTwentyThousandDevices() {
        let fleet = Self.fleet
        measure {
            _ = fleet.map {
                DeviceSearchKey(deviceName: $0.deviceName, userDisplayName: $0.userDisplayName,
                                userPrincipalName: $0.userPrincipalName, emailAddress: $0.emailAddress,
                                serialNumber: $0.serialNumber, model: $0.model, managedDeviceName: $0.managedDeviceName)
            }
        }
    }
}
