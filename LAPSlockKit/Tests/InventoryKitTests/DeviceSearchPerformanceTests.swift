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

    /// Today's fill: 50 pages of 100, and after each one the whole accumulated list is
    /// filtered again for the screen.
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
}
