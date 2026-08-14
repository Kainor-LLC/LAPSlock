import XCTest
@testable import InventoryKit

// Tests for the build-number → release-name mapping.
//
// The behavior that matters most here is the FALLBACK. This table is a snapshot taken
// at a point in time, and Microsoft will ship builds that postdate it. An unknown build
// must degrade to something true ("Windows 11", or the raw version) and must never
// produce a confident wrong answer — an admin who reads "24H2" on a 26H1 machine has
// been actively misled.

final class WindowsReleaseTests: XCTestCase {

    // MARK: - parsing

    func test_parsesBuildFromFullVersion() {
        XCTAssertEqual(WindowsRelease.buildNumber(from: "10.0.26100.2314"), 26100)
    }

    func test_parsesBuildWithoutRevision() {
        XCTAssertEqual(WindowsRelease.buildNumber(from: "10.0.22631"), 22631)
    }

    func test_toleratesWhitespace() {
        XCTAssertEqual(WindowsRelease.buildNumber(from: "  10.0.19045.5011 "), 19045)
    }

    func test_rejectsMalformedVersions() {
        XCTAssertNil(WindowsRelease.buildNumber(from: "10.0"))
        XCTAssertNil(WindowsRelease.buildNumber(from: "not a version"))
        XCTAssertNil(WindowsRelease.buildNumber(from: ""))
        XCTAssertNil(WindowsRelease.buildNumber(from: nil))
    }

    // MARK: - known releases

    func test_windows11Releases() {
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.26100.2314"), "Windows 11 24H2")
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.22631.4317"), "Windows 11 23H2")
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.22000.1"), "Windows 11 21H2")
    }

    func test_windows10Releases() {
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.19045.5011"), "Windows 10 22H2")
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.17763.100"), "Windows 10 1809")
    }

    func test_serverBuildsNamedAsServer() {
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.20348.2000"), "Windows Server 2022")
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.25398.500"), "Windows Server 23H2")
    }

    // MARK: - the important part: unknown builds

    func test_unknownFutureBuild_fallsBackToGeneration() {
        // A build past the table must not be labelled with the nearest known release.
        let name = WindowsRelease.friendlyName(osVersion: "10.0.29999.1")
        XCTAssertEqual(name, "Windows 11")
        XCTAssertFalse(WindowsRelease.isExactMatch(osVersion: "10.0.29999.1"),
                       "Generation fallback must not be reported as an exact match.")
    }

    func test_unknownOlderWin10Build_fallsBackToGeneration() {
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.19100.1"), "Windows 10")
    }

    func test_veryOldBuildReturnsNil() {
        // Pre-Windows 10. Nothing true to say, so say nothing and let the UI show raw.
        XCTAssertNil(WindowsRelease.friendlyName(osVersion: "6.1.7601.1"))
    }

    func test_malformedVersionReturnsNil() {
        XCTAssertNil(WindowsRelease.friendlyName(osVersion: "garbage"))
        XCTAssertNil(WindowsRelease.friendlyName(osVersion: nil))
    }

    func test_exactMatchFlag() {
        XCTAssertTrue(WindowsRelease.isExactMatch(osVersion: "10.0.26100.2314"))
        XCTAssertFalse(WindowsRelease.isExactMatch(osVersion: "10.0.29999.1"))
        XCTAssertFalse(WindowsRelease.isExactMatch(osVersion: nil))
    }

    // MARK: - boundary

    func test_windows11BoundaryAt22000() {
        // 22000 is the documented Windows 10 / 11 split and is not expected to move.
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.21999.1"), "Windows 10")
        XCTAssertEqual(WindowsRelease.friendlyName(osVersion: "10.0.22000.1"), "Windows 11 21H2")
    }
}
