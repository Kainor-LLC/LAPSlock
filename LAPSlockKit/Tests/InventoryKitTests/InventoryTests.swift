import XCTest
import CredentialKit
@testable import InventoryKit

// Build Spec §13 — inventory parsing and search tests. No network, no Microsoft deps.
//
// The parsing tests matter more than they look: the Entra device id normalization is
// what stands between an admin and a confusing 404. Graph returns "no Entra identity"
// three different ways (absent key, empty string, all-zeros GUID) and all three must
// land as nil so the UI can explain the situation instead of firing a doomed request.

final class ManagedDeviceSummaryTests: XCTestCase {

    // MARK: - parsing

    func test_parsesFullWindowsDevice() {
        let entry: [String: Any] = [
            "id": "intune-1",
            "deviceName": "WS-4821",
            "operatingSystem": "Windows",
            "osVersion": "10.0.26100.1",
            "azureADDeviceId": "bd367e9e-2f43-490d-92d0-000000000001",
            "userPrincipalName": "tech@example.com",
            "serialNumber": "SN12345",
            "model": "OptiPlex 7090",
            "manufacturer": "Dell Inc.",
            "complianceState": "compliant",
            "lastSyncDateTime": "2026-08-14T18:42:08Z"
        ]
        let d = ManagedDeviceSummary(graphEntry: entry)
        XCTAssertNotNil(d)
        XCTAssertEqual(d?.id, "intune-1")
        XCTAssertEqual(d?.deviceName, "WS-4821")
        XCTAssertEqual(d?.platform, .windows)
        XCTAssertEqual(d?.entraDeviceId, "bd367e9e-2f43-490d-92d0-000000000001")
        XCTAssertTrue(d?.hasEntraDeviceIdentity == true)
        XCTAssertNil(d?.revealBlockedReason, "A joined Windows device should not be blocked.")
        XCTAssertNotNil(d?.lastSyncDateTime)
    }

    func test_rejectsEntryWithoutId() {
        XCTAssertNil(ManagedDeviceSummary(graphEntry: ["deviceName": "no-id"]))
        XCTAssertNil(ManagedDeviceSummary(graphEntry: ["id": ""]))
    }

    func test_missingDeviceName_getsPlaceholder() {
        let d = ManagedDeviceSummary(graphEntry: ["id": "x", "operatingSystem": "Windows"])
        XCTAssertEqual(d?.deviceName, "Unnamed device")
    }

    // MARK: - the three ways Graph says "no Entra identity"

    func test_entraDeviceId_absentKey_isNil() {
        let d = ManagedDeviceSummary(graphEntry: ["id": "x", "operatingSystem": "Windows"])
        XCTAssertNil(d?.entraDeviceId)
        XCTAssertFalse(d?.hasEntraDeviceIdentity == true)
    }

    func test_entraDeviceId_emptyString_isNil() {
        let d = ManagedDeviceSummary(graphEntry: [
            "id": "x", "operatingSystem": "Windows", "azureADDeviceId": ""
        ])
        XCTAssertNil(d?.entraDeviceId)
    }

    func test_entraDeviceId_allZerosGuid_isNil() {
        let d = ManagedDeviceSummary(graphEntry: [
            "id": "x",
            "operatingSystem": "Windows",
            "azureADDeviceId": "00000000-0000-0000-0000-000000000000"
        ])
        XCTAssertNil(d?.entraDeviceId, "The all-zeros GUID is Graph's placeholder, not an identity.")
    }

    func test_entraDeviceId_whitespaceTrimmed() {
        let d = ManagedDeviceSummary(graphEntry: [
            "id": "x", "operatingSystem": "Windows", "azureADDeviceId": "  abc-123  "
        ])
        XCTAssertEqual(d?.entraDeviceId, "abc-123")
    }

    // MARK: - reveal blocking (structural, not permission-based)

    func test_windowsWithoutEntraIdentity_isBlockedWithExplanation() {
        let d = ManagedDeviceSummary(graphEntry: ["id": "x", "operatingSystem": "Windows"])
        let reason = d?.revealBlockedReason
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason?.contains("Entra") == true)
    }

    func test_iosDevice_isBlockedAsUnsupportedPlatform() {
        let d = ManagedDeviceSummary(graphEntry: [
            "id": "x", "operatingSystem": "iOS", "azureADDeviceId": "abc"
        ])
        XCTAssertEqual(d?.platform, .other)
        XCTAssertNotNil(d?.revealBlockedReason)
    }

    func test_macOS_notBlockedStructurally() {
        // macOS reveal is unavailable for an API reason, which MacOSLapsProvider reports.
        // That is a different concern from a structural block, so nothing here.
        let d = ManagedDeviceSummary(graphEntry: [
            "id": "x", "operatingSystem": "macOS", "azureADDeviceId": "abc"
        ])
        XCTAssertEqual(d?.platform, .macOS)
        XCTAssertNil(d?.revealBlockedReason)
    }

    // MARK: - credential hand-off carries both identifiers (§2.5)

    func test_credentialTarget_carriesBothIdentifiers() {
        let d = ManagedDeviceSummary(graphEntry: [
            "id": "intune-1", "operatingSystem": "Windows",
            "azureADDeviceId": "entra-1", "deviceName": "WS-1"
        ])!
        let target = d.credentialTarget
        XCTAssertEqual(target.managedDeviceId, "intune-1")
        XCTAssertEqual(target.entraDeviceId, "entra-1")
        XCTAssertEqual(target.platform, .windows)
        XCTAssertEqual(target.deviceName, "WS-1")
    }
}

final class DeviceSearchTests: XCTestCase {

    private func device(_ name: String, upn: String? = nil, serial: String? = nil, model: String? = nil) -> ManagedDeviceSummary {
        ManagedDeviceSummary(
            id: UUID().uuidString,
            entraDeviceId: "e-\(name)",
            deviceName: name,
            platform: .windows,
            userPrincipalName: upn,
            serialNumber: serial,
            model: model
        )
    }

    func test_emptyQuery_returnsAllSortedByName() {
        let list = [device("WS-99"), device("WS-01"), device("MBA-7")]
        let out = DeviceSearch.filter(list, query: "")
        XCTAssertEqual(out.map(\.deviceName), ["MBA-7", "WS-01", "WS-99"])
    }

    func test_matchesDeviceNameCaseInsensitively() {
        let list = [device("WS-4821"), device("MBA-1")]
        XCTAssertEqual(DeviceSearch.filter(list, query: "ws-48").map(\.deviceName), ["WS-4821"])
    }

    func test_matchesUserPrincipalName() {
        let list = [device("WS-1", upn: "tech@example.com"), device("WS-2")]
        XCTAssertEqual(DeviceSearch.filter(list, query: "tech@").map(\.deviceName), ["WS-1"])
    }

    func test_matchesSerialAndModel() {
        let list = [device("WS-1", serial: "ABC123"), device("WS-2", model: "OptiPlex 7090")]
        XCTAssertEqual(DeviceSearch.filter(list, query: "abc123").map(\.deviceName), ["WS-1"])
        XCTAssertEqual(DeviceSearch.filter(list, query: "optiplex").map(\.deviceName), ["WS-2"])
    }

    func test_exactAndPrefixMatchesSortFirst() {
        let list = [
            device("LAB-WS-01"),   // contains
            device("WS-01"),       // exact
            device("WS-01-SPARE")  // prefix
        ]
        let out = DeviceSearch.filter(list, query: "WS-01").map(\.deviceName)
        XCTAssertEqual(out.first, "WS-01", "An exact name match must rank first.")
        XCTAssertEqual(out[1], "WS-01-SPARE", "Prefix matches rank above substring matches.")
    }

    func test_whitespaceOnlyQueryTreatedAsEmpty() {
        let list = [device("A"), device("B")]
        XCTAssertEqual(DeviceSearch.filter(list, query: "   ").count, 2)
    }

    func test_noMatch_returnsEmpty() {
        let list = [device("WS-1"), device("WS-2")]
        XCTAssertTrue(DeviceSearch.filter(list, query: "zzzz").isEmpty)
    }
}
