import XCTest
import CredentialKit
@testable import InventoryKit

final class UserNameResolverTests: XCTestCase {

    private func device(_ name: String, upn: String?, displayName: String? = nil) -> ManagedDeviceSummary {
        ManagedDeviceSummary(
            id: name, entraDeviceId: "e-\(name)", deviceName: name, platform: .windows,
            userPrincipalName: upn, userDisplayName: displayName)
    }

    // MARK: - the request

    func test_filterUsesTheInOperatorWithQuotedValues() {
        XCTAssertEqual(
            UserNameResolver.filterClause(for: ["a@example.com", "b@example.com"]),
            "userPrincipalName in ('a@example.com','b@example.com')")
    }

    func test_anApostropheInAUPNIsDoubledNotLeftToBreakTheFilter() {
        // o'brien@ is a legal UPN. Unescaped, the quote ends the literal early and the
        // whole request is a 400 — for every user in the batch, not just this one.
        XCTAssertEqual(
            UserNameResolver.filterClause(for: ["o'brien@example.com"]),
            "userPrincipalName in ('o''brien@example.com')")
    }

    func test_batchesAreAtMostFifteenBecauseThatIsWhatGraphAccepts() {
        let upns = (1...33).map { "u\($0)@example.com" }
        let batches = UserNameResolver.batches(upns)
        XCTAssertEqual(batches.map(\.count), [15, 15, 3])
        XCTAssertEqual(batches.flatMap { $0 }, upns, "nothing dropped or reordered")
        XCTAssertEqual(UserNameResolver.batchSize, 15)
    }

    // MARK: - the response

    func test_parseKeysByLowercasedUPN() {
        let json: [String: Any] = ["value": [
            ["userPrincipalName": "Connor@Example.com", "displayName": "Connor Johnson"],
            ["userPrincipalName": "b@example.com", "displayName": "  "],          // blank name: skipped
            ["userPrincipalName": "c@example.com"],                               // no name: skipped
            ["displayName": "Nobody"],                                            // no UPN: skipped
        ]]
        XCTAssertEqual(UserNameResolver.parse(json), ["connor@example.com": "Connor Johnson"])
    }

    // MARK: - applying to devices

    func test_onlyDevicesMissingANameAreLookedUp() {
        let devices = [
            device("A", upn: "A@example.com"),                            // needs one
            device("B", upn: "b@example.com", displayName: "Already Set"), // Intune had it
            device("C", upn: nil),                                         // nobody to look up
            device("D", upn: "a@example.com"),                             // same user as A
        ]
        XCTAssertEqual(UserNameResolver.upnsNeedingNames(in: devices), ["a@example.com"],
                       "deduplicated, lowercased, and only where a name is actually missing")
    }

    func test_enrichFillsOnlyTheGapsAndNeverOverwritesIntune() {
        let devices = [
            device("A", upn: "a@example.com"),
            device("B", upn: "b@example.com", displayName: "From Intune"),
            device("C", upn: "c@example.com"),
        ]
        let out = UserNameResolver.enrich(devices, names: [
            "a@example.com": "Alice Looked-Up",
            "b@example.com": "Should Be Ignored",
        ])
        XCTAssertEqual(out[0].userDisplayName, "Alice Looked-Up")
        XCTAssertEqual(out[1].userDisplayName, "From Intune", "Intune's own value wins")
        XCTAssertNil(out[2].userDisplayName, "not found stays empty; the row falls back to the UPN")
        XCTAssertEqual(out[0].primaryUserLabel, "Alice Looked-Up")
    }

    func test_enrichCarriesEveryOtherFieldAcross() {
        let original = ManagedDeviceSummary(
            id: "id", entraDeviceId: "e", deviceName: "WS-1", platform: .windows,
            operatingSystemRaw: "Windows", osVersion: "10.0.26100", userPrincipalName: "a@example.com",
            emailAddress: "alias@example.com", managedDeviceName: "WS-1_Windows", serialNumber: "SN",
            model: "Latitude", manufacturer: "Dell", complianceState: "compliant", lastSyncDateTime: Date(timeIntervalSince1970: 1))
        let enriched = original.withUserDisplayName("Alice")
        XCTAssertEqual(enriched.userDisplayName, "Alice")
        XCTAssertEqual(enriched.id, original.id)
        XCTAssertEqual(enriched.entraDeviceId, original.entraDeviceId)
        XCTAssertEqual(enriched.serialNumber, original.serialNumber)
        XCTAssertEqual(enriched.emailAddress, original.emailAddress)
        XCTAssertEqual(enriched.lastSyncDateTime, original.lastSyncDateTime)
        XCTAssertEqual(enriched.complianceState, original.complianceState)
    }

    func test_enrichWithNoNamesReturnsTheSameDevices() {
        let devices = [device("A", upn: "a@example.com")]
        XCTAssertEqual(UserNameResolver.enrich(devices, names: [:]), devices)
    }

    func test_aLookedUpNameBecomesSearchable() {
        // The point of the field is search first, display second. A name Intune did not
        // supply but Entra did must match the same way.
        let devices = UserNameResolver.enrich(
            [device("WS-1", upn: "a@example.com")], names: ["a@example.com": "Alice Márquez"])
        XCTAssertEqual(DeviceSearch.filter(devices, query: "marquez").count, 1)
    }

    func test_primaryUserLabelPrefersTheNameThenTheUPNThenTheMail() {
        // Pinned because BOTH the device row and the detail screen's "Primary user" field
        // read this one property. They disagreed once — the detail screen read
        // userPrincipalName directly and kept showing an address after the row had a name.
        let named = ManagedDeviceSummary(
            id: "1", entraDeviceId: "e", deviceName: "WS-1", platform: .windows,
            userPrincipalName: "a@example.com", userDisplayName: "Alice", emailAddress: "alias@example.com")
        XCTAssertEqual(named.primaryUserLabel, "Alice")

        let upnOnly = ManagedDeviceSummary(
            id: "2", entraDeviceId: "e", deviceName: "WS-2", platform: .windows,
            userPrincipalName: "b@example.com", emailAddress: "alias@example.com")
        XCTAssertEqual(upnOnly.primaryUserLabel, "b@example.com")

        let mailOnly = ManagedDeviceSummary(
            id: "3", entraDeviceId: "e", deviceName: "WS-3", platform: .windows,
            emailAddress: "alias@example.com")
        XCTAssertEqual(mailOnly.primaryUserLabel, "alias@example.com")

        let nobody = ManagedDeviceSummary(
            id: "4", entraDeviceId: "e", deviceName: "WS-4", platform: .windows)
        XCTAssertNil(nobody.primaryUserLabel, "shared and kiosk devices have no primary user")
    }

    func test_theScopeIsTheLeastThatResolvesAName() {
        // Pinned: a change here is a consent-screen change for every customer who opts in.
        XCTAssertEqual(UserNameResolver.scope, "User.ReadBasic.All")
    }
}
