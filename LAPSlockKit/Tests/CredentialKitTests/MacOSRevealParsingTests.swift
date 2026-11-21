import XCTest
@testable import CredentialKit

/// Parsing retrieveMacOSManagedDeviceLocalAdminAccountDetail's answer.
///
/// The shape is from Microsoft's beta page, not yet from a real Mac, so the parser accepts
/// the documented `value` wrapper and a bare object, and refuses anything without a password
/// rather than showing an empty field.
final class MacOSRevealParsingTests: XCTestCase {

    private func read(_ value: SensitiveValue) -> String {
        var out = ""
        value.withValue { out = $0 }
        return out
    }

    func test_theDocumentedShape() throws {
        let body: [String: Any] = ["value": [
            "@odata.type": "microsoft.graph.macOSManagedDeviceLocalAdminAccountDetail",
            "adminAccountPassword": "Kx7-pQ2v-Lm9Rt4",
            "passwordLastRotatedDateTime": "2026-11-01T09:30:00Z",
        ]]
        let credential = try MacOSLapsProvider.credential(from: body)
        XCTAssertEqual(read(credential.secret), "Kx7-pQ2v-Lm9Rt4")
        XCTAssertEqual(credential.backupDateTime, ISO8601DateFormatter().date(from: "2026-11-01T09:30:00Z"))
        XCTAssertNil(credential.accountName, "The function returns no account name; never guess one.")
        XCTAssertTrue(credential.previousVersions.isEmpty, "Intune keeps one value for a Mac.")
        credential.secret.wipe()
        XCTAssertTrue(credential.secret.isWiped)
    }

    func test_aBareObjectIsReadToo() throws {
        let credential = try MacOSLapsProvider.credential(from: ["adminAccountPassword": "abc", "passwordLastRotatedDateTime": "2026-11-01T09:30:00.2371449Z"])
        XCTAssertEqual(read(credential.secret), "abc")
        XCTAssertNotNil(credential.backupDateTime, "Fractional seconds, as the example on Microsoft's page has.")
    }

    func test_aMissingDateLeavesTheDateEmpty() throws {
        let credential = try MacOSLapsProvider.credential(from: ["value": ["adminAccountPassword": "abc"]])
        XCTAssertNil(credential.backupDateTime)
    }

    func test_noPasswordIsAnEmptyCredentialSet() {
        for body: [String: Any] in [
            ["value": ["passwordLastRotatedDateTime": "2026-11-01T09:30:00Z"]],
            ["value": ["adminAccountPassword": ""]],
            ["value": ["adminAccountPassword": NSNull()]],
            [:],
        ] {
            XCTAssertThrowsError(try MacOSLapsProvider.credential(from: body)) { error in
                XCTAssertEqual(error as? CredentialError, .emptyCredentialSet)
            }
        }
    }

    func test_aPasswordWithNonASCIICharactersSurvives() throws {
        let credential = try MacOSLapsProvider.credential(from: ["value": ["adminAccountPassword": "ä£€-Zz9"]])
        XCTAssertEqual(read(credential.secret), "ä£€-Zz9")
    }
}

final class DemoMacRevealTests: XCTestCase {
    func test_offByDefault() {
        XCTAssertFalse(DemoLapsProvider(platform: .macOS).capabilities.supportsReveal)
    }

    func test_onRevealsAnObviouslyFakeValue_withNoHistory() async throws {
        let p = DemoLapsProvider(platform: .macOS, latency: .milliseconds(1), macOSRevealEnabled: true)
        XCTAssertTrue(p.capabilities.supportsReveal)
        let credential = try await p.reveal(for: DeviceCredentialTarget(platform: .macOS, entraDeviceId: nil, managedDeviceId: "m1"))
        var value = ""
        credential.secret.withValue { value = $0 }
        XCTAssertTrue(value.hasPrefix("DEMO-"), "Demo values must be obviously fake.")
        XCTAssertTrue(credential.previousVersions.isEmpty)
        XCTAssertNil(credential.accountName)
    }
}
