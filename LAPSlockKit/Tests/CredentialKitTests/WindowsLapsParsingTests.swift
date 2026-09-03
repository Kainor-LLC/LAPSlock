import XCTest
@testable import CredentialKit

/// Parsing the Windows LAPS `credentials` payload.
///
/// This is the function that decides WHICH password an admin is shown, so it is tested
/// harder than its size suggests. Showing the wrong version sends somebody to a console
/// with a credential that fails — and the reason history exists at all is that a device
/// which stopped checking in is still on an older password.
final class WindowsLapsParsingTests: XCTestCase {

    private func entry(_ password: String, _ backupDateTime: String?, account: String = "LapsAdmin") -> [String: Any] {
        var e: [String: Any] = [
            "passwordBase64": Data(password.utf8).base64EncodedString(),
            "accountName": account,
        ]
        if let backupDateTime { e["backupDateTime"] = backupDateTime }
        return e
    }

    private func read(_ value: SensitiveValue) -> String {
        var out = ""
        value.withValue { out = $0 }
        return out
    }

    func test_theNewestVersionIsTheCurrentPassword() throws {
        // Deliberately out of order in the payload: Graph does not promise an ordering,
        // and the old implementation's `max` was right about this even though it discarded
        // everything else.
        let credential = try WindowsLapsProvider.credential(from: ["credentials": [
            entry("older", "2026-07-01T10:00:00Z"),
            entry("newest", "2026-09-01T10:00:00Z"),
            entry("middle", "2026-08-01T10:00:00Z"),
        ]])
        XCTAssertEqual(read(credential.secret), "newest")
        XCTAssertEqual(credential.previousVersions.map { read($0.secret) }, ["middle", "older"],
                       "history is newest-first, so the most recently retired password is on top")
    }

    func test_historyIsEmptyWhenTheTenantKeepsNone() throws {
        let credential = try WindowsLapsProvider.credential(from: ["credentials": [
            entry("only", "2026-09-01T10:00:00Z"),
        ]])
        XCTAssertEqual(read(credential.secret), "only")
        XCTAssertTrue(credential.previousVersions.isEmpty, "the picker hides itself on this")
    }

    func test_anUndatedEntryNeverWinsByAccident() throws {
        // An entry with no backupDateTime sorts LAST, not first. Treating an undated entry
        // as newest would put an unknown password in front of a known-current one.
        let credential = try WindowsLapsProvider.credential(from: ["credentials": [
            entry("undated", nil),
            entry("dated", "2026-09-01T10:00:00Z"),
        ]])
        XCTAssertEqual(read(credential.secret), "dated")
        XCTAssertEqual(credential.previousVersions.map { read($0.secret) }, ["undated"])
    }

    func test_anUnreadableEntryIsDroppedRatherThanShownBlank() throws {
        // A version an admin cannot read is worse than one they cannot see, because they
        // would try it.
        let credential = try WindowsLapsProvider.credential(from: ["credentials": [
            entry("good", "2026-09-01T10:00:00Z"),
            ["accountName": "LapsAdmin", "backupDateTime": "2026-08-01T10:00:00Z"],  // no password
            ["passwordBase64": "!!!not base64!!!", "backupDateTime": "2026-07-01T10:00:00Z"],
        ]])
        XCTAssertEqual(read(credential.secret), "good")
        XCTAssertTrue(credential.previousVersions.isEmpty)
    }

    func test_anEmptyOrMissingCollectionIsItsOwnError() {
        // emptyCredentialSet has its own user-facing message; it must not degrade into a
        // generic decode failure.
        for payload in [["credentials": [[String: Any]]()], [String: Any]()] {
            XCTAssertThrowsError(try WindowsLapsProvider.credential(from: payload)) { error in
                XCTAssertEqual(error as? CredentialError, .emptyCredentialSet)
            }
        }
    }

    func test_aCollectionOfOnlyUnreadableEntriesIsADecodeFailure() {
        // Present but unusable is a different problem from absent, and says so.
        XCTAssertThrowsError(try WindowsLapsProvider.credential(from: ["credentials": [
            ["accountName": "LapsAdmin"],
        ]])) { error in
            XCTAssertEqual(error as? CredentialError, .decodeFailure)
        }
    }

    func test_theNumberOfVersionsHeldIsCapped() throws {
        // Each version is another live secret held for the reveal window, so a pathological
        // response must not multiply that without bound. Newest-first ordering means the
        // cap drops the least useful end.
        let many = (1...40).map { i in
            entry("pw-\(i)", String(format: "2026-01-%02dT10:00:00Z", i % 28 + 1))
        }
        let credential = try WindowsLapsProvider.credential(from: ["credentials": many])
        XCTAssertEqual(credential.previousVersions.count, WindowsLapsProvider.maxVersions - 1)
        XCTAssertEqual(WindowsLapsProvider.maxVersions, 10)
    }

    func test_theAccountNameTravelsWithEachVersion() throws {
        // LAPS policy can change the managed account, so an old password may belong to a
        // different account than the current one. Showing the current name beside an old
        // password would be wrong in exactly the case history exists for.
        let credential = try WindowsLapsProvider.credential(from: ["credentials": [
            entry("new", "2026-09-01T10:00:00Z", account: "LapsAdmin"),
            entry("old", "2026-07-01T10:00:00Z", account: "OldLocalAdmin"),
        ]])
        XCTAssertEqual(credential.accountName, "LapsAdmin")
        XCTAssertEqual(credential.previousVersions.first?.accountName, "OldLocalAdmin")
    }
}
