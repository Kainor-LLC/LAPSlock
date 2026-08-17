import XCTest
import AuthKit
@testable import CredentialKit

final class BitLockerKeyInfoTests: XCTestCase {

    // MARK: - parsing

    func test_parsesGraphEntry() {
        let entry: [String: Any] = [
            "id": "b465e4e8-e4e8-b465-e8e4-65b4e8e465b4",
            "volumeType": "operatingSystemVolume",
            "createdDateTime": "2026-08-01T12:00:00Z",
            "deviceId": "entra-1"
        ]
        let info = BitLockerKeyInfo(graphEntry: entry)
        XCTAssertNotNil(info)
        XCTAssertEqual(info?.volumeType, .operatingSystemVolume)
        XCTAssertEqual(info?.deviceId, "entra-1")
        XCTAssertNotNil(info?.createdDateTime)
    }

    func test_rejectsEntryWithoutId() {
        XCTAssertNil(BitLockerKeyInfo(graphEntry: ["volumeType": "fixedDataVolume"]))
        XCTAssertNil(BitLockerKeyInfo(graphEntry: ["id": ""]))
    }

    func test_volumeTypeMappingIsCaseInsensitive() {
        XCTAssertEqual(BitLockerVolumeType(graphValue: "operatingSystemVolume"), .operatingSystemVolume)
        XCTAssertEqual(BitLockerVolumeType(graphValue: "OPERATINGSYSTEMVOLUME"), .operatingSystemVolume)
        XCTAssertEqual(BitLockerVolumeType(graphValue: "fixedDataVolume"), .fixedDataVolume)
        XCTAssertEqual(BitLockerVolumeType(graphValue: "removableDataVolume"), .removableDataVolume)
    }

    func test_unknownVolumeTypeDegradesGracefully() {
        // Microsoft could add a volume type. An unknown value must not break the screen.
        XCTAssertEqual(BitLockerVolumeType(graphValue: "somethingNew"), .unknown)
        XCTAssertEqual(BitLockerVolumeType(graphValue: nil), .unknown)
        XCTAssertFalse(BitLockerVolumeType.unknown.displayName.isEmpty)
    }

    func test_volumeDisplayNamesAreAdminReadable() {
        XCTAssertEqual(BitLockerVolumeType.operatingSystemVolume.displayName, "Operating system drive")
        XCTAssertEqual(BitLockerVolumeType.fixedDataVolume.displayName, "Fixed data drive")
    }

    /// BitLocker's own recovery screen shows a key identifier, so a prefix lets an admin
    /// match the prompt in front of them to the right key.
    func test_shortIdentifierIsUppercasePrefix() {
        let info = BitLockerKeyInfo(
            id: "b465e4e8-e4e8-b465-e8e4-65b4e8e465b4",
            volumeType: .operatingSystemVolume,
            createdDateTime: nil,
            deviceId: nil
        )
        XCTAssertEqual(info.shortIdentifier, "B465E4E8")
        XCTAssertEqual(info.shortIdentifier.count, 8)
    }
}

final class BitLockerServiceTests: XCTestCase {

    func test_scopesAreSplitByPrivilege() {
        let s = BitLockerService(auth: FakeAuth())
        XCTAssertEqual(s.listScopes, ["BitLockerKey.ReadBasic.All"])
        XCTAssertEqual(s.revealScopes, ["BitLockerKey.Read.All"])
        XCTAssertNotEqual(s.listScopes, s.revealScopes,
                          "Listing keys must not require the scope that returns key values.")
    }

    func test_signInBaselineExcludesKeyRetrievalScopes() {
        // The first consent screen a customer sees must not ask to read every password
        // and disk encryption key in the tenant.
        let baseline = LapsCredentialScopes.signInBaseline
        XCTAssertFalse(baseline.contains(LapsCredentialScopes.reveal))
        XCTAssertFalse(baseline.contains(LapsCredentialScopes.bitLockerKeys))
        XCTAssertTrue(baseline.contains(LapsCredentialScopes.bitLockerKeysBasic))
    }

    func test_listRequiresEntraDeviceId() async {
        let s = BitLockerService(auth: FakeAuth())
        do {
            _ = try await s.keys(forEntraDeviceId: "")
            XCTFail("expected missingIdentifier")
        } catch let error as CredentialError {
            guard case .missingIdentifier(let detail) = error else {
                return XCTFail("expected missingIdentifier, got \(error)")
            }
            XCTAssertTrue(detail.contains("Entra"), "The message must explain why, not just fail.")
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }
}

final class DemoBitLockerServiceTests: XCTestCase {

    private let demo = DemoBitLockerService(latency: .milliseconds(1))

    func test_returnsMultipleVolumesSortedOSFirst() async throws {
        let keys = try await demo.keys(forEntraDeviceId: "entra-1")
        XCTAssertGreaterThan(keys.count, 1, "A realistic device has more than one key.")
        XCTAssertEqual(keys.first?.volumeType, .operatingSystemVolume,
                       "An admin at a recovery prompt is almost always on the OS drive.")
    }

    func test_demoRequiresEntraDeviceIdLikeProduction() async {
        // Demo must fail the same way production does, or it teaches the wrong behavior.
        do {
            _ = try await demo.keys(forEntraDeviceId: "")
            XCTFail("expected missingIdentifier")
        } catch let error as CredentialError {
            guard case .missingIdentifier = error else {
                return XCTFail("expected missingIdentifier, got \(error)")
            }
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func test_demoKeyMatchesRealBitLockerShapeButIsObviouslyFake() async throws {
        let keys = try await demo.keys(forEntraDeviceId: "entra-1")
        let revealed = try await demo.reveal(keyId: keys[0].id, info: keys[0])

        revealed.secret.withValue { value in
            // Real keys: eight hyphen-separated groups of six digits.
            let groups = value.split(separator: "-")
            XCTAssertEqual(groups.count, 8, "Shape must match a real key so layout is tested honestly.")
            for group in groups {
                XCTAssertEqual(group.count, 6)
                XCTAssertTrue(group.allSatisfy(\.isNumber))
                // Every group is a repeated digit — no real key looks like this.
                XCTAssertEqual(Set(group).count, 1,
                               "Demo keys must be unmistakable at a glance.")
            }
        }
    }

    func test_demoRevealIsDeterministicPerKey() async throws {
        let keys = try await demo.keys(forEntraDeviceId: "entra-1")
        let first = try await demo.reveal(keyId: keys[0].id, info: keys[0])
        let again = try await demo.reveal(keyId: keys[0].id, info: keys[0])

        var a = ""; var b = ""
        first.secret.withValue { a = $0 }
        again.secret.withValue { b = $0 }
        XCTAssertEqual(a, b, "Same key should show the same value across reveals.")
    }

    func test_demoDifferentKeysDifferentValues() async throws {
        let keys = try await demo.keys(forEntraDeviceId: "entra-1")
        var a = ""; var b = ""
        try await demo.reveal(keyId: keys[0].id, info: keys[0]).secret.withValue { a = $0 }
        try await demo.reveal(keyId: keys[1].id, info: keys[1]).secret.withValue { b = $0 }
        XCTAssertNotEqual(a, b)
    }
}

// MARK: - test double

private struct FakeAuth: AuthManaging {
    var currentAccount: AdminAccount? {
        get async { AdminAccount(id: "acct", tenantId: "tenant-1", username: "admin@example.com") }
    }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String { "fake-token" }
    func signIn() async throws -> AdminAccount {
        AdminAccount(id: "acct", tenantId: "tenant-1", username: "admin@example.com")
    }
    func signOut(account: AdminAccount) async throws {}
}
