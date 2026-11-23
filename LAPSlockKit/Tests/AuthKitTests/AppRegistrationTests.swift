import XCTest
import Foundation
@testable import AuthKit

/// The split into a read registration and several write registrations is only worth
/// anything if it cannot quietly erode. These tests are what make "the read sign-in
/// cannot write" a checked fact instead of a sentence in a document.
final class AppRegistrationTests: XCTestCase {

    // MARK: - the registrations

    func testEveryRegistrationHasItsOwnClientId() {
        let ids = AppRegistration.allCases.map(\.clientId)
        XCTAssertEqual(Set(ids).count, ids.count)
        for id in ids { XCTAssertNotNil(UUID(uuidString: id), id + " is not a client ID") }
    }

    /// The whole point. Every scope on the read registration has to look like a read, and
    /// the list has to match the one written out here, so adding to it means editing a test
    /// whose name says what is at stake.
    func testTheReadRegistrationHoldsNoPermissionThatWrites() throws {
        let read = try NSRegularExpression(pattern: #"^[A-Za-z]+\.Read(Basic)?\.(All|Directory|AzureADGroup)$"#)
        for scope in AppRegistration.read.scopes {
            let range = NSRange(scope.startIndex..., in: scope)
            XCTAssertNotNil(read.firstMatch(in: scope, range: range), scope + " does not look like a read-only permission")
        }
        XCTAssertEqual(Set(AppRegistration.read.scopes), [
            "DeviceManagementManagedDevices.Read.All", "Device.Read.All",
            "DeviceLocalCredential.ReadBasic.All", "DeviceLocalCredential.Read.All",
            "BitLockerKey.ReadBasic.All", "BitLockerKey.Read.All",
            "User.ReadBasic.All", "User.Read.All", "IdentityRiskyUser.Read.All",
            "AuditLog.Read.All", "Policy.Read.All", "Directory.Read.All",
            "ServiceHealth.Read.All", "ServiceMessage.Read.All", "Application.Read.All",
            "DeviceManagementServiceConfig.Read.All", "SecurityEvents.Read.All",
            "SecurityIncident.Read.All", "ThreatHunting.Read.All",
            "RoleAssignmentSchedule.Read.Directory", "RoleEligibilitySchedule.Read.Directory",
            "RoleManagementPolicy.Read.Directory", "PrivilegedAssignmentSchedule.Read.AzureADGroup",
            "PrivilegedEligibilitySchedule.Read.AzureADGroup", "RoleManagementPolicy.Read.AzureADGroup"
        ])
    }

    func testOnlyTheReadRegistrationIsReadOnly() {
        XCTAssertEqual(AppRegistration.allCases.filter(\.isReadOnly), [.read])
    }

    /// A write permission in two registrations would mean two ways to do one thing, and no
    /// single switch that turns it off.
    func testNoWritePermissionIsHeldTwice() {
        var seen: [String: AppRegistration] = [:]
        for registration in AppRegistration.allCases where !registration.isReadOnly {
            for scope in registration.scopes where !AppRegistration.read.scopes.contains(scope) {
                XCTAssertNil(seen[scope], scope + " is in two registrations")
                seen[scope] = registration
            }
        }
    }

    // MARK: - routing

    func testReadsGoToTheReadRegistration() throws {
        XCTAssertEqual(try ScopeRouter.registration(for: ["DeviceManagementManagedDevices.Read.All", "Device.Read.All", "DeviceLocalCredential.ReadBasic.All"]), .read)
        XCTAssertEqual(try ScopeRouter.registration(for: ["DeviceLocalCredential.Read.All"]), .read)
        XCTAssertEqual(try ScopeRouter.registration(for: ["AuditLog.Read.All", "Policy.Read.All", "User.ReadBasic.All"]), .read)
        XCTAssertEqual(try ScopeRouter.registration(for: ["RoleAssignmentSchedule.Read.Directory"]), .read)
    }

    func testEachWriteGoesToItsOwnRegistration() throws {
        XCTAssertEqual(try ScopeRouter.registration(for: ["RoleAssignmentSchedule.ReadWrite.Directory"]), .roleActivation)
        XCTAssertEqual(try ScopeRouter.registration(for: ["PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup"]), .roleActivation)
        XCTAssertEqual(try ScopeRouter.registration(for: ["DeviceManagementManagedDevices.PrivilegedOperations.All", "DeviceManagementManagedDevices.ReadWrite.All"]), .deviceActions)
        XCTAssertEqual(try ScopeRouter.registration(for: ["User.RevokeSessions.All"]), .userActions)
        XCTAssertEqual(try ScopeRouter.registration(for: ["IdentityRiskyUser.ReadWrite.All"]), .userActions)
        XCTAssertEqual(try ScopeRouter.registration(for: ["UserAuthenticationMethod.ReadWrite.All"]), .accountRecovery)
        XCTAssertEqual(try ScopeRouter.registration(for: ["UserAuthMethod-TAP.ReadWrite.All"]), .accountRecovery)
        XCTAssertEqual(try ScopeRouter.registration(for: ["GroupMember.ReadWrite.All"]), .groupMembership)
    }

    /// Microsoft accepts only the remote-actions permission for a Mac's admin password, so
    /// that read cannot go through the read registration.
    func testReadingAMacPasswordGoesThroughDeviceActions() throws {
        XCTAssertEqual(try ScopeRouter.registration(for: ["DeviceManagementManagedDevices.PrivilegedOperations.All"]), .deviceActions)
    }

    /// The one read a write registration also holds: Graph wants it on the same token as
    /// the permission to block sign-in. Alone, it is still a read.
    func testTheCompanionReadFollowsItsWriteAndIsOtherwiseARead() throws {
        XCTAssertEqual(try ScopeRouter.registration(for: ["User.EnableDisableAccount.All", "User.Read.All"]), .userActions)
        XCTAssertEqual(try ScopeRouter.registration(for: ["User.Read.All"]), .read)
    }

    func testAMixedRequestIsRefused() {
        let mixed = ["GroupMember.ReadWrite.All", "Directory.Read.All"]
        XCTAssertThrowsError(try ScopeRouter.registration(for: mixed)) {
            XCTAssertEqual($0 as? ScopeRouter.RoutingError, .mixedRegistrations(mixed))
        }
        let twoWrites = ["User.RevokeSessions.All", "UserAuthMethod-TAP.ReadWrite.All"]
        XCTAssertThrowsError(try ScopeRouter.registration(for: twoWrites)) {
            XCTAssertEqual($0 as? ScopeRouter.RoutingError, .mixedRegistrations(twoWrites))
        }
    }

    func testAnUnknownPermissionIsRefused() {
        XCTAssertThrowsError(try ScopeRouter.registration(for: ["Mail.Send"])) {
            XCTAssertEqual($0 as? ScopeRouter.RoutingError, .unknownScope("Mail.Send"))
        }
        // Not falling back to the read registration matters most for a write nobody listed.
        XCTAssertThrowsError(try ScopeRouter.registration(for: ["Directory.ReadWrite.All"]))
    }

    /// Microsoft returns `BitlockerKey` where its reference says `BitLockerKey`, and a
    /// scope may carry the Graph resource in front.
    func testSpellingAndTheResourcePrefixDoNotMatter() throws {
        XCTAssertEqual(try ScopeRouter.registration(for: ["BitlockerKey.Read.All"]), .read)
        XCTAssertEqual(try ScopeRouter.registration(for: ["https://graph.microsoft.com/Device.Read.All"]), .read)
        XCTAssertEqual(try ScopeRouter.registration(for: ["groupmember.readwrite.all"]), .groupMembership)
    }

    func testSignInProtocolScopesAreSetAside() throws {
        XCTAssertEqual(try ScopeRouter.registration(for: ["openid", "profile", "offline_access", "Device.Read.All"]), .read)
        XCTAssertThrowsError(try ScopeRouter.registration(for: ["openid", "profile"])) {
            XCTAssertEqual($0 as? ScopeRouter.RoutingError, .noScopes)
        }
        XCTAssertThrowsError(try ScopeRouter.registration(for: [])) {
            XCTAssertEqual($0 as? ScopeRouter.RoutingError, .noScopes)
        }
    }

    /// A registration's own API scope, which is how a phone registers for Instant alerts.
    func testARegistrationsOwnScopeBelongsToIt() throws {
        let read = "api://" + AppRegistration.read.clientId + "/Alerts.Register"
        XCTAssertEqual(try ScopeRouter.registration(for: [read]), .read)
        let before = "api://" + AppRegistration.roleActivation.clientId.uppercased() + "/Alerts.Register"
        XCTAssertEqual(try ScopeRouter.registration(for: [before]), .roleActivation)
        XCTAssertThrowsError(try ScopeRouter.registration(for: ["api://00000000-0000-0000-0000-000000000000/Anything"]))
        XCTAssertThrowsError(try ScopeRouter.registration(for: [read, "Device.Read.All"]))
    }

    // MARK: - the published list and the source tree

    private var repositoryRoot: URL {
        // Tests/AuthKitTests/this file -> LAPSlockKit -> the repository
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    /// docs/app-registrations.json is what the approval page and TenantKeep Posture read.
    func testThePublishedListMatchesTheCode() throws {
        let url = repositoryRoot.appendingPathComponent("docs/app-registrations.json")
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        let published = try XCTUnwrap(json?["registrations"] as? [[String: Any]])
        XCTAssertEqual(published.compactMap { $0["key"] as? String }, AppRegistration.allCases.map(\.rawValue))
        for entry in published {
            let key = try XCTUnwrap(entry["key"] as? String)
            let registration = try XCTUnwrap(AppRegistration(rawValue: key), key)
            XCTAssertEqual(entry["clientId"] as? String, registration.clientId, key)
            XCTAssertEqual(entry["name"] as? String, registration.displayName, key)
            XCTAssertEqual(entry["summary"] as? String, registration.summary, key)
            XCTAssertEqual(entry["readOnly"] as? Bool, registration.isReadOnly, key)
            XCTAssertEqual(entry["scopes"] as? [String], registration.scopes, key)
        }
    }

    /// Scopes written in the source that no registration holds, each with its reason. A
    /// permission added to a module without a home in `AppRegistration` fails the test below.
    private static let notRouted: [String: String] = [
        "SecurityAlert.Read.All": "defined in SecurityKit, held in reserve, never requested",
        "User.Read": "the Mac menu bar app's session check; to be replaced by a base scope"
    ]

    func testEveryPermissionWrittenInTheSourceHasARegistration() throws {
        let scope = try NSRegularExpression(
            pattern: #""([A-Z][A-Za-z-]+\.(?:Read|ReadWrite|ReadBasic|RevokeSessions|EnableDisableAccount|PrivilegedOperations)(?:\.[A-Za-z]+)*)""#)
        var found: Set<String> = []
        var homeless: [String] = []
        for folder in ["LAPSlockKit/Sources", "App"] {
            let files = FileManager.default.enumerator(at: repositoryRoot.appendingPathComponent(folder), includingPropertiesForKeys: nil)
            while let file = files?.nextObject() as? URL {
                guard file.pathExtension == "swift" else { continue }
                let text = try String(contentsOf: file, encoding: .utf8)
                for line in text.components(separatedBy: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    if trimmed.hasPrefix("//") { continue }
                    for match in scope.matches(in: line, range: NSRange(line.startIndex..., in: line)) {
                        guard let range = Range(match.range(at: 1), in: line) else { continue }
                        let name = String(line[range])
                        found.insert(name)
                        if Self.notRouted[name] != nil { continue }
                        if (try? ScopeRouter.registration(for: [name])) == nil {
                            homeless.append(file.lastPathComponent + ": " + name)
                        }
                    }
                }
            }
        }
        XCTAssertGreaterThan(found.count, 25, "the source scan found too little; the pattern is probably broken")
        XCTAssertTrue(homeless.isEmpty, "Permissions with no registration in AppRegistration:\n" + homeless.joined(separator: "\n"))
        for name in Self.notRouted.keys {
            XCTAssertTrue(found.contains(name), name + " is no longer in the source; remove it from notRouted")
        }
    }
}
