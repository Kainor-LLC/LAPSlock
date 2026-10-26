import XCTest
import AuthKit
import ActionGateKit
@testable import DeviceActionsKit

final class DeviceActionsTests: XCTestCase {

    private let windows = DeviceActionTarget(managedDeviceId: "dev-1", deviceName: "LT-FIELD-207", platform: .windows, ownerType: "company")
    private let iPhone = DeviceActionTarget(managedDeviceId: "dev-2", deviceName: "iPhone (Field 12)", platform: .iOS, ownerType: "company")
    private let personalPhone = DeviceActionTarget(managedDeviceId: "dev-3", deviceName: "Personal", platform: .android, ownerType: "personal")
    private let unmanaged = DeviceActionTarget(managedDeviceId: "", deviceName: "GHOST", platform: .windows)

    func test_scopesAndVersionsMatchTheReference() {
        XCTAssertEqual(DeviceActionKind.sync.scope, "DeviceManagementManagedDevices.PrivilegedOperations.All")
        XCTAssertEqual(DeviceActionKind.restart.scope, "DeviceManagementManagedDevices.PrivilegedOperations.All")
        XCTAssertEqual(DeviceActionKind.remoteLock.scope, "DeviceManagementManagedDevices.PrivilegedOperations.All")
        XCTAssertEqual(DeviceActionKind.locate.scope, "DeviceManagementManagedDevices.ReadWrite.All")
        XCTAssertEqual(DeviceActionKind.rotateBitLockerKeys.scope, "DeviceManagementManagedDevices.ReadWrite.All")
        XCTAssertEqual(DeviceActionKind.rotateBitLockerKeys.version, .beta)
        for kind in DeviceActionKind.allCases where kind != .rotateBitLockerKeys {
            XCTAssertEqual(kind.version, .v1_0, kind.rawValue)
        }
        XCTAssertEqual(DeviceActionScopes.module, ["DeviceManagementManagedDevices.PrivilegedOperations.All", "DeviceManagementManagedDevices.ReadWrite.All"])
    }

    func test_theWriteIsAPostToTheDocumentedPathWithTheIdHiddenFromTheTemplate() {
        let action = DeviceActionKind.restart.action(for: windows)
        XCTAssertEqual(action.request.method, .post)
        XCTAssertEqual(action.request.path, "/deviceManagement/managedDevices/dev-1/rebootNow")
        XCTAssertEqual(action.request.template, "/deviceManagement/managedDevices/{id}/rebootNow")
        XCTAssertEqual(action.request.scopes, ["DeviceManagementManagedDevices.PrivilegedOperations.All"])
        XCTAssertEqual(action.tier, .confirm)
        XCTAssertEqual(action.target.label, "LT-FIELD-207")
        XCTAssertEqual(action.requiredRoleTemplateIds, DeviceActionRoles.known)
        XCTAssertEqual(DeviceActionKind.sync.action(for: windows).tier, .none)
        XCTAssertEqual(DeviceActionKind.rotateBitLockerKeys.action(for: windows).request.version, .beta)
    }

    func test_availabilityRules() {
        for kind in DeviceActionKind.allCases {
            XCTAssertEqual(kind.unavailableReason(for: unmanaged), "Not managed by Intune.", kind.rawValue)
        }
        XCTAssertNil(DeviceActionKind.sync.unavailableReason(for: windows))
        XCTAssertNil(DeviceActionKind.rotateBitLockerKeys.unavailableReason(for: windows))
        XCTAssertNotNil(DeviceActionKind.rotateBitLockerKeys.unavailableReason(for: iPhone))
        XCTAssertNotNil(DeviceActionKind.locate.unavailableReason(for: windows))
        XCTAssertNil(DeviceActionKind.locate.unavailableReason(for: iPhone))
        XCTAssertEqual(DeviceActionKind.locate.unavailableReason(for: personalPhone), "Locate works on corporate-owned devices only.")
        var unknownOwner = iPhone
        unknownOwner.ownerType = nil
        XCTAssertNil(DeviceActionKind.locate.unavailableReason(for: unknownOwner), "unknown ownership is not a refusal; Graph decides")
    }

    func test_everySuccessCopySaysRequested() {
        for kind in DeviceActionKind.allCases {
            XCTAssertTrue(kind.successCopy.lowercased().contains("requested"), kind.rawValue)
            XCTAssertFalse(kind.successCopy.contains("\u{2014}"))
        }
    }

    func test_recordDecodesAndFindsPendingActions() throws {
        let json = ##"{"id":"dev-1","managedDeviceOwnerType":"company","deviceEnrollmentType":"windowsAzureADJoin","managementAgent":"mdm","enrollmentProfileName":"Autopilot Standard","complianceState":"compliant","lastSyncDateTime":"2026-10-25T10:00:00Z","deviceActionResults":[{"actionName":"rebootNow","actionState":"pending","startDateTime":"2026-10-25T09:50:00Z","lastUpdatedDateTime":"2026-10-25T09:50:00Z"},{"actionName":"syncDevice","actionState":"done","startDateTime":"2026-10-24T09:50:00Z","lastUpdatedDateTime":"2026-10-24T09:51:00Z"}]}"##
        let record = try GraphClient.decoder.decode(DeviceRecord.self, from: Data(json.utf8))
        XCTAssertEqual(record.managedDeviceOwnerType, "company")
        XCTAssertEqual(record.pendingActions.map(\.title), ["Restart"])
        XCTAssertEqual(DeviceRecord.words("windowsAzureADJoin"), "Entra joined")
        XCTAssertEqual(DeviceRecord.words("appleBulkWithUser"), "Apple automated enrollment, with user")
        XCTAssertEqual(DeviceRecord.words("mdm"), "Intune MDM")
        XCTAssertEqual(DeviceRecord.words("somethingNewTomorrow"), "Something new tomorrow")
        XCTAssertNil(DeviceRecord.words("unknown"))
        XCTAssertNil(DeviceRecord.words(nil))
        let bare = try GraphClient.decoder.decode(DeviceRecord.self, from: Data(##"{"id":"x"}"##.utf8))
        XCTAssertTrue(bare.deviceActionResults.isEmpty)
    }

    func test_demoRunsLogsAndRefusesWhatDoesNotApply() async throws {
        let demo = DemoDeviceActionsProvider(latency: .milliseconds(1))
        let outcome = await demo.run(.restart, on: windows)
        XCTAssertTrue(outcome.isRequested)
        let last = await demo.lastLogEntry(managedDeviceId: "dev-1")
        XCTAssertEqual(last?.actionTitle, "Restart")
        XCTAssertEqual(last?.outcome, "requested")
        let refused = await demo.run(.locate, on: windows)
        XCTAssertEqual(refused, .failed(.refused(reason: "Locate works on iOS and Android devices.")))
        let record = try await demo.record(managedDeviceId: "demo-w-003")
        XCTAssertEqual(record.pendingActions.count, 1)
        let none = await demo.lastLogEntry(managedDeviceId: "nothing")
        XCTAssertNil(none)
    }
}
