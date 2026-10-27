import Foundation
import AuthKit
import ActionGateKit
import PrivilegedAccessKit

// Device actions. Spec section 3.3: sync, restart, remote lock, locate and the two key
// rotations, whose worst outcome is a rebooted laptop, and since phase 3 retire and wipe,
// which are the destructive tier: the device name typed back, the app lock asked again,
// ten seconds to change your mind, then one send.
//
// Every action is a WriteAction run by ActionGateKit's runner. This target builds them and
// reads the device's management record; it never sends anything itself. It takes the
// device as plain values rather than importing the inventory module, so its link graph
// holds no credential code: the isolation guard forbids CredentialKit here.
//
// Every success is "requested". Intune queues the action and the device performs it at
// its next check-in, which may be a while if it is offline, and the screen must never say
// more than Microsoft has confirmed.

/// The device, as this module needs it. Built by the app from the inventory summary.
public struct DeviceActionTarget: Sendable, Equatable {
    public enum Platform: String, Sendable, Equatable {
        case windows, macOS, iOS, android, other
    }
    /// The Intune managedDeviceId. Empty when the device is not Intune managed, which
    /// disables every action.
    public let managedDeviceId: String
    public let deviceName: String
    public let platform: Platform
    /// `company`, `personal` or nil when not yet known; from the management record.
    public var ownerType: String?
    /// Whether the device has an Entra device identity, which Windows LAPS needs to back its
    /// password up to Entra ID.
    public var hasEntraIdentity: Bool

    public init(managedDeviceId: String, deviceName: String, platform: Platform, ownerType: String? = nil, hasEntraIdentity: Bool = true) {
        self.managedDeviceId = managedDeviceId
        self.deviceName = deviceName
        self.platform = platform
        self.ownerType = ownerType
        self.hasEntraIdentity = hasEntraIdentity
    }
}

/// The delegated scopes, verified on the v1.0 reference pages 2026-10-25. Microsoft splits
/// them two ways and the split is not the one the spec hoped for: sync, restart and lock
/// need the privileged-operations scope; locate and key rotation need read-write.
public enum DeviceActionScopes {
    public static let privilegedOperations = "DeviceManagementManagedDevices.PrivilegedOperations.All"
    public static let readWrite = "DeviceManagementManagedDevices.ReadWrite.All"
    /// Reading the management record; already consented at sign-in for the device list.
    public static let read = "DeviceManagementManagedDevices.Read.All"
    /// Requested together when the Settings toggle is turned on, so an organization that
    /// leaves it off never sees a write scope on a consent screen.
    public static let module = [privilegedOperations, readWrite]
}

/// Role template ids known to allow Intune device actions. Microsoft's pages do not state
/// a role per action, so the gate starts from these and a 403 covers the rest.
public enum DeviceActionRoles {
    public static let intuneAdministrator = "3a2c62db-5318-420d-8d74-23affee5d9d5"
    public static let globalAdministrator = "62e90394-69f5-4237-9190-012177145e10"
    public static let known = [intuneAdministrator, globalAdministrator]
}

public enum DeviceActionKind: String, CaseIterable, Sendable, Identifiable, Codable {
    case sync
    case restart
    case remoteLock
    case locate
    case rotateBitLockerKeys
    case rotateLocalAdminPassword
    case retire
    case wipe

    public var id: String { rawValue }

    /// The two that remove data. An organization can switch these off on their own with
    /// the managed configuration id `destructiveActions`, leaving the rest.
    public var isDestructive: Bool { self == .retire || self == .wipe }

    public var title: String {
        switch self {
        case .sync:                 return "Sync"
        case .restart:              return "Restart"
        case .remoteLock:           return "Remote lock"
        case .locate:               return "Locate"
        case .rotateBitLockerKeys:  return "Rotate BitLocker keys"
        case .rotateLocalAdminPassword: return "Rotate local admin password"
        case .retire:               return "Retire"
        case .wipe:                 return "Wipe"
        }
    }

    public var symbol: String {
        switch self {
        case .sync:                 return "arrow.triangle.2.circlepath"
        case .restart:              return "power"
        case .remoteLock:           return "lock"
        case .locate:               return "location"
        case .rotateBitLockerKeys:  return "key"
        case .rotateLocalAdminPassword: return "key.horizontal"
        case .retire:               return "rectangle.portrait.and.arrow.right"
        case .wipe:                 return "trash"
        }
    }

    /// Spec section 4: sync fires on the tap; the rest confirm.
    public var tier: ActionTier {
        switch self {
        case .sync:           return .none
        case .retire, .wipe:  return .destructive
        default:              return .confirm
        }
    }

    public var actionId: String { "device." + rawValue }

    var pathSegment: String {
        switch self {
        case .sync:                 return "syncDevice"
        case .restart:              return "rebootNow"
        case .remoteLock:           return "remoteLock"
        case .locate:               return "locateDevice"
        case .rotateBitLockerKeys:  return "rotateBitLockerKeys"
        case .rotateLocalAdminPassword: return "rotateLocalAdminPassword"
        case .retire:               return "retire"
        case .wipe:                 return "wipe"
        }
    }

    /// Both rotations are still beta on the reference; the others are v1.0.
    public var version: GraphAPIVersion {
        switch self {
        case .rotateBitLockerKeys, .rotateLocalAdminPassword: return .beta
        default: return .v1_0
        }
    }

    /// The local admin password rotation is on the privileged-operations scope, verified on
    /// the beta reference 2026-10-26 (1.0 sent it on read-write).
    public var scope: String {
        switch self {
        case .sync, .restart, .remoteLock, .retire, .wipe, .rotateLocalAdminPassword: return DeviceActionScopes.privilegedOperations
        case .locate, .rotateBitLockerKeys: return DeviceActionScopes.readWrite
        }
    }

    /// What the sheet asks before the call.
    public var confirmation: String {
        switch self {
        case .sync:                 return ""
        case .restart:              return "Restart this device now? Anyone using it loses unsaved work."
        case .remoteLock:           return "Lock this device? The person will need their passcode to get back in."
        case .locate:               return "Ask the device for its location? The person is notified on the device."
        case .rotateBitLockerKeys:  return "Rotate the BitLocker recovery keys? The old keys stop working once the device checks in."
        case .rotateLocalAdminPassword: return "Rotate the local administrator password now? The current password stops working once the device checks in, and the new one appears here after the device backs it up."
        case .retire:               return "Retire removes your organization's data, apps and settings from the device and stops managing it. The person's own data stays."
        case .wipe:                 return "Wipe restores the device to factory settings and erases everything on it, your organization's data and the person's. It cannot be undone once the device receives it."
        }
    }

    public var successCopy: String {
        switch self {
        case .sync:                 return "Sync requested. The device checks in with Intune when it is next online."
        case .restart:              return "Restart requested. Intune runs it at the device's next check-in."
        case .remoteLock:           return "Lock requested. It applies at the device's next check-in."
        case .locate:               return "Location requested. It appears on the device's page in the Intune admin center once the device answers."
        case .rotateBitLockerKeys:  return "Rotation requested. The device generates a new key at its next check-in, then the new key appears above."
        case .rotateLocalAdminPassword: return "Rotation requested. Intune sets a new password at the device's next check-in; reveal again after it backs up to see it."
        case .retire:               return "Retire requested. Intune removes your organization's data at the device's next check-in."
        case .wipe:                 return "Wipe requested. The device erases itself at its next check-in."
        }
    }

    /// Why this action is not offered for this device, or nil when it is.
    public func unavailableReason(for target: DeviceActionTarget) -> String? {
        if target.managedDeviceId.isEmpty { return "Not managed by Intune." }
        switch self {
        case .locate:
            guard target.platform == .iOS || target.platform == .android else { return "Locate works on iOS and Android devices." }
            if let owner = target.ownerType, owner.lowercased() != "company" { return "Locate works on corporate-owned devices only." }
            return nil
        case .rotateBitLockerKeys:
            return target.platform == .windows ? nil : "BitLocker is a Windows feature."
        case .retire:
            return nil
        case .wipe:
            // Spec section 4: wipe is replaced by retire on personal devices. Unknown
            // ownership is a refusal here, unlike locate: the cost of guessing is the
            // person's own data.
            guard let owner = target.ownerType?.lowercased() else { return "Waiting for the management record to say who owns this device." }
            guard owner == "company" else { return "A personal device can be retired, not wiped." }
            // (verify) A Mac wipe can need a six-digit recovery PIN the app does not collect.
            if target.platform == .macOS { return "Wipe a Mac from the Intune admin center; it can need a recovery PIN." }
            return nil
        case .rotateLocalAdminPassword:
            // Intune's action, verified 2026-10-26: Windows, corporate-owned, Entra or hybrid
            // joined with Windows LAPS backing up to Entra ID; macOS enrolled through
            // Automated Device Enrollment. Unknown ownership is left to Intune: this changes
            // a password, not anyone's data.
            switch target.platform {
            case .windows:
                if let owner = target.ownerType?.lowercased(), owner != "company" { return "Intune rotates the password on corporate-owned devices only." }
                if !target.hasEntraIdentity { return "Needs an Entra joined device with Windows LAPS backing up to Entra ID." }
                return nil
            case .macOS:
                return nil
            default:
                return "Local admin password rotation is for Windows and Mac."
            }
        default:
            return nil
        }
    }

    /// The wipe body: Microsoft's defaults, said out loud. Enrollment and user data are not
    /// kept; the eSIM plan is left to Microsoft's default by not sending it.
    static let wipeBody: Data = {
        (try? JSONSerialization.data(withJSONObject: ["keepEnrollmentData": false, "keepUserData": false], options: [.sortedKeys])) ?? Data("{}".utf8)
    }()

    /// The write, as data, for the runner.
    public func action(for target: DeviceActionTarget) -> WriteAction {
        WriteAction(
            id: actionId,
            title: title,
            tier: tier,
            target: ActionTarget(label: target.deviceName, id: target.managedDeviceId),
            request: GraphRequest(
                method: .post,
                version: version,
                path: "/deviceManagement/managedDevices/" + target.managedDeviceId + "/" + pathSegment,
                template: "/deviceManagement/managedDevices/{id}/" + pathSegment,
                body: self == .wipe ? Self.wipeBody : nil,
                scopes: [scope]),
            requiredRoleTemplateIds: DeviceActionRoles.known,
            successCopy: successCopy)
    }
}

/// The management record, the fields the device list does not carry.
public struct DeviceRecord: Decodable, Sendable, Equatable {
    public struct ActionResult: Decodable, Sendable, Equatable, Identifiable {
        public let actionName: String?
        public let actionState: String?
        public let startDateTime: Date?
        public let lastUpdatedDateTime: Date?
        public var id: String { (actionName ?? "") + "|" + (startDateTime.map { String($0.timeIntervalSince1970) } ?? "") }
        public init(actionName: String?, actionState: String?, startDateTime: Date?, lastUpdatedDateTime: Date?) {
            self.actionName = actionName
            self.actionState = actionState
            self.startDateTime = startDateTime
            self.lastUpdatedDateTime = lastUpdatedDateTime
        }
        /// "rebootNow" reads as "Restart"; anything else reads as Graph names it.
        public var title: String {
            DeviceActionKind.allCases.first { $0.pathSegment == actionName }?.title ?? (actionName ?? "Action")
        }
    }

    public let id: String
    public let managedDeviceOwnerType: String?
    public let deviceEnrollmentType: String?
    public let managementAgent: String?
    public let enrollmentProfileName: String?
    public let complianceState: String?
    public let lastSyncDateTime: Date?
    public let deviceActionResults: [ActionResult]

    public init(id: String, managedDeviceOwnerType: String?, deviceEnrollmentType: String?, managementAgent: String?, enrollmentProfileName: String?, complianceState: String?, lastSyncDateTime: Date?, deviceActionResults: [ActionResult]) {
        self.id = id
        self.managedDeviceOwnerType = managedDeviceOwnerType
        self.deviceEnrollmentType = deviceEnrollmentType
        self.managementAgent = managementAgent
        self.enrollmentProfileName = enrollmentProfileName
        self.complianceState = complianceState
        self.lastSyncDateTime = lastSyncDateTime
        self.deviceActionResults = deviceActionResults
    }

    enum CodingKeys: String, CodingKey {
        case id, managedDeviceOwnerType, deviceEnrollmentType, managementAgent, enrollmentProfileName, complianceState, lastSyncDateTime, deviceActionResults
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        managedDeviceOwnerType = try c.decodeIfPresent(String.self, forKey: .managedDeviceOwnerType)
        deviceEnrollmentType = try c.decodeIfPresent(String.self, forKey: .deviceEnrollmentType)
        managementAgent = try c.decodeIfPresent(String.self, forKey: .managementAgent)
        enrollmentProfileName = try c.decodeIfPresent(String.self, forKey: .enrollmentProfileName)
        complianceState = try c.decodeIfPresent(String.self, forKey: .complianceState)
        lastSyncDateTime = try c.decodeIfPresent(Date.self, forKey: .lastSyncDateTime)
        deviceActionResults = try c.decodeIfPresent([ActionResult].self, forKey: .deviceActionResults) ?? []
    }

    public static let selectFields = ["id", "managedDeviceOwnerType", "deviceEnrollmentType", "managementAgent", "enrollmentProfileName", "complianceState", "lastSyncDateTime", "deviceActionResults"]

    /// Actions Intune still has in flight, newest first.
    public var pendingActions: [ActionResult] {
        deviceActionResults
            .filter { ($0.actionState ?? "").lowercased() == "pending" }
            .sorted { ($0.startDateTime ?? .distantPast) > ($1.startDateTime ?? .distantPast) }
    }

    /// Graph's enum values an administrator sees most, in the words the portal uses.
    static let vocabulary: [String: String] = [
        "company": "Corporate",
        "personal": "Personal",
        "mdm": "Intune MDM",
        "easMdm": "Exchange ActiveSync and Intune",
        "configurationManagerClientMdm": "Configuration Manager and Intune (co-managed)",
        "configurationManagerClient": "Configuration Manager",
        "intuneClient": "Intune client",
        "jamf": "Jamf",
        "googleCloudDevicePolicyController": "Android Enterprise",
        "windowsAzureADJoin": "Entra joined",
        "windowsAzureADJoinUsingDeviceAuth": "Entra joined (device authentication)",
        "windowsAutoEnrollment": "Group Policy auto-enrollment",
        "windowsBulkAzureDomainJoin": "Bulk Entra join",
        "windowsBulkUserless": "Bulk userless",
        "windowsCoManagement": "Co-management",
        "userEnrollment": "User enrollment",
        "deviceEnrollmentManager": "Device enrollment manager",
        "appleBulkWithUser": "Apple automated enrollment, with user",
        "appleBulkWithoutUser": "Apple automated enrollment, userless",
        "appleUserEnrollment": "Apple user enrollment",
        "androidEnterpriseDedicatedDevice": "Android Enterprise dedicated",
        "androidEnterpriseFullyManaged": "Android Enterprise fully managed",
        "androidEnterpriseCorporateWorkProfile": "Android Enterprise work profile"
    ]

    /// `windowsAzureADJoin` reads as "Entra joined"; a value not in the table is split
    /// on its capitals so a new one still reads.
    public static func words(_ raw: String?) -> String? {
        guard let raw, !raw.isEmpty, raw != "unknown" else { return nil }
        if let known = vocabulary[raw] { return known }
        var out = ""
        var previousWasLower = false
        for ch in raw {
            if ch.isUppercase, previousWasLower { out.append(" ") }
            out.append(ch)
            previousWasLower = ch.isLowercase || ch.isNumber
        }
        return out.prefix(1).uppercased() + out.dropFirst().lowercased()
    }
}

public enum DeviceActionsError: Error, Sendable, Equatable {
    case consentRequired
    case notAuthorized
    case transport(status: Int)
    case decodeFailure
    case cancelled

    public init(_ error: GraphError) {
        switch error {
        case .consentRequired:                 self = .consentRequired
        case .notAuthorized:                   self = .notAuthorized
        case .notFound:                        self = .transport(status: 404)
        case .badRequest:                      self = .transport(status: 400)
        case .throttled:                       self = .transport(status: 429)
        case .serviceUnavailable(let status):  self = .transport(status: status)
        case .transport(let status):           self = .transport(status: status)
        case .decodeFailure:                   self = .decodeFailure
        case .cancelled:                       self = .cancelled
        }
    }
}

public protocol DeviceActionsProviding: Sendable {
    func record(managedDeviceId: String) async throws -> DeviceRecord
    func run(_ kind: DeviceActionKind, on target: DeviceActionTarget) async -> ActionOutcome
    func resume(_ kind: DeviceActionKind, on target: DeviceActionTarget, satisfying challenge: ClaimsChallenge) async -> ActionOutcome
    /// The last shift log line for this device, for the screen.
    func lastLogEntry(managedDeviceId: String) async -> ShiftLogEntry?
}

/// Live: the record through the shared Graph client, the actions through the runner.
public actor DeviceActionsService: DeviceActionsProviding {

    private let graph: GraphClient
    private let runner: ActionRunner
    private let log: any ShiftLogging
    private let tenantId: @Sendable () async -> String

    public init(graph: GraphClient, runner: ActionRunner, log: any ShiftLogging, tenantId: @escaping @Sendable () async -> String) {
        self.graph = graph
        self.runner = runner
        self.log = log
        self.tenantId = tenantId
    }

    public static let devicesPath = "/deviceManagement/managedDevices"

    public func record(managedDeviceId: String) async throws -> DeviceRecord {
        let request = GraphRequest(
            path: Self.devicesPath + "/" + managedDeviceId,
            template: Self.devicesPath + "/{id}",
            query: [URLQueryItem(name: "$select", value: DeviceRecord.selectFields.joined(separator: ","))],
            scopes: [DeviceActionScopes.read])
        do {
            return try await graph.decode(DeviceRecord.self, from: request)
        } catch let error as GraphError {
            throw DeviceActionsError(error)
        }
    }

    public func run(_ kind: DeviceActionKind, on target: DeviceActionTarget) async -> ActionOutcome {
        if let reason = kind.unavailableReason(for: target) {
            return .failed(.refused(reason: reason))
        }
        return await runner.run(kind.action(for: target))
    }

    public func resume(_ kind: DeviceActionKind, on target: DeviceActionTarget, satisfying challenge: ClaimsChallenge) async -> ActionOutcome {
        await runner.resume(kind.action(for: target), satisfying: challenge)
    }

    public func lastLogEntry(managedDeviceId: String) async -> ShiftLogEntry? {
        let tenant = await tenantId()
        return await log.entries(tenantId: tenant).first { $0.targetId == managedDeviceId }
    }
}

/// Demo: every action succeeds after a pause and lands in an in-memory log, so the
/// screens, App Review and screenshots never need a tenant.
public actor DemoDeviceActionsProvider: DeviceActionsProviding {

    private let latency: Duration
    private let log = InMemoryShiftLog()
    public static let tenant = "demo"

    public init(latency: Duration = .seconds(2)) {
        self.latency = latency
    }

    public func record(managedDeviceId: String) async throws -> DeviceRecord {
        try await Task.sleep(for: .milliseconds(300))
        let personal = managedDeviceId.hasSuffix("008")
        return DeviceRecord(
            id: managedDeviceId,
            managedDeviceOwnerType: personal ? "personal" : "company",
            deviceEnrollmentType: managedDeviceId.contains("-w-") ? "windowsAzureADJoin" : (managedDeviceId.contains("-m-") ? "appleBulkWithUser" : "userEnrollment"),
            managementAgent: "mdm",
            enrollmentProfileName: managedDeviceId.contains("-w-") ? "Autopilot Standard" : nil,
            complianceState: nil,
            lastSyncDateTime: Date().addingTimeInterval(-3600),
            deviceActionResults: managedDeviceId.hasSuffix("003")
                ? [DeviceRecord.ActionResult(actionName: "rebootNow", actionState: "pending", startDateTime: Date().addingTimeInterval(-600), lastUpdatedDateTime: Date().addingTimeInterval(-600))]
                : [])
    }

    public func run(_ kind: DeviceActionKind, on target: DeviceActionTarget) async -> ActionOutcome {
        if let reason = kind.unavailableReason(for: target) {
            return .failed(.refused(reason: reason))
        }
        try? await Task.sleep(for: latency)
        let requestId = "demo-" + UUID().uuidString.prefix(8)
        await log.append(ShiftLogEntry(
            at: Date(), tenantId: Self.tenant, actionId: kind.actionId, actionTitle: kind.title,
            targetLabel: target.deviceName, targetId: target.managedDeviceId, outcome: "requested", requestId: requestId))
        return .requested(requestId: requestId)
    }

    public func resume(_ kind: DeviceActionKind, on target: DeviceActionTarget, satisfying challenge: ClaimsChallenge) async -> ActionOutcome {
        await run(kind, on: target)
    }

    public func lastLogEntry(managedDeviceId: String) async -> ShiftLogEntry? {
        await log.entries(tenantId: Self.tenant).first { $0.targetId == managedDeviceId }
    }

    public var shiftLog: any ShiftLogging { log }
}
