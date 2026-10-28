import Foundation
import AuthKit

// Build Spec §2.2, §2.5, §5, device inventory models.
//
// Everything here is non-sensitive. Device names, OS versions, compliance state, and
// identifiers are ordinary management metadata: cacheable, loggable, and safe to keep in
// memory. Passwords never touch this module, that is CredentialKit's job, and the
// separation is deliberate (§3.1).
//
// FINDING (verified against a live tenant): §2.5's "two-identifier
// join" is NOT a join. The Intune v1.0 managedDevices resource returns
// `azureADDeviceId` directly, so the Entra device id that Windows LAPS reveal keys
// on arrives in the same response as the Intune managedDeviceId. No second call to
// /devices is required.
//
// The real edge case is absence, not lookup: `azureADDeviceId` may be null or the
// all-zeros GUID for devices that are not Entra-joined (e.g. workplace-joined or
// Intune-only). Those devices cannot have Windows LAPS, so the UI must say so
// instead of firing a request that 404s.

/// Ordinary management metadata for one device. Safe to cache.
public struct ManagedDeviceSummary: Sendable, Identifiable, Equatable, Hashable {
    /// Intune managedDeviceId, the key for Intune actions (rotate, portal deep link).
    public let id: String
    /// Entra directory device id, the key for Windows LAPS reveal. Nil when absent
    /// or when Graph returned the all-zeros placeholder.
    public let entraDeviceId: String?
    public let deviceName: String
    public let platform: DevicePlatform
    public let operatingSystemRaw: String?
    public let osVersion: String?
    public let userPrincipalName: String?
    /// Primary user's display name ("Connor Johnson"). Admins search for people by name
    /// far more often than by UPN, so this is a search field first and a display field
    /// second.
    public let userDisplayName: String?
    /// Primary user's mail address. Frequently differs from the UPN (alias domains,
    /// post-migration tenants), and an admin handed an email address from a ticket has no
    /// way to know which one they were given.
    public let emailAddress: String?
    /// Intune's own name for the device, which is not always the same string as
    /// `deviceName`, some enrolment paths generate one and let the other drift.
    public let managedDeviceName: String?
    public let serialNumber: String?
    public let model: String?
    public let manufacturer: String?
    public let complianceState: String?
    public let lastSyncDateTime: Date?
    /// The searchable fields folded once, when the device is built, so a search compares
    /// strings instead of folding every field of every device on every keystroke. Built
    /// from the fields above and nothing else.
    public let searchKey: DeviceSearchKey

    public init(
        id: String,
        entraDeviceId: String?,
        deviceName: String,
        platform: DevicePlatform,
        operatingSystemRaw: String? = nil,
        osVersion: String? = nil,
        userPrincipalName: String? = nil,
        userDisplayName: String? = nil,
        emailAddress: String? = nil,
        managedDeviceName: String? = nil,
        serialNumber: String? = nil,
        model: String? = nil,
        manufacturer: String? = nil,
        complianceState: String? = nil,
        lastSyncDateTime: Date? = nil
    ) {
        self.id = id
        self.entraDeviceId = entraDeviceId
        self.deviceName = deviceName
        self.platform = platform
        self.operatingSystemRaw = operatingSystemRaw
        self.osVersion = osVersion
        self.userPrincipalName = userPrincipalName
        self.userDisplayName = userDisplayName
        self.emailAddress = emailAddress
        self.managedDeviceName = managedDeviceName
        self.serialNumber = serialNumber
        self.model = model
        self.manufacturer = manufacturer
        self.complianceState = complianceState
        self.lastSyncDateTime = lastSyncDateTime
        self.searchKey = DeviceSearchKey(
            deviceName: deviceName, userDisplayName: userDisplayName, userPrincipalName: userPrincipalName,
            emailAddress: emailAddress, serialNumber: serialNumber, model: model, managedDeviceName: managedDeviceName)
    }

    /// The same device with the primary user's display name filled in. Used when the name
    /// was looked up in Entra because Intune left the field empty; every other field is
    /// carried across unchanged.
    public func withUserDisplayName(_ name: String) -> ManagedDeviceSummary {
        ManagedDeviceSummary(
            id: id,
            entraDeviceId: entraDeviceId,
            deviceName: deviceName,
            platform: platform,
            operatingSystemRaw: operatingSystemRaw,
            osVersion: osVersion,
            userPrincipalName: userPrincipalName,
            userDisplayName: name,
            emailAddress: emailAddress,
            managedDeviceName: managedDeviceName,
            serialNumber: serialNumber,
            model: model,
            manufacturer: manufacturer,
            complianceState: complianceState,
            lastSyncDateTime: lastSyncDateTime)
    }

    /// The all-zeros GUID Graph sometimes returns instead of null.
    static let placeholderGuid = "00000000-0000-0000-0000-000000000000"

    /// True when this device has a usable Entra device id. Windows LAPS reveal is
    /// impossible without one, so the UI gates on this rather than on an error.
    public var hasEntraDeviceIdentity: Bool { entraDeviceId != nil }

    /// Best available label for the primary user: real name if Intune has one, otherwise
    /// the UPN, otherwise the mail address. Nil when the device has no primary user at
    /// all, which is normal for shared and kiosk devices.
    public var primaryUserLabel: String? {
        userDisplayName ?? userPrincipalName ?? emailAddress
    }

    /// Explanation shown when a device can't support reveal for a structural reason
    /// (as opposed to a permission or service error). Nil when reveal is plausible.
    public var revealBlockedReason: String? {
        if platform == .other {
            return "LAPSlock manages local administrator passwords on Windows and macOS devices only."
        }
        if platform == .windows && !hasEntraDeviceIdentity {
            return "This device isn't joined to Microsoft Entra ID, so Windows LAPS can't store a password for it."
        }
        return nil
    }

    // MARK: - parsing

    /// Builds a summary from a Graph `managedDevices` entry.
    /// Returns nil only when the response lacks an `id`, which would make the record
    /// unusable for every subsequent call.
    init?(graphEntry obj: [String: Any]) {
        guard let id = obj["id"] as? String, !id.isEmpty else { return nil }
        self.id = id

        // Normalize the Entra device id: reject empty strings and the all-zeros GUID,
        // both of which Graph uses to mean "none".
        let rawEntra = (obj["azureADDeviceId"] as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let rawEntra,
           !rawEntra.isEmpty,
           rawEntra.lowercased() != Self.placeholderGuid {
            self.entraDeviceId = rawEntra
        } else {
            self.entraDeviceId = nil
        }

        let osRaw = obj["operatingSystem"] as? String
        self.operatingSystemRaw = osRaw
        self.platform = DevicePlatform(intuneOperatingSystem: osRaw)

        let name = (obj["deviceName"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.deviceName = (name?.isEmpty == false ? name! : "Unnamed device")

        self.osVersion = obj["osVersion"] as? String
        self.userPrincipalName = Self.nonEmpty(obj["userPrincipalName"])
        self.userDisplayName = Self.nonEmpty(obj["userDisplayName"])
        self.emailAddress = Self.nonEmpty(obj["emailAddress"])
        self.managedDeviceName = Self.nonEmpty(obj["managedDeviceName"])
        self.serialNumber = obj["serialNumber"] as? String
        self.model = obj["model"] as? String
        self.manufacturer = obj["manufacturer"] as? String
        self.complianceState = obj["complianceState"] as? String
        self.lastSyncDateTime = InventoryHTTP.date(obj["lastSyncDateTime"])
        self.searchKey = DeviceSearchKey(
            deviceName: deviceName, userDisplayName: userDisplayName, userPrincipalName: userPrincipalName,
            emailAddress: emailAddress, serialNumber: serialNumber, model: model, managedDeviceName: managedDeviceName)
    }

    /// Graph returns "" rather than null for user fields on devices with no primary user.
    /// An empty string is a substring of every query, so left as-is it would make those
    /// devices match everything. Normalising to nil at the boundary keeps the search code
    /// from having to know that.
    private static func nonEmpty(_ any: Any?) -> String? {
        guard let s = any as? String else { return nil }
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

/// A device's searchable fields, folded for case and diacritics once.
public struct DeviceSearchKey: Sendable, Hashable {
    /// The device name folded: what the list sorts by, and what a name match compares.
    public let name: String
    /// The other searchable fields folded, in the order a search ranks them: the user's
    /// name, sign-in address and mail, then serial number, model and Intune's own name.
    public let others: [String]
    /// All of them joined by a character nobody can type, so a device that cannot match is
    /// ruled out with one check before any ranking.
    public let all: String

    static let separator = "\u{1F}"

    init(deviceName: String, userDisplayName: String?, userPrincipalName: String?, emailAddress: String?,
         serialNumber: String?, model: String?, managedDeviceName: String?) {
        let fold = { (s: String) in s.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil) }
        name = fold(deviceName)
        others = [userDisplayName, userPrincipalName, emailAddress, serialNumber, model, managedDeviceName]
            .compactMap { $0 }
            .map(fold)
        all = ([name] + others).joined(separator: Self.separator)
    }
}

/// One page of results plus the cursor for the next page.
public struct DevicePage: Sendable, Equatable {
    public let devices: [ManagedDeviceSummary]
    /// Graph `@odata.nextLink`. Nil means the last page.
    public let nextLink: String?
    public var hasMore: Bool { nextLink != nil }

    public init(devices: [ManagedDeviceSummary], nextLink: String?) {
        self.devices = devices
        self.nextLink = nextLink
    }
}

public enum InventoryError: Error, Sendable, Equatable {
    case notAuthorized                        // 403, lacks an Intune read role
    case consentRequired                      // 401
    case throttled(retryAfter: TimeInterval?) // 429, honor Retry-After
    case serviceUnavailable(status: Int)      // 5xx
    case transport(status: Int)
    case decodeFailure
    case cancelled
}
