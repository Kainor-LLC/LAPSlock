import Foundation
import CredentialKit

// Build Spec §2.2, §2.5, §5 — device inventory models.
//
// EVERYTHING HERE IS NON-SENSITIVE. Device names, OS versions, compliance state, and
// identifiers are ordinary management metadata: cacheable, loggable, and safe to keep in
// memory. Passwords never touch this module — that is CredentialKit's job, and the
// separation is deliberate (§3.1).
//
// ─────────────────────────────────────────────────────────────────────────────
// FINDING (2026-08-14, verified against a live tenant): §2.5's "two-identifier
// join" is NOT a join. The Intune v1.0 managedDevices resource returns
// `azureADDeviceId` directly, so the Entra device id that Windows LAPS reveal keys
// on arrives in the same response as the Intune managedDeviceId. No second call to
// /devices is required.
//
// The real edge case is absence, not lookup: `azureADDeviceId` may be null or the
// all-zeros GUID for devices that are not Entra-joined (e.g. workplace-joined or
// Intune-only). Those devices cannot have Windows LAPS, so the UI must say so
// instead of firing a request that 404s.
// ─────────────────────────────────────────────────────────────────────────────

/// Ordinary management metadata for one device. Safe to cache.
public struct ManagedDeviceSummary: Sendable, Identifiable, Equatable, Hashable {
    /// Intune managedDeviceId — the key for Intune actions (rotate, portal deep link).
    public let id: String
    /// Entra directory device id — the key for Windows LAPS reveal. Nil when absent
    /// or when Graph returned the all-zeros placeholder.
    public let entraDeviceId: String?
    public let deviceName: String
    public let platform: DevicePlatform
    public let operatingSystemRaw: String?
    public let osVersion: String?
    public let userPrincipalName: String?
    public let serialNumber: String?
    public let model: String?
    public let manufacturer: String?
    public let complianceState: String?
    public let lastSyncDateTime: Date?

    public init(
        id: String,
        entraDeviceId: String?,
        deviceName: String,
        platform: DevicePlatform,
        operatingSystemRaw: String? = nil,
        osVersion: String? = nil,
        userPrincipalName: String? = nil,
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
        self.serialNumber = serialNumber
        self.model = model
        self.manufacturer = manufacturer
        self.complianceState = complianceState
        self.lastSyncDateTime = lastSyncDateTime
    }

    /// The all-zeros GUID Graph sometimes returns instead of null.
    static let placeholderGuid = "00000000-0000-0000-0000-000000000000"

    /// True when this device has a usable Entra device id. Windows LAPS reveal is
    /// impossible without one, so the UI gates on this rather than on an error.
    public var hasEntraDeviceIdentity: Bool { entraDeviceId != nil }

    /// Hand-off object for CredentialKit. Carries both identifiers (§2.5).
    public var credentialTarget: DeviceCredentialTarget {
        DeviceCredentialTarget(
            platform: platform,
            entraDeviceId: entraDeviceId,
            managedDeviceId: id,
            deviceName: deviceName
        )
    }

    /// Explanation shown when a device can't support reveal for a structural reason
    /// (as opposed to a permission or service error). Nil when reveal is plausible.
    public var revealBlockedReason: String? {
        if platform == .other {
            return "PitLAPS manages local administrator passwords on Windows and macOS devices only."
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
        self.userPrincipalName = obj["userPrincipalName"] as? String
        self.serialNumber = obj["serialNumber"] as? String
        self.model = obj["model"] as? String
        self.manufacturer = obj["manufacturer"] as? String
        self.complianceState = obj["complianceState"] as? String
        self.lastSyncDateTime = InventoryHTTP.date(obj["lastSyncDateTime"])
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
    case notAuthorized                        // 403 — lacks an Intune read role
    case consentRequired                      // 401
    case throttled(retryAfter: TimeInterval?) // 429 — honor Retry-After
    case serviceUnavailable(status: Int)      // 5xx
    case transport(status: Int)
    case decodeFailure
    case cancelled
}
