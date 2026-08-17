import Foundation
import AuthKit

// BitLocker recovery keys — the most-requested adjacent feature in this category.
//
// WHY THIS BELONGS IN CredentialKit
// A BitLocker recovery key is a secret of the same weight as a local admin password: it
// decrypts the disk. So it lives behind the same isolation boundary (§3.1), flows through
// SensitiveValue, and gets the same biometric gate and bounded reveal window. It is not
// "device metadata."
//
// THE API (verified against Microsoft Learn, v1.0 GA)
//   List for a device:
//     GET /v1.0/informationProtection/bitlocker/recoveryKeys?$filter=deviceId eq '{entraDeviceId}'
//     Returns key metadata WITHOUT the key value. Note: $top is not supported here.
//   Reveal one key:
//     GET /v1.0/informationProtection/bitlocker/recoveryKeys/{id}?$select=key
//     The `key` property is only returned when explicitly $select-ed.
//
// Two properties of this API that fit the product unusually well:
//   1. Delegated only — application permissions are NOT supported for retrieving the key.
//      The same "acts as you, never on its own" story as LAPS, enforced by Microsoft.
//   2. Adding $select=key triggers a Microsoft Entra audit entry (KeyManagement category).
//      The audit claim we already make for LAPS holds here for the same reason.
//
// Roles that can read keys (least privileged first): Cloud Device Administrator,
// Helpdesk Administrator, Intune Service Administrator, Security Administrator,
// Security Reader, Global Reader. A signed-in user who is the registered owner of the
// device can also read its own key.
//
// KEYED BY THE ENTRA DEVICE ID — the same identifier Windows LAPS reveal uses, which
// InventoryKit already carries on every device. No new lookup, no new join.

/// Which volume a recovery key unlocks. Shown because a device commonly has several keys
/// and picking the wrong one wastes a trip to the machine.
public enum BitLockerVolumeType: String, Sendable, Equatable {
    case operatingSystemVolume
    case fixedDataVolume
    case removableDataVolume
    case unknown

    public init(graphValue: String?) {
        switch (graphValue ?? "").lowercased() {
        case "operatingsystemvolume": self = .operatingSystemVolume
        case "fixeddatavolume":       self = .fixedDataVolume
        case "removabledatavolume":   self = .removableDataVolume
        default:                      self = .unknown
        }
    }

    /// Label an admin standing at a recovery prompt would recognize.
    public var displayName: String {
        switch self {
        case .operatingSystemVolume: return "Operating system drive"
        case .fixedDataVolume:       return "Fixed data drive"
        case .removableDataVolume:   return "Removable drive"
        case .unknown:               return "Drive"
        }
    }

    /// The OS volume is what a locked-out user is almost always staring at, so it sorts
    /// first and is the sensible default selection.
    var sortPriority: Int {
        switch self {
        case .operatingSystemVolume: return 0
        case .fixedDataVolume:       return 1
        case .removableDataVolume:   return 2
        case .unknown:               return 3
        }
    }
}

/// Non-sensitive metadata about a stored recovery key. Safe to list before any gate,
/// because it contains no key material.
public struct BitLockerKeyInfo: Sendable, Equatable, Identifiable {
    /// The recovery key's own id, used to fetch the value.
    public let id: String
    public let volumeType: BitLockerVolumeType
    public let createdDateTime: Date?
    /// The Entra device this key was most recently backed up from.
    public let deviceId: String?

    public init(id: String, volumeType: BitLockerVolumeType, createdDateTime: Date?, deviceId: String?) {
        self.id = id
        self.volumeType = volumeType
        self.createdDateTime = createdDateTime
        self.deviceId = deviceId
    }

    init?(graphEntry obj: [String: Any]) {
        guard let id = obj["id"] as? String, !id.isEmpty else { return nil }
        self.id = id
        self.volumeType = BitLockerVolumeType(graphValue: obj["volumeType"] as? String)
        self.createdDateTime = GraphHTTP.date(obj["createdDateTime"])
        self.deviceId = obj["deviceId"] as? String
    }

    /// First eight characters of the key id. BitLocker's own recovery screen shows a key
    /// identifier, so surfacing a prefix lets an admin match the on-screen prompt to the
    /// right key when a device has several.
    public var shortIdentifier: String {
        String(id.prefix(8)).uppercased()
    }
}

/// A revealed recovery key. The value exists only inside `secret`.
public struct RevealedRecoveryKey {
    public let info: BitLockerKeyInfo
    public let secret: SensitiveValue

    public init(info: BitLockerKeyInfo, secret: SensitiveValue) {
        self.info = info
        self.secret = secret
    }
}

/// The contract. Implemented live against Graph and by a demo double.
public protocol BitLockerKeyProviding: Sendable {
    /// Scope needed to list metadata.
    var listScopes: [String] { get }
    /// Scope needed to retrieve an actual key value.
    var revealScopes: [String] { get }

    /// Lists the recovery keys backed up from a device. No key material returned.
    func keys(forEntraDeviceId entraDeviceId: String) async throws -> [BitLockerKeyInfo]

    /// Retrieves one key value. Caller MUST have passed the biometric gate first.
    func reveal(keyId: String, info: BitLockerKeyInfo) async throws -> RevealedRecoveryKey
}
