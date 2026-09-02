import Foundation
#if canImport(Security)
import Security
#endif

// Build Spec — where the entitlement lives on the device. Contract section 7.5.

/// Everything persisted about a license activation. Codable, and small on purpose.
///
/// `boundTenantId` is the tenant the license was activated against, which is what `sub` is
/// checked against. It is stored separately from the token so the check does not depend on
/// decoding an unverified claim to find out what to compare it to.
public struct EntitlementRecord: Codable, Sendable, Equatable {
    public var boundTenantId: String
    /// The compact JWS as received. Verified from scratch on every read — a stored token is
    /// never trusted because it was trusted before.
    public var token: String?
    /// Server hint, already clamped. Nil when the server did not send one.
    public var refreshAfter: Date?
    /// Last time an automatic OR manual fetch was attempted, successful or not. Drives the
    /// once-per-24-hours floor in section 7.3.
    public var lastAttemptAt: Date?
    /// Set when the last attempt failed at the NETWORK layer specifically. This is the one
    /// condition under which an expired token keeps working (section 7.5). Cleared by any
    /// answer from the server, including an error.
    public var lastFailureWasNetwork: Bool

    public init(
        boundTenantId: String,
        token: String? = nil,
        refreshAfter: Date? = nil,
        lastAttemptAt: Date? = nil,
        lastFailureWasNetwork: Bool = false
    ) {
        self.boundTenantId = boundTenantId.lowercased()
        self.token = token
        self.refreshAfter = refreshAfter
        self.lastAttemptAt = lastAttemptAt
        self.lastFailureWasNetwork = lastFailureWasNetwork
    }
}

public protocol EntitlementStoring: Sendable {
    func load() throws -> EntitlementRecord?
    func save(_ record: EntitlementRecord) throws
    func clear() throws
}

/// In-memory store, for tests and previews.
public final class InMemoryEntitlementStore: EntitlementStoring, @unchecked Sendable {
    private var record: EntitlementRecord?
    public init(_ record: EntitlementRecord? = nil) { self.record = record }
    public func load() throws -> EntitlementRecord? { record }
    public func save(_ record: EntitlementRecord) throws { self.record = record }
    public func clear() throws { record = nil }
}

#if canImport(Security)

/// Keeps the entitlement in the Keychain.
///
/// Modelled on `KeychainRevealLedgerStore`, with one deliberate difference in the
/// accessibility class. The ledger uses WhenUnlocked because it is only touched with the app
/// in the foreground. The entitlement uses **AfterFirstUnlockThisDeviceOnly**, per contract
/// section 7.5: a background refresh may run with the screen locked, and a token that could
/// not be read then would look like a license flickering off.
///
/// ThisDeviceOnly for the same reason as the ledger — the item must not sync through iCloud
/// Keychain or ride a restore onto a new phone. A new device re-activating is one tap; a
/// license following a backup around is not something to explain to an auditor.
///
/// The token is not a credential — it grants no Graph access and cannot read a password —
/// but it IS a bearer statement, and `UserDefaults` is not the place for one.
public struct KeychainEntitlementStore: EntitlementStoring {

    private let service: String
    private let account: String

    public init(
        service: String = "com.kainor.lapslock.entitlement",
        account: String = "record"
    ) {
        self.service = service
        self.account = account
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    public func load() throws -> EntitlementRecord? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw KeychainEntitlementError.readFailed(status)
        }
        // Undecodable means absent, not fatal. The user lands on the free tier and can
        // re-activate, which is section 7.6's answer to every failure here.
        return try? JSONDecoder().decode(EntitlementRecord.self, from: data)
    }

    public func save(_ record: EntitlementRecord) throws {
        let data = try JSONEncoder().encode(record)

        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }

        if status == errSecItemNotFound {
            var insert = baseQuery
            insert[kSecValueData as String] = data
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let addStatus = SecItemAdd(insert as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainEntitlementError.writeFailed(addStatus)
            }
            return
        }

        throw KeychainEntitlementError.writeFailed(status)
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainEntitlementError.deleteFailed(status)
        }
    }
}

public enum KeychainEntitlementError: Error, Equatable {
    case readFailed(OSStatus)
    case writeFailed(OSStatus)
    case deleteFailed(OSStatus)
}

#endif
