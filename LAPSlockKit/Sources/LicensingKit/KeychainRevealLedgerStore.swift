import Foundation
#if canImport(Security)
import Security
#endif

#if canImport(Security)

/// Keeps the reveal ledger in the Keychain.
///
/// WHY THE KEYCHAIN AND NOT UserDefaults: `UserDefaults` is inside the app container and
/// is destroyed when the app is deleted, so the meter would reset with a delete and
/// reinstall. Keychain items outlive the app on iOS, which is the entire reason for the
/// choice.
///
/// ⚠️ VERIFY THAT ON DEVICE BEFORE TRUSTING IT. Keychain survival across app deletion is
/// long-standing iOS behaviour but it is NOT a documented guarantee, and Apple changed it
/// briefly in an iOS 10.3 beta before reverting. This app has already shipped four bugs
/// that only appeared on real hardware. Install, reveal, delete the app, reinstall, and
/// confirm the count carried over.
///
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` is deliberate on both halves:
///   * WhenUnlocked, because the meter is only ever touched with the app in the foreground
///     on an unlocked device, so nothing weaker is needed.
///   * ThisDeviceOnly, because the item must not sync through iCloud Keychain and must not
///     restore onto a new phone. A new device resetting the meter is accepted, and is far
///     preferable to one person's allowance following a restored backup around.
public struct KeychainRevealLedgerStore: RevealLedgerStore {

    private let service: String
    private let account: String

    public init(
        service: String = "com.kainor.lapslock.reveal-meter",
        account: String = "ledger"
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

    public func load() throws -> RevealLedger? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw KeychainLedgerError.readFailed(status)
        }
        // A ledger that will not decode is treated as absent rather than fatal. The only
        // way to get here is a format change or corruption, and neither is worth blocking
        // a reveal over.
        return try? JSONDecoder().decode(RevealLedger.self, from: data)
    }

    public func save(_ ledger: RevealLedger) throws {
        let data = try JSONEncoder().encode(ledger)

        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)

        if status == errSecSuccess { return }

        if status == errSecItemNotFound {
            var insert = baseQuery
            insert[kSecValueData as String] = data
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(insert as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainLedgerError.writeFailed(addStatus)
            }
            return
        }

        throw KeychainLedgerError.writeFailed(status)
    }

    public func reset() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainLedgerError.deleteFailed(status)
        }
    }
}

/// Carries only an OSStatus. There is nothing user-facing to say about these: the meter
/// fails open, so a Keychain problem costs a count and never blocks anybody.
public enum KeychainLedgerError: Error, Equatable {
    case readFailed(OSStatus)
    case writeFailed(OSStatus)
    case deleteFailed(OSStatus)
}

#endif
