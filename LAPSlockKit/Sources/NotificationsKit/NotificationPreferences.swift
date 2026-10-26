import Foundation
import Security

// What the admin chose, per tenant, and the break-glass accounts to watch.
//
// One Keychain item, the fifth non-credential item, decided 2026-10-26: the break-glass
// list is the tenant's most privileged accounts, and the tenant list beside it is an MSP's
// client list, the same reasoning that put the MSP tenant list in the Keychain. Unlike that
// list it is readable after first unlock rather than only while unlocked, because the
// background run reads it with the phone in a pocket. Device only, never synced, never in a
// backup that restores onto another phone.

public struct TenantAlertPreferences: Codable, Sendable, Equatable, Identifiable {
    public let tenantId: String
    /// Shown on the lock screen in place of anything from the tenant's data.
    public var label: String
    public var enabled: Bool
    public var kinds: Set<AlertKind>
    /// Sign-in addresses for the break-glass kind.
    public var breakGlassUPNs: [String]
    /// Set by the run when a silent sign-in fails; cleared by the next foreground sign-in.
    public var paused: Bool

    public var id: String { tenantId }

    public init(tenantId: String, label: String, enabled: Bool = false, kinds: Set<AlertKind> = [], breakGlassUPNs: [String] = [], paused: Bool = false) {
        self.tenantId = tenantId.lowercased()
        self.label = label
        self.enabled = enabled
        self.kinds = kinds
        self.breakGlassUPNs = breakGlassUPNs
        self.paused = paused
    }

    /// The kinds the run should actually check: enabled, and break-glass only with accounts.
    public var activeKinds: [AlertKind] {
        guard enabled, !paused else { return [] }
        return kinds.sorted().filter { $0 != .breakGlassSignIn || !breakGlassUPNs.isEmpty }
    }

    /// Lowercases, trims, drops anything that is not shaped like a sign-in address, and
    /// removes duplicates, keeping the order typed.
    public static func cleanUPNs(_ input: [String]) -> [String] {
        var seen = Set<String>()
        return input.compactMap { raw in
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard value.count <= 113, value.filter({ $0 == "@" }).count == 1,
                  let at = value.firstIndex(of: "@"), at != value.startIndex,
                  value[value.index(after: at)...].contains("."),
                  !value.contains(" "), !value.contains("'"),
                  seen.insert(value).inserted else { return nil }
            return value
        }
    }
}

public struct NotificationPreferences: Codable, Sendable, Equatable {
    public var tenants: [TenantAlertPreferences]

    public init(tenants: [TenantAlertPreferences] = []) {
        self.tenants = tenants
    }

    public func tenant(_ id: String) -> TenantAlertPreferences? {
        tenants.first { $0.tenantId == id.lowercased() }
    }

    /// Adds or updates one tenant, keeping the rest in order.
    public mutating func upsert(_ prefs: TenantAlertPreferences) {
        if let index = tenants.firstIndex(where: { $0.tenantId == prefs.tenantId }) {
            tenants[index] = prefs
        } else {
            tenants.append(prefs)
        }
    }

    /// Whether the run has anything to do at all; when not, no task is scheduled.
    public var anythingToCheck: Bool {
        tenants.contains { !$0.activeKinds.isEmpty }
    }

    /// Every enabled tenant that is paused, for the Settings banner.
    public var paused: [TenantAlertPreferences] {
        tenants.filter { $0.enabled && $0.paused }
    }
}

public protocol NotificationPreferencesStoring: Sendable {
    func load() throws -> NotificationPreferences
    func save(_ preferences: NotificationPreferences) throws
    func clear() throws
}

public enum NotificationPreferencesError: Error, Equatable {
    case readFailed(OSStatus)
    case writeFailed(OSStatus)
    case deleteFailed(OSStatus)
}

public struct KeychainNotificationPreferencesStore: NotificationPreferencesStoring {

    private let service: String
    private let account: String

    public init(service: String = "com.kainor.lapslock.notifications", account: String = "preferences") {
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

    public func load() throws -> NotificationPreferences {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return NotificationPreferences() }
        guard status == errSecSuccess, let data = item as? Data else {
            throw NotificationPreferencesError.readFailed(status)
        }
        return (try? JSONDecoder().decode(NotificationPreferences.self, from: data)) ?? NotificationPreferences()
    }

    public func save(_ preferences: NotificationPreferences) throws {
        let data = try JSONEncoder().encode(preferences)
        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        if status == errSecItemNotFound {
            var insert = baseQuery
            insert[kSecValueData as String] = data
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let added = SecItemAdd(insert as CFDictionary, nil)
            guard added == errSecSuccess else { throw NotificationPreferencesError.writeFailed(added) }
            return
        }
        throw NotificationPreferencesError.writeFailed(status)
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NotificationPreferencesError.deleteFailed(status)
        }
    }
}

public final class InMemoryNotificationPreferencesStore: NotificationPreferencesStoring, @unchecked Sendable {
    private var value = NotificationPreferences()
    private let lock = NSLock()
    public init(_ initial: NotificationPreferences = NotificationPreferences()) { value = initial }
    public func load() throws -> NotificationPreferences { lock.lock(); defer { lock.unlock() }; return value }
    public func save(_ preferences: NotificationPreferences) throws { lock.lock(); value = preferences; lock.unlock() }
    public func clear() throws { lock.lock(); value = NotificationPreferences(); lock.unlock() }
}
