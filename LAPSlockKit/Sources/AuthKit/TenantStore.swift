import Foundation
#if canImport(Security)
import Security
#endif

// The customer organizations an MSP has added, so domains are typed once rather than daily.
//
// WHAT THIS LIST IS, AND WHY IT IS TREATED CAREFULLY.
//
// Individually these values are public: any domain's tenant GUID is returned by
// unauthenticated OIDC discovery, which is the same fact the entitlement contract relies on
// in §9.1. In aggregate they are something else — **a list of an MSP's clients** — and that
// is commercially sensitive.
//
// This is the client-side half of a decision already made on the server side. The
// entitlement contract §7.1 refuses to auto-activate on tenant switch specifically so that
// Kainor never accumulates this list. Storing it loosely on the device while refusing to
// collect it centrally would be an odd kind of principle, so it goes in the Keychain,
// device-only, and it is never transmitted anywhere by any code path.

/// One organization an MSP works in.
public struct TenantReference: Codable, Sendable, Equatable, Identifiable, Hashable {
    /// Lowercase canonical GUID. Also the identity: one row per directory.
    public let tenantId: String
    /// What the user typed — usually a domain. Shown in the picker, because an
    /// administrator recognises `contoso.com` and not a GUID.
    public var label: String
    public var lastUsedAt: Date

    public var id: String { tenantId }

    public init(tenantId: String, label: String, lastUsedAt: Date = Date()) {
        self.tenantId = tenantId.lowercased()
        self.label = label
        self.lastUsedAt = lastUsedAt
    }
}

public protocol TenantStoring: Sendable {
    func load() throws -> [TenantReference]
    func save(_ tenants: [TenantReference]) throws
    func clear() throws
}

/// Ordering and de-duplication, kept out of the storage implementations so it is testable
/// without a Keychain.
public enum TenantList {

    /// Most recently used first. An MSP's working set is a handful of customers they touch
    /// repeatedly, so recency beats alphabetical for getting the next tap right.
    public static func sorted(_ tenants: [TenantReference]) -> [TenantReference] {
        tenants.sorted { $0.lastUsedAt > $1.lastUsedAt }
    }

    /// Adds or updates one entry, keyed by tenant ID.
    ///
    /// Re-adding an existing tenant updates its label and recency rather than creating a
    /// second row: two entries for one directory would be a picker that lies about how many
    /// customers you have.
    public static func upsert(
        _ tenant: TenantReference,
        into tenants: [TenantReference],
        limit: Int = 50
    ) -> [TenantReference] {
        var remaining = tenants.filter { $0.tenantId != tenant.tenantId }
        remaining.append(tenant)
        return Array(sorted(remaining).prefix(max(1, limit)))
    }

    public static func removing(_ tenantId: String, from tenants: [TenantReference]) -> [TenantReference] {
        tenants.filter { $0.tenantId != tenantId.lowercased() }
    }
}

/// In-memory store, for tests and previews.
public final class InMemoryTenantStore: TenantStoring, @unchecked Sendable {
    private var tenants: [TenantReference]
    public init(_ tenants: [TenantReference] = []) { self.tenants = tenants }
    public func load() throws -> [TenantReference] { tenants }
    public func save(_ tenants: [TenantReference]) throws { self.tenants = tenants }
    public func clear() throws { tenants = [] }
}

#if canImport(Security)

/// Keychain-backed, modelled on `KeychainRevealLedgerStore`.
///
/// `WhenUnlockedThisDeviceOnly`, deliberately on both halves. WhenUnlocked because the list
/// is only ever read with the app in the foreground. ThisDeviceOnly because a client list
/// must not sync through iCloud Keychain and must not restore onto a different phone —
/// re-adding a customer is one line of typing, and a client list following a restored backup
/// around is not.
public struct KeychainTenantStore: TenantStoring {

    private let service: String
    private let account: String

    public init(
        service: String = "com.kainor.lapslock.tenants",
        account: String = "list"
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

    public func load() throws -> [TenantReference] {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let data = item as? Data else {
            throw TenantStoreError.readFailed(status)
        }
        // Undecodable means empty rather than fatal. The cost is retyping a domain; the cost
        // of throwing here would be an MSP unable to open the picker at all.
        return (try? JSONDecoder().decode([TenantReference].self, from: data)) ?? []
    }

    public func save(_ tenants: [TenantReference]) throws {
        let data = try JSONEncoder().encode(TenantList.sorted(tenants))
        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }

        if status == errSecItemNotFound {
            var insert = baseQuery
            insert[kSecValueData as String] = data
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(insert as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw TenantStoreError.writeFailed(addStatus) }
            return
        }
        throw TenantStoreError.writeFailed(status)
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TenantStoreError.deleteFailed(status)
        }
    }
}

public enum TenantStoreError: Error, Equatable {
    case readFailed(OSStatus)
    case writeFailed(OSStatus)
    case deleteFailed(OSStatus)
}

#endif
