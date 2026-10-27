import Foundation
import CryptoKit
import Security

// The relay, on the phone. Phase 4 step D, docs/RELAY-API.md (frozen 2026-10-27).
//
// The customer's Automation run encrypts each alert for one phone with HPKE in
// authenticated mode and sends it through Kainor's relay to APNs. Here: the phone's key
// (in the Secure Enclave), the two pairing codes, opening an envelope, checking what is
// inside, and dropping a repeat. The Notification Service Extension and the app both use
// this; neither writes anything decrypted to disk except a day of alert ids.
//
// Foundation, CryptoKit and Security only. The isolation guard keeps every kit that can
// reach a token or a credential out of its link graph.

public enum RelayContract {
    public static let version = 1
    public static let suite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
    public static let suiteName = "DHKEM-P256-HKDF-SHA256/HKDF-SHA256/AES-256-GCM"
    public static let info = Data("TenantKeep relay v1".utf8)
    public static let plaintextLimit = 2_700
    public static let titleLimit = 80
    public static let bodyLimit = 400
    /// The Keychain access group the app and its notification extension share.
    public static let accessGroupSuffix = "com.kainor.lapslock.relay"
}

public enum RelayError: Error, Sendable, Equatable {
    case notPaired
    case noSenderForTenant
    case malformed(String)
    case verificationFailed
    case duplicate
    case tooLarge
    case keyUnavailable
    case keychain(OSStatus)
}

// MARK: - base64url

enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s.append("=") }
        return Data(base64Encoded: s)
    }
}

// MARK: - pairing codes

/// Phone to Automation: what the customer's run needs to send to this phone.
/// Shown as a QR code and as text starting `tkrelay1:`.
public struct PairingCode: Codable, Sendable, Equatable {
    public var v: Int
    public var deviceToken: String
    public var environment: String
    /// The phone's public key, X9.63 uncompressed, base64url.
    public var publicKey: String

    public static let prefix = "tkrelay1:"

    public init(deviceToken: String, environment: String, publicKey: Data) {
        self.v = RelayContract.version
        self.deviceToken = deviceToken.lowercased()
        self.environment = environment
        self.publicKey = Base64URL.encode(publicKey)
    }

    public var text: String {
        Self.prefix + Base64URL.encode((try? JSONEncoder().encode(self)) ?? Data())
    }

    public static func parse(_ text: String) -> PairingCode? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(prefix), let data = Base64URL.decode(String(trimmed.dropFirst(prefix.count))),
              let code = try? JSONDecoder().decode(PairingCode.self, from: data), code.v == RelayContract.version else { return nil }
        return code
    }
}

/// Automation to phone: the sender key a tenant's alerts must be signed with.
/// Printed by Watch's setup as text starting `tksender1:`.
public struct SenderPin: Codable, Sendable, Equatable {
    public var v: Int
    public var tenant: String
    /// The sender's public key, X9.63 uncompressed, base64url.
    public var senderKey: String

    public static let prefix = "tksender1:"

    public init(tenant: String, senderKey: Data) {
        self.v = RelayContract.version
        self.tenant = tenant.lowercased()
        self.senderKey = Base64URL.encode(senderKey)
    }

    public var text: String {
        Self.prefix + Base64URL.encode((try? JSONEncoder().encode(self)) ?? Data())
    }

    public static func parse(_ text: String) -> SenderPin? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(prefix), let data = Base64URL.decode(String(trimmed.dropFirst(prefix.count))),
              let pin = try? JSONDecoder().decode(SenderPin.self, from: data), pin.v == RelayContract.version,
              let key = Base64URL.decode(pin.senderKey), (try? P256.KeyAgreement.PublicKey(x963Representation: key)) != nil,
              UUID(uuidString: pin.tenant) != nil else { return nil }
        return pin
    }

    var publicKey: P256.KeyAgreement.PublicKey? {
        Base64URL.decode(senderKey).flatMap { try? P256.KeyAgreement.PublicKey(x963Representation: $0) }
    }
}

// MARK: - the alert inside

public struct RelayAlert: Codable, Sendable, Equatable {
    public var v: Int
    public var id: String
    public var at: Int
    public var tenant: String
    public var kind: String
    public var title: String
    public var body: String
    public var link: String?

    /// Checks the contract's rules. A link that is not `tenantkeep://` is dropped, not refused.
    func validated() throws -> RelayAlert {
        guard v == RelayContract.version else { throw RelayError.malformed("version") }
        guard UUID(uuidString: id) != nil else { throw RelayError.malformed("id") }
        guard UUID(uuidString: tenant) != nil else { throw RelayError.malformed("tenant") }
        guard title.count <= RelayContract.titleLimit, body.count <= RelayContract.bodyLimit else { throw RelayError.malformed("length") }
        var copy = self
        copy.tenant = tenant.lowercased()
        if let link, !link.lowercased().hasPrefix("tenantkeep://") { copy.link = nil }
        return copy
    }
}

// MARK: - the phone's state: key, token, pins

/// The sixth Keychain item: the Enclave key's reference (useless off this device), the
/// device token it was paired with, and the pinned sender per tenant.
public struct RelayState: Codable, Sendable, Equatable {
    public var keyReference: Data
    /// True for a real Secure Enclave key; false only in the simulator, which has none.
    public var enclave: Bool
    public var deviceToken: String?
    public var environment: String
    public var pins: [String: String]

    public init(keyReference: Data, enclave: Bool, deviceToken: String?, environment: String, pins: [String: String] = [:]) {
        self.keyReference = keyReference
        self.enclave = enclave
        self.deviceToken = deviceToken
        self.environment = environment
        self.pins = pins
    }
}

public protocol RelayStateStoring: Sendable {
    func load() throws -> RelayState?
    func save(_ state: RelayState) throws
    func delete() throws
}

/// The Keychain item, in the access group the notification extension shares, this device
/// only, readable after first unlock so a locked phone can still decrypt.
public struct KeychainRelayStateStore: RelayStateStoring {
    let accessGroup: String?
    static let service = "com.kainor.lapslock.relay"
    static let account = "relay-state"

    /// `teamPrefix` is the app identifier prefix, such as "72C7PQBP52."; nil uses the
    /// default group, for tests.
    public init(teamPrefix: String?) {
        self.accessGroup = teamPrefix.map { $0 + RelayContract.accessGroupSuffix }
    }

    private var base: [String: Any] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: Self.service,
                                    kSecAttrAccount as String: Self.account,
                                    kSecUseDataProtectionKeychain as String: true]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    public func load() throws -> RelayState? {
        var query = base
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else { throw RelayError.keychain(status) }
        return try JSONDecoder().decode(RelayState.self, from: data)
    }

    public func save(_ state: RelayState) throws {
        let data = try JSONEncoder().encode(state)
        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(base as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = base
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            add[kSecAttrSynchronizable as String] = false
            let added = SecItemAdd(add as CFDictionary, nil)
            guard added == errSecSuccess else { throw RelayError.keychain(added) }
        } else if status != errSecSuccess {
            throw RelayError.keychain(status)
        }
    }

    public func delete() throws {
        let status = SecItemDelete(base as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw RelayError.keychain(status) }
    }
}

/// In memory, for tests and previews.
public final class MemoryRelayStateStore: RelayStateStoring, @unchecked Sendable {
    private var state: RelayState?
    private let lock = NSLock()
    public init(_ state: RelayState? = nil) { self.state = state }
    public func load() throws -> RelayState? { lock.lock(); defer { lock.unlock() }; return state }
    public func save(_ state: RelayState) throws { lock.lock(); self.state = state; lock.unlock() }
    public func delete() throws { lock.lock(); state = nil; lock.unlock() }
}

// MARK: - the relay on the phone

public struct RelayPhone: Sendable {
    let store: any RelayStateStoring

    public init(store: any RelayStateStoring) {
        self.store = store
    }

    public var isOn: Bool { (try? store.load()) != nil }

    /// Turns the relay on: a new key in the Secure Enclave, replacing any old one, so
    /// anything sent to the old key can no longer be read.
    @discardableResult
    public func turnOn(environment: String) throws -> RelayState {
        let state: RelayState
        if SecureEnclave.isAvailable {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
            state = RelayState(keyReference: key.dataRepresentation, enclave: true, deviceToken: nil, environment: environment)
        } else {
            #if targetEnvironment(simulator) || os(macOS)
            // The simulator has no Enclave; tests and the simulator use a software key.
            let key = P256.KeyAgreement.PrivateKey()
            state = RelayState(keyReference: key.rawRepresentation, enclave: false, deviceToken: nil, environment: environment)
            #else
            throw RelayError.keyUnavailable
            #endif
        }
        try store.save(state)
        return state
    }

    /// The kill switch: the key reference and every pin go. The Enclave key is unusable
    /// without its reference.
    public func turnOff() throws { try store.delete() }

    public func setDeviceToken(_ token: Data) throws {
        guard var state = try store.load() else { throw RelayError.notPaired }
        state.deviceToken = token.map { String(format: "%02x", $0) }.joined()
        try store.save(state)
    }

    public func pairingCode() throws -> PairingCode {
        guard let state = try store.load(), let token = state.deviceToken else { throw RelayError.notPaired }
        return PairingCode(deviceToken: token, environment: state.environment, publicKey: try publicKey(state))
    }

    public func pin(_ pin: SenderPin) throws {
        guard var state = try store.load() else { throw RelayError.notPaired }
        state.pins[pin.tenant] = pin.senderKey
        try store.save(state)
    }

    public func pinnedTenants() -> [String] {
        ((try? store.load())?.pins.keys).map { Array($0).sorted() } ?? []
    }

    func publicKey(_ state: RelayState) throws -> Data {
        if state.enclave {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: state.keyReference).publicKey.x963Representation
        }
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: state.keyReference).publicKey.x963Representation
    }

    /// Opens the envelope from a push payload's `e` field. Tries each pinned sender, since
    /// the tenant is only known after decryption; the AAD binds it to this phone's token.
    public func open(enc: String, ct: String, seen: RelaySeenStore? = nil, now: Date = Date()) throws -> RelayAlert {
        guard let state = try store.load(), let token = state.deviceToken else { throw RelayError.notPaired }
        guard let encData = Base64URL.decode(enc), encData.count == 65, let ctData = Base64URL.decode(ct) else { throw RelayError.malformed("envelope") }
        guard ctData.count <= RelayContract.plaintextLimit + 100 else { throw RelayError.tooLarge }
        let aad = Data(token.lowercased().utf8)
        for (_, senderText) in state.pins {
            guard let senderData = Base64URL.decode(senderText),
                  let sender = try? P256.KeyAgreement.PublicKey(x963Representation: senderData) else { continue }
            guard let plaintext = try? decrypt(state, enc: encData, ct: ctData, aad: aad, sender: sender) else { continue }
            guard plaintext.count <= RelayContract.plaintextLimit else { throw RelayError.tooLarge }
            let alert = try JSONDecoder().decode(RelayAlert.self, from: plaintext).validated()
            // The sender must be the one pinned for the tenant the alert names.
            guard state.pins[alert.tenant] == senderText else { throw RelayError.verificationFailed }
            if let seen {
                if seen.contains(alert.id, now: now) { throw RelayError.duplicate }
                seen.insert(alert.id, now: now)
            }
            return alert
        }
        throw state.pins.isEmpty ? RelayError.noSenderForTenant : RelayError.verificationFailed
    }

    private func decrypt(_ state: RelayState, enc: Data, ct: Data, aad: Data, sender: P256.KeyAgreement.PublicKey) throws -> Data {
        if state.enclave {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: state.keyReference)
            var r = try HPKE.Recipient(privateKey: key, ciphersuite: RelayContract.suite, info: RelayContract.info, encapsulatedKey: enc, authenticatedBy: sender)
            return try r.open(ct, authenticating: aad)
        }
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: state.keyReference)
        var r = try HPKE.Recipient(privateKey: key, ciphersuite: RelayContract.suite, info: RelayContract.info, encapsulatedKey: enc, authenticatedBy: sender)
        return try r.open(ct, authenticating: aad)
    }
}

// MARK: - a day of alert ids

/// Ids of alerts already shown, for a day, so a replayed push is dropped. Ids only; nothing
/// decrypted. A JSON file in the app group container the extension shares.
public final class RelaySeenStore: @unchecked Sendable {
    private let url: URL?
    private var entries: [String: Date] = [:]
    private let lock = NSLock()
    static let window: TimeInterval = 24 * 3600

    public init(url: URL?) {
        self.url = url
        if let url, let data = try? Data(contentsOf: url), let decoded = try? JSONDecoder().decode([String: Date].self, from: data) {
            entries = decoded
        }
    }

    func contains(_ id: String, now: Date) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if let at = entries[id], now.timeIntervalSince(at) < Self.window { return true }
        return false
    }

    func insert(_ id: String, now: Date) {
        lock.lock()
        entries = entries.filter { now.timeIntervalSince($0.value) < Self.window }
        entries[id] = now
        let snapshot = entries
        lock.unlock()
        if let url, let data = try? JSONEncoder().encode(snapshot) { try? data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]) }
    }
}

// MARK: - for tests and the reference sender

/// Seals an alert the way the customer's run does. Used by the tests and the demo; the
/// shipping sender is relay/sender/Hpke.cs.
public enum RelayTestSender {
    public static func seal(_ alert: RelayAlert, to phonePublicKey: Data, deviceToken: String, sender: P256.KeyAgreement.PrivateKey) throws -> (enc: String, ct: String) {
        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: phonePublicKey)
        var s = try HPKE.Sender(recipientKey: recipient, ciphersuite: RelayContract.suite, info: RelayContract.info, authenticatedBy: sender)
        let ct = try s.seal(try JSONEncoder().encode(alert), authenticating: Data(deviceToken.lowercased().utf8))
        return (Base64URL.encode(s.encapsulatedKey), Base64URL.encode(ct))
    }
}
