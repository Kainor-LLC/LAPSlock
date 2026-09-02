import Foundation
import AuthKit

// Live BitLocker recovery key retrieval, and the demo double.
//
// Same rules as the LAPS path: ephemeral session, JSONSerialization (so no Codable model
// ever holds key material), key parsed straight into SensitiveValue, nothing logged.

public struct BitLockerService: BitLockerKeyProviding {
    /// ReadBasic is enough to LIST keys without values — request the cheaper scope for
    /// the cheaper operation so a tenant can allow browsing without allowing retrieval.
    public let listScopes = [LapsCredentialScopes.bitLockerKeysBasic]
    /// Retrieving an actual key needs the full scope, requested incrementally on first
    /// reveal exactly like the LAPS password scope (§4).
    public let revealScopes = [LapsCredentialScopes.bitLockerKeys]

    private let auth: AuthManaging
    private let session: URLSession

    public init(auth: AuthManaging) {
        self.auth = auth
        self.session = GraphHTTP.makeSession()
    }

    // MARK: - list (no key material)

    public func keys(forEntraDeviceId entraDeviceId: String) async throws -> [BitLockerKeyInfo] {
        guard !entraDeviceId.isEmpty else {
            throw CredentialError.missingIdentifier(
                "This device has no Microsoft Entra ID device record, so BitLocker recovery keys can't be looked up for it."
            )
        }
        let token = try await auth.token(scopes: listScopes, allowInteractive: false)

        // $filter on deviceId is supported here. $top is NOT supported by this endpoint,
        // so no page size is requested.
        var req = URLRequest(url: GraphHTTP.url(
            version: "v1.0",
            path: "/informationProtection/bitlocker/recoveryKeys",
            query: [URLQueryItem(name: "$filter", value: "deviceId eq '\(entraDeviceId)'")]))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await session.data(for: req)
        try GraphHTTP.validate(response)

        guard
            let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let value = root["value"] as? [[String: Any]]
        else { throw CredentialError.decodeFailure }

        // Newest first within each volume type, OS volume first overall — an admin at a
        // recovery prompt is almost always looking at the OS drive.
        return value
            .compactMap { BitLockerKeyInfo(graphEntry: $0) }
            .sorted { a, b in
                if a.volumeType.sortPriority != b.volumeType.sortPriority {
                    return a.volumeType.sortPriority < b.volumeType.sortPriority
                }
                return (a.createdDateTime ?? .distantPast) > (b.createdDateTime ?? .distantPast)
            }
    }

    // MARK: - reveal (key material)

    public func reveal(keyId: String, info: BitLockerKeyInfo) async throws -> RevealedRecoveryKey {
        guard !keyId.isEmpty else {
            throw CredentialError.missingIdentifier("Missing recovery key identifier.")
        }
        // allowInteractive so first use can prompt incremental consent for the full scope.
        let token = try await auth.token(scopes: revealScopes, allowInteractive: true)

        // The `key` property is returned ONLY when explicitly selected. Selecting it also
        // generates a Microsoft Entra audit entry, which is the behavior we want.
        var req = URLRequest(url: GraphHTTP.url(
            version: "v1.0",
            path: "/informationProtection/bitlocker/recoveryKeys/\(keyId)",
            query: [URLQueryItem(name: "$select", value: "key")]))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await session.data(for: req)
        try GraphHTTP.validate(response)

        guard
            let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let keyString = obj["key"] as? String,
            !keyString.isEmpty
        else { throw CredentialError.emptyCredentialSet }

        // Recovery keys arrive as plain text (not base64 like LAPS), so wrap the UTF-8
        // bytes directly rather than round-tripping through a decoder.
        let secret = SensitiveValue(bytes: [UInt8](keyString.utf8), encoding: .utf8)
        return RevealedRecoveryKey(info: info, secret: secret)
    }

    // MARK: - rotate (write scope, opt-in)

    public let rotateScopes = [LapsCredentialScopes.deviceWrite]

    /// POST /beta/deviceManagement/managedDevices/{id}/rotateBitLockerKeys
    ///
    /// Beta API, and it needs a WRITE scope, so it is only reachable when the user has
    /// explicitly enabled rotation in Settings. Asynchronous by nature: Intune queues the
    /// action and the device performs it on its next check-in, which may be a while if the
    /// machine is offline. Callers must report "requested", not "rotated".
    public func rotateKeys(managedDeviceId: String) async throws {
        guard !managedDeviceId.isEmpty else {
            throw CredentialError.missingIdentifier("Missing Intune device identifier.")
        }
        let token = try await auth.token(scopes: rotateScopes, allowInteractive: true)
        var req = URLRequest(url: GraphHTTP.url(
            version: "beta",
            path: "/deviceManagement/managedDevices/\(managedDeviceId)/rotateBitLockerKeys"))
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (_, response) = try await session.data(for: req)
        try GraphHTTP.validate(response)
    }
}

// MARK: - demo

/// Demo double. Keys are formatted like real BitLocker keys (eight groups of six digits)
/// so the layout is exercised honestly, but every group is a repeated digit so no one can
/// mistake one for a real key.
public struct DemoBitLockerService: BitLockerKeyProviding {
    public let listScopes: [String] = []
    public let revealScopes: [String] = []

    private let latency: Duration

    public init(latency: Duration = .milliseconds(500)) {
        self.latency = latency
    }

    public func keys(forEntraDeviceId entraDeviceId: String) async throws -> [BitLockerKeyInfo] {
        guard !entraDeviceId.isEmpty else {
            throw CredentialError.missingIdentifier(
                "This device has no Microsoft Entra ID device record, so BitLocker recovery keys can't be looked up for it."
            )
        }
        try await Task.sleep(for: latency)

        // Two volumes and an older superseded OS key: the realistic shape that makes
        // "which key do I need?" a real question the UI has to answer.
        return [
            BitLockerKeyInfo(
                id: "demo1111-1111-1111-1111-111111111111",
                volumeType: .operatingSystemVolume,
                createdDateTime: Date().addingTimeInterval(-14 * 86_400),
                deviceId: entraDeviceId
            ),
            BitLockerKeyInfo(
                id: "demo2222-2222-2222-2222-222222222222",
                volumeType: .fixedDataVolume,
                createdDateTime: Date().addingTimeInterval(-14 * 86_400),
                deviceId: entraDeviceId
            ),
            BitLockerKeyInfo(
                id: "demo3333-3333-3333-3333-333333333333",
                volumeType: .operatingSystemVolume,
                createdDateTime: Date().addingTimeInterval(-190 * 86_400),
                deviceId: entraDeviceId
            )
        ]
    }

    public let rotateScopes: [String] = []

    public func rotateKeys(managedDeviceId: String) async throws {
        try await Task.sleep(for: latency)
        // Succeeds silently. Nothing to rotate in demo mode, and faking a state change
        // would misrepresent what the real action does.
    }

    public func reveal(keyId: String, info: BitLockerKeyInfo) async throws -> RevealedRecoveryKey {
        try await Task.sleep(for: latency)
        // Real keys are 48 digits in eight hyphenated groups of six. Repeated digits make
        // this unmistakably fake while preserving the exact shape and length.
        let digest = demoStableHash(keyId)
        let groups = (0..<8).map { i in
            String(repeating: String((digest >> (UInt64(i) * 4)) % 9 + 1), count: 6)
        }
        let fake = groups.joined(separator: "-")
        let secret = SensitiveValue(bytes: [UInt8](fake.utf8), encoding: .utf8)
        return RevealedRecoveryKey(info: info, secret: secret)
    }
}
