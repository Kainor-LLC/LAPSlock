import Foundation
import AuthKit

// Build Spec §2.3, §3.4, §6 — Windows LAPS. FULLY SUPPORTED.
//
// Reveal:  GET /v1.0/directory/deviceLocalCredentials/{entraDeviceId}?$select=credentials
//          Scope: DeviceLocalCredential.Read.All (delegated) AND the signed-in admin must
//          hold Cloud Device Administrator or Intune Service Administrator in Entra.
// Metadata: same resource without $select=credentials — needs only ReadBasic.All.
//
// This file is the ONLY Windows code path that touches a password value. It never logs
// a request or response body, and the password leaves only as a SensitiveValue.

public struct WindowsLapsProvider: LocalAdminCredentialProviding {
    public let platform: DevicePlatform = .windows

    public let capabilities = CredentialCapabilities(
        supportsMetadata: true,
        supportsReveal: true,
        supportsRotate: false,      // Windows LAPS rotates via policy/post-auth reset, not an app action
        usesBetaAPI: false,         // v1.0, GA
        offersPortalHandoff: true,  // still useful as an escape hatch on errors
        unavailabilityReason: nil
    )

    public let metadataScopes = ["DeviceLocalCredential.ReadBasic.All"]
    public let revealScopes   = ["DeviceLocalCredential.Read.All"]

    private let auth: AuthManaging
    private let session: URLSession

    public init(auth: AuthManaging) {
        self.auth = auth
        self.session = GraphHTTP.makeSession()
    }

    // MARK: - metadata (low privilege, safe pre-reveal)

    public func metadata(for target: DeviceCredentialTarget) async throws -> CredentialMetadata {
        guard let entraDeviceId = target.entraDeviceId, !entraDeviceId.isEmpty else {
            throw CredentialError.missingIdentifier("Entra device ID is required to look up Windows LAPS.")
        }
        let token = try await auth.token(scopes: metadataScopes, allowInteractive: false)
        var req = URLRequest(url: GraphHTTP.url(
            version: "v1.0",
            path: "/directory/deviceLocalCredentials/\(entraDeviceId)"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await session.data(for: req)
        try GraphHTTP.validate(response)

        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CredentialError.decodeFailure
        }
        return CredentialMetadata(
            accountName: nil,   // account name only appears on the credentials payload
            lastBackupDateTime: GraphHTTP.date(obj["lastBackupDateTime"]),
            nextRefreshDateTime: GraphHTTP.date(obj["refreshDateTime"]),
            lastRotationDateTime: GraphHTTP.date(obj["lastBackupDateTime"])
        )
    }

    // MARK: - reveal (§6 step 3; caller MUST have passed the biometric gate first)

    public func reveal(for target: DeviceCredentialTarget) async throws -> RevealedCredential {
        guard let entraDeviceId = target.entraDeviceId, !entraDeviceId.isEmpty else {
            throw CredentialError.missingIdentifier("Entra device ID is required to reveal a Windows LAPS password.")
        }
        // allowInteractive: true so first use can prompt incremental consent (§4).
        let token = try await auth.token(scopes: revealScopes, allowInteractive: true)
        var req = URLRequest(url: GraphHTTP.url(
            version: "v1.0",
            path: "/directory/deviceLocalCredentials/\(entraDeviceId)",
            query: [URLQueryItem(name: "$select", value: "credentials")]))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await session.data(for: req)
        try GraphHTTP.validate(response)

        // JSONSerialization on purpose: no Codable model ever holds the password.
        guard
            let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let credentials = obj["credentials"] as? [[String: Any]],
            !credentials.isEmpty
        else { throw CredentialError.emptyCredentialSet }

        // Password history can contain several entries; newest backupDateTime wins (§2.3).
        let newest = credentials.max {
            (GraphHTTP.date($0["backupDateTime"]) ?? .distantPast)
                < (GraphHTTP.date($1["backupDateTime"]) ?? .distantPast)
        }
        guard
            let entry = newest,
            let b64 = entry["passwordBase64"] as? String,
            let secret = SensitiveValue(base64AutoDetect: b64)
        else { throw CredentialError.decodeFailure }

        return RevealedCredential(
            accountName: entry["accountName"] as? String,
            backupDateTime: GraphHTTP.date(entry["backupDateTime"]),
            secret: secret
        )
    }

    // MARK: - rotate (not an app action on Windows)

    public func rotate(for target: DeviceCredentialTarget) async throws {
        throw CredentialError.unsupportedOnPlatform(
            platform: .windows,
            reason: "Windows LAPS rotates on its own schedule, and after each use when post-authentication reset is enabled in policy. There's nothing to trigger here."
        )
    }

    public func portalURL(for target: DeviceCredentialTarget) -> URL? {
        guard let managedDeviceId = target.managedDeviceId else { return nil }
        return URL(string: "https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mDMDeviceId/\(managedDeviceId)")
    }
}
