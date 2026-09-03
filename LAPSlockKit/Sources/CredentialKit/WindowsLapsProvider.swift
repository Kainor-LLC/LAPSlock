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

    public let metadataScopes = [LapsCredentialScopes.metadataBasic]
    public let revealScopes   = [LapsCredentialScopes.reveal]

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
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CredentialError.decodeFailure
        }
        return try Self.credential(from: obj)
    }

    /// Most versions of one device's password to return.
    ///
    /// **A defensive ceiling of ours, not a Microsoft limit.** Each version returned is
    /// another live secret held in memory for the reveal window, so a pathological response
    /// must not be able to multiply that without bound. Newest-first ordering means the cap
    /// drops the least useful end.
    static let maxVersions = 10

    /// Parses the `credentials` payload into the current password and its history.
    ///
    /// Static and pure so every branch is covered without a tenant — ordering, entries
    /// missing a date, entries missing a password. That matters more here than almost
    /// anywhere else in the app: **this function decides which password an admin is shown**,
    /// and showing the wrong one sends them to a console with a credential that fails.
    ///
    /// Graph returns the whole `credentials` collection in one response. The previous
    /// version discarded everything but the newest, which is why history looked like a
    /// feature needing new requests when it needed none.
    static func credential(from obj: [String: Any]) throws -> RevealedCredential {
        guard
            let credentials = obj["credentials"] as? [[String: Any]],
            !credentials.isEmpty
        else { throw CredentialError.emptyCredentialSet }

        // An entry whose password will not decode is DROPPED rather than surfaced as a
        // blank row: a version an admin cannot read is worse than one they cannot see,
        // because they would try it.
        let versions = credentials.compactMap { entry -> CredentialVersion? in
            guard
                let b64 = entry["passwordBase64"] as? String,
                let secret = SensitiveValue(base64AutoDetect: b64)
            else { return nil }
            return CredentialVersion(
                accountName: entry["accountName"] as? String,
                backupDateTime: GraphHTTP.date(entry["backupDateTime"]),
                secret: secret)
        }
        // Newest first. An entry with no date sorts last rather than winning by accident —
        // `.distantPast` is deliberate, because treating an undated entry as newest would
        // put an unknown password in front of a known-current one.
        .sorted { ($0.backupDateTime ?? .distantPast) > ($1.backupDateTime ?? .distantPast) }
        .prefix(maxVersions)

        guard let current = versions.first else { throw CredentialError.decodeFailure }

        return RevealedCredential(
            accountName: current.accountName,
            backupDateTime: current.backupDateTime,
            secret: current.secret,
            previousVersions: Array(versions.dropFirst())
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
