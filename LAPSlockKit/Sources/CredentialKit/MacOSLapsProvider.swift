import Foundation
import AuthKit

// Build Spec §2.4, macOS LAPS. Reveal is behind a Settings switch, off by default.
//
// History, because the answer changed:
//   * 2026-08: the only macOS function tried, retrieveDeviceLocalAdminAccountDetail, is
//     documented to return passwordLastRotationDateTime and nothing else, and it answered
//     HTTP 500 for every ADE-enrolled Mac tested. The Entra store Windows LAPS uses holds
//     nothing for Macs. Reveal was declared unavailable.
//   * 2026-11-08: Microsoft pointed to a different function, which does return the
//     password (MACOS-REVEAL-PLAN.md in the private repo):
//     GET /beta/deviceManagement/managedDevices/{id}/retrieveMacOSManagedDeviceLocalAdminAccountDetail
//     → { "value": { "adminAccountPassword": "…", "passwordLastRotatedDateTime": "…" } }
//     Delegated DeviceManagementManagedDevices.PrivilegedOperations.All, the only
//     permission listed. The password is created when the Mac enrolls through Automated
//     Device Enrollment with the local admin account in its enrollment profile.
//
// It is beta, so reveal is off until the admin turns it on, and the switch is where the
// permission is asked for. `revealEnabled` is read every time capabilities are, so the
// switch takes effect on the next device opened without rebuilding the session.
//
// (verify) on a real ADE-enrolled Mac, tools/Verify-MacOSLapsGraph.ps1 probe D: the
// response shape, and whether Graph also requires the custom Intune role (Enrollment
// programs, View macOS admin password) that the admin center does.

public struct MacOSLapsProvider: LocalAdminCredentialProviding {
    public let platform: DevicePlatform = .macOS

    public var capabilities: CredentialCapabilities {
        revealEnabled()
            ? CredentialCapabilities(
                supportsMetadata: true,      // attempted; degrades cleanly if the API 500s
                supportsReveal: true,
                usesBetaAPI: true,
                offersPortalHandoff: true,
                unavailabilityReason: nil)
            : CredentialCapabilities(
                supportsMetadata: true,
                supportsReveal: false,
                usesBetaAPI: true,
                offersPortalHandoff: true,
                unavailabilityReason: Self.revealOffReason)
    }

    /// User-facing copy for the switch being off: what happened and the next step.
    static let revealOffReason =
        "Revealing Mac passwords is off. Turn it on in Settings, Actions and Permissions. "
        + "You can also open this device in Intune to view the password there."

    public let metadataScopes = [LapsCredentialScopes.intuneDevices]
    public let revealScopes = [LapsCredentialScopes.macOSReveal]

    private let auth: AuthManaging
    private let session: URLSession
    private let revealEnabled: @Sendable () -> Bool

    /// `revealEnabled` is the Settings switch. Defaults to off, so anything built without
    /// it (the coordinator's default, tests) cannot reveal a Mac password by accident.
    public init(auth: AuthManaging, revealEnabled: @escaping @Sendable () -> Bool = { false }) {
        self.auth = auth
        self.session = GraphHTTP.makeSession()
        self.revealEnabled = revealEnabled
    }

    // MARK: - metadata (rotation timestamp only; tolerates the current 500)

    /// The old function, on purpose. The new one returns the password, and Intune logs it
    /// as a view, so it is never called just for a date. (verify) in M0 whether this still
    /// 500s; if it does, `supportsMetadata` goes false and the date comes from the reveal.
    public func metadata(for target: DeviceCredentialTarget) async throws -> CredentialMetadata {
        guard let managedDeviceId = target.managedDeviceId, !managedDeviceId.isEmpty else {
            throw CredentialError.missingIdentifier("Intune managed device ID is required for macOS.")
        }
        let token = try await auth.token(scopes: metadataScopes, allowInteractive: false)
        var req = URLRequest(url: GraphHTTP.url(
            version: "beta",
            path: "/deviceManagement/managedDevices/\(managedDeviceId)/retrieveDeviceLocalAdminAccountDetail"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await session.data(for: req)
        // Deliberately NOT swallowed: a 500 surfaces as .serviceUnavailable so the UI can
        // say "Intune isn't returning this right now" instead of showing a blank field.
        try GraphHTTP.validate(response)

        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CredentialError.decodeFailure
        }
        // Documented shape is { "value": { ... } }; tolerate a bare object too.
        let obj = (root["value"] as? [String: Any]) ?? root
        return CredentialMetadata(
            accountName: obj["accountName"] as? String,
            lastBackupDateTime: nil,
            nextRefreshDateTime: nil,
            lastRotationDateTime: GraphHTTP.date(obj["passwordLastRotationDateTime"])
        )
    }

    // MARK: - reveal (§6 step 3; caller MUST have passed the biometric gate first)

    public func reveal(for target: DeviceCredentialTarget) async throws -> RevealedCredential {
        // Checked here as well as in the coordinator and the view model: the app holds this
        // provider directly, and the switch is the only thing standing in front of a beta API.
        guard revealEnabled() else {
            throw CredentialError.unsupportedOnPlatform(platform: .macOS, reason: Self.revealOffReason)
        }
        guard let managedDeviceId = target.managedDeviceId, !managedDeviceId.isEmpty else {
            throw CredentialError.missingIdentifier("Intune managed device ID is required for macOS.")
        }
        // allowInteractive: true so a first reveal can still prompt consent if the switch's
        // own prompt was skipped (another organization, a revoked grant).
        let token = try await auth.token(scopes: revealScopes, allowInteractive: true)
        var req = URLRequest(url: GraphHTTP.url(
            version: "beta",
            path: "/deviceManagement/managedDevices/\(managedDeviceId)/retrieveMacOSManagedDeviceLocalAdminAccountDetail"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await session.data(for: req)
        try GraphHTTP.validate(response)

        // JSONSerialization on purpose: no Codable model ever holds the password.
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CredentialError.decodeFailure
        }
        return try Self.credential(from: obj)
    }

    /// Parses the function's answer. Static and pure so every branch is tested without a
    /// tenant.
    ///
    /// One value, no history: Intune keeps only the current password for a Mac. No account
    /// name either; it is set in the enrollment profile, not returned here.
    static func credential(from root: [String: Any]) throws -> RevealedCredential {
        // Documented shape is { "value": { ... } }; tolerate a bare object too, as metadata does.
        let obj = (root["value"] as? [String: Any]) ?? root
        guard let password = obj["adminAccountPassword"] as? String else {
            throw CredentialError.emptyCredentialSet
        }
        guard !password.isEmpty else { throw CredentialError.emptyCredentialSet }
        return RevealedCredential(
            accountName: nil,
            backupDateTime: GraphHTTP.date(obj["passwordLastRotatedDateTime"]),
            secret: SensitiveValue(bytes: Array(password.utf8), encoding: .utf8))
    }

    public func portalURL(for target: DeviceCredentialTarget) -> URL? {
        guard let managedDeviceId = target.managedDeviceId else { return nil }
        return URL(string: "https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mDMDeviceId/\(managedDeviceId)")
    }
}
