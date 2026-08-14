import Foundation
import AuthKit

// Build Spec §2.4 — macOS LAPS. REVEAL UNAVAILABLE (verified empirically 2026-08-14).
//
// ═══════════════════════════════════════════════════════════════════════════════
// HOW TO ENABLE macOS REVEAL WHEN MICROSOFT SHIPS IT
// ═══════════════════════════════════════════════════════════════════════════════
// Everything needed is in this one file. No UI, view-model, or other module changes.
//   1. Re-run tools/Verify-MacOSLapsGraph.ps1 against a live tenant.
//   2. If a documented endpoint returns a password value:
//        a. set `supportsReveal: true` in `capabilities` below
//        b. clear `unavailabilityReason`
//        c. set `usesBetaAPI` to reflect the endpoint's status (false only once GA)
//        d. implement `reveal(for:)` — replace the thrown error with the real request,
//           parsing straight into SensitiveValue exactly as WindowsLapsProvider does
//        e. put the required scope in `revealScopes`
//   3. Run the CredentialKitTests capability tests; they assert the declared shape.
//
// WHY IT'S OFF (evidence, tested against a licensed production tenant):
//   * The Entra store used by Windows LAPS returns 200 OK with NO credentials array for
//     ADE-enrolled Macs — macOS passwords are not kept there. Consistent with Microsoft's
//     "stored and encrypted by Intune" statement.
//   * The documented beta function is specified to return only
//     passwordLastRotationDateTime. There is no password field in the contract:
//     GET /beta/deviceManagement/managedDevices/{id}/retrieveDeviceLocalAdminAccountDetail
//   * That function also returns HTTP 500 from Intune's DeviceFE backend on every
//     ADE-enrolled, LAPS-managed Mac tested (multiple devices, multiple users, one
//     tenant, 2026-08-14). The portal displays these passwords, so retrieval is
//     portal-internal. Per §2.4 we do NOT ship on undocumented/internal endpoints.
// ═══════════════════════════════════════════════════════════════════════════════

public struct MacOSLapsProvider: LocalAdminCredentialProviding {
    public let platform: DevicePlatform = .macOS

    /// Rotate is implemented but OFF by default (beta API, §2.4). Callers opt in.
    public let rotateEnabled: Bool

    public var capabilities: CredentialCapabilities {
        CredentialCapabilities(
            supportsMetadata: true,      // attempted; degrades cleanly if the API 500s
            supportsReveal: false,       // ← flip to true when Microsoft ships it
            supportsRotate: rotateEnabled,
            usesBetaAPI: true,
            offersPortalHandoff: true,
            unavailabilityReason: Self.revealUnavailableReason
        )
    }

    /// User-facing copy: explain what happened and the next step, in the app's voice.
    static let revealUnavailableReason =
        "Microsoft doesn't currently offer an API for reading macOS local admin passwords. "
        + "Intune keeps them encrypted on its own service, and only the admin center can display them. "
        + "You can see the rotation schedule here and open this device in Intune to view the password."

    public let metadataScopes = [LapsCredentialScopes.intuneDevices]
    /// Empty until a documented reveal endpoint exists.
    public let revealScopes: [String] = []

    private let auth: AuthManaging
    private let session: URLSession

    public init(auth: AuthManaging, rotateEnabled: Bool = false) {
        self.auth = auth
        self.rotateEnabled = rotateEnabled
        self.session = GraphHTTP.makeSession()
    }

    // MARK: - metadata (rotation timestamp only; tolerates the current 500)

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

    // MARK: - reveal (NOT AVAILABLE — see the header block to enable)

    public func reveal(for target: DeviceCredentialTarget) async throws -> RevealedCredential {
        // Fails loudly and specifically rather than returning an empty value, so the UI
        // renders the portal handoff instead of a broken password field (§8).
        throw CredentialError.unsupportedOnPlatform(
            platform: .macOS,
            reason: Self.revealUnavailableReason
        )
    }

    // MARK: - rotate (beta, opt-in, §2.4)

    public func rotate(for target: DeviceCredentialTarget) async throws {
        guard rotateEnabled else {
            throw CredentialError.unsupportedOnPlatform(
                platform: .macOS,
                reason: "Rotating macOS passwords uses a Microsoft preview API. Turn it on in Settings to enable it."
            )
        }
        guard let managedDeviceId = target.managedDeviceId, !managedDeviceId.isEmpty else {
            throw CredentialError.missingIdentifier("Intune managed device ID is required to rotate.")
        }
        let token = try await auth.token(scopes: metadataScopes, allowInteractive: true)
        var req = URLRequest(url: GraphHTTP.url(
            version: "beta",
            path: "/deviceManagement/managedDevices/\(managedDeviceId)/rotateLocalAdminPassword"))
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (_, response) = try await session.data(for: req)
        try GraphHTTP.validate(response)
    }

    public func portalURL(for target: DeviceCredentialTarget) -> URL? {
        guard let managedDeviceId = target.managedDeviceId else { return nil }
        return URL(string: "https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mDMDeviceId/\(managedDeviceId)")
    }
}
