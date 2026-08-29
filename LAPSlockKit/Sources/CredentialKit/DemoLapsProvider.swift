import Foundation
import AuthKit

// Demo credential provider. Used by SwiftUI previews, UI development without a tenant,
// and App Store review (Guideline 2.1).
//
// SAFETY RULES FOR DEMO CREDENTIALS
//   1. Values must be OBVIOUSLY fake. A reviewer, a colleague looking over a shoulder,
//      or a screenshot in a bug report must never leave anyone unsure whether they saw
//      a real administrator password. Hence the literal "DEMO" prefix.
//   2. Demo mode must be visibly labeled in the UI, not just internally. That is the
//      view layer's job; this type exposes `isDemo` so it can't be forgotten silently.
//   3. This provider performs NO network calls and never touches AuthManaging, so it
//      cannot accidentally reach a real tenant even if wired up wrong.
//
// It still flows through SensitiveValue and the same reveal path as production, so the
// wipe-on-hide and auto-hide behavior are exercised for real rather than bypassed.

public struct DemoLapsProvider: LocalAdminCredentialProviding {
    public let platform: DevicePlatform

    /// Matches the real providers' declared capabilities so the demo exercises the same
    /// UI branches — including macOS reveal being unavailable.
    public var capabilities: CredentialCapabilities {
        switch platform {
        case .windows:
            return CredentialCapabilities(
                supportsMetadata: true, supportsReveal: true, supportsRotate: false,
                usesBetaAPI: false, offersPortalHandoff: true, unavailabilityReason: nil
            )
        case .macOS:
            return CredentialCapabilities(
                supportsMetadata: true, supportsReveal: false, supportsRotate: false,
                usesBetaAPI: true, offersPortalHandoff: true,
                unavailabilityReason: MacOSLapsProvider.revealUnavailableReason
            )
        case .other:
            return CredentialCapabilities(
                supportsMetadata: false, supportsReveal: false, supportsRotate: false,
                usesBetaAPI: false, offersPortalHandoff: false,
                unavailabilityReason: "LAPSlock manages local administrator passwords on Windows and macOS devices only."
            )
        }
    }

    /// True so the UI can display a persistent demo banner. Never conditional.
    public let isDemo = true

    public let metadataScopes: [String] = []
    public let revealScopes: [String] = []

    /// Simulated latency so loading and gate states are visible during development.
    private let latency: Duration

    public init(platform: DevicePlatform, latency: Duration = .milliseconds(600)) {
        self.platform = platform
        self.latency = latency
    }

    public func metadata(for target: DeviceCredentialTarget) async throws -> CredentialMetadata {
        try await Task.sleep(for: latency)
        switch platform {
        case .windows:
            // accountName is deliberately nil here, matching production: Windows LAPS
            // only returns the account name inside the `credentials` payload, which
            // requires the high-privilege reveal scope. It appears after the first
            // reveal, not before. Demo fidelity beats a fuller-looking demo.
            return CredentialMetadata(
                accountName: nil,
                lastBackupDateTime: Date().addingTimeInterval(-6 * 3600),
                nextRefreshDateTime: Date().addingTimeInterval(24 * 3600),
                lastRotationDateTime: Date().addingTimeInterval(-6 * 3600)
            )
        case .macOS:
            // Also nil: the documented beta resource carries only
            // passwordLastRotationDateTime.
            return CredentialMetadata(
                accountName: nil,
                lastRotationDateTime: Date().addingTimeInterval(-11 * 86_400)
            )
        case .other:
            throw CredentialError.unsupportedOnPlatform(
                platform: platform,
                reason: capabilities.unavailabilityReason ?? "Unsupported device."
            )
        }
    }

    public func reveal(for target: DeviceCredentialTarget) async throws -> RevealedCredential {
        guard capabilities.supportsReveal else {
            throw CredentialError.unsupportedOnPlatform(
                platform: platform,
                reason: capabilities.unavailabilityReason ?? "Reveal isn't available for this device."
            )
        }
        guard target.entraDeviceId != nil else {
            throw CredentialError.missingIdentifier(
                "This device isn't joined to Microsoft Entra ID, so Windows LAPS can't store a password for it."
            )
        }
        try await Task.sleep(for: latency)

        // Deterministic per device so the same device shows the same value across
        // reveals, and unmistakably fake either way.
        let suffix = String(abs(target.managedDeviceId?.hashValue ?? 0) % 10_000)
        let fake = "DEMO-Not-A-Real-Password-\(String(format: "%04d", Int(suffix) ?? 0))"

        guard let secret = SensitiveValue(base64: Data(fake.utf8).base64EncodedString(), encoding: .utf8) else {
            throw CredentialError.decodeFailure
        }
        return RevealedCredential(
            // Deliberately not "Administrator": LAPS account names vary by policy, and
            // the UI must not train anyone to expect a particular one.
            accountName: "LapsAdmin",
            backupDateTime: Date().addingTimeInterval(-6 * 3600),
            secret: secret
        )
    }

    public func rotate(for target: DeviceCredentialTarget) async throws {
        try await Task.sleep(for: latency)
        // Succeeds silently in demo mode. Nothing to rotate, and pretending otherwise
        // would misrepresent what the real action does.
    }

    public func portalURL(for target: DeviceCredentialTarget) -> URL? {
        URL(string: "https://intune.microsoft.com")
    }
}
