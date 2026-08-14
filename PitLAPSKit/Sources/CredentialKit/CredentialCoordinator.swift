import Foundation
import AuthKit

// Build Spec §3.4, §6 — the single entry point the rest of the app talks to.
//
// The app never instantiates a platform provider or branches on OS. It asks the
// coordinator, which resolves the provider from the device's platform. Adding a
// platform (or enabling a capability) touches only this registry and that provider.

public actor CredentialCoordinator {
    private let providers: [DevicePlatform: any LocalAdminCredentialProviding]

    public init(auth: AuthManaging, macRotateEnabled: Bool = false) {
        self.providers = [
            .windows: WindowsLapsProvider(auth: auth),
            .macOS: MacOSLapsProvider(auth: auth, rotateEnabled: macRotateEnabled)
        ]
    }

    /// Test/DI seam.
    public init(providers: [DevicePlatform: any LocalAdminCredentialProviding]) {
        self.providers = providers
    }

    /// What the UI should offer for this device. Drives the whole credential section:
    /// an unsupported platform yields supportsReveal == false plus a reason string,
    /// so the view renders an explanation and a portal button rather than a dead button.
    public func capabilities(for platform: DevicePlatform) -> CredentialCapabilities {
        providers[platform]?.capabilities ?? CredentialCapabilities(
            supportsMetadata: false,
            supportsReveal: false,
            supportsRotate: false,
            usesBetaAPI: false,
            offersPortalHandoff: false,
            unavailabilityReason: "PitLAPS doesn't manage local admin passwords on this kind of device."
        )
    }

    public func metadata(for target: DeviceCredentialTarget) async throws -> CredentialMetadata {
        try await provider(for: target.platform).metadata(for: target)
    }

    /// Reveal. The caller MUST have completed the biometric gate first (§6 step 2) —
    /// this layer performs no UI and cannot verify it, so that ordering is the
    /// view model's contract.
    public func reveal(for target: DeviceCredentialTarget) async throws -> RevealedCredential {
        let p = try provider(for: target.platform)
        guard p.capabilities.supportsReveal else {
            throw CredentialError.unsupportedOnPlatform(
                platform: target.platform,
                reason: p.capabilities.unavailabilityReason ?? "Revealing passwords isn't available for this device."
            )
        }
        return try await p.reveal(for: target)
    }

    public func rotate(for target: DeviceCredentialTarget) async throws {
        try await provider(for: target.platform).rotate(for: target)
    }

    public func portalURL(for target: DeviceCredentialTarget) -> URL? {
        guard let p = providers[target.platform] else { return nil }
        return p.portalURL(for: target)
    }

    /// Scopes to request at sign-in across all providers (browse/metadata tier, §4).
    public func baselineMetadataScopes() -> [String] {
        Array(Set(providers.values.flatMap { $0.metadataScopes })).sorted()
    }

    private func provider(for platform: DevicePlatform) throws -> any LocalAdminCredentialProviding {
        guard let p = providers[platform] else {
            throw CredentialError.unsupportedOnPlatform(
                platform: platform,
                reason: "PitLAPS doesn't manage local admin passwords on this kind of device."
            )
        }
        return p
    }
}
