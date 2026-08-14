import XCTest
import AuthKit
@testable import CredentialKit

// Build Spec §13 — capability/platform contract tests. No Microsoft dependency.
// These lock in the macOS decision so it can't silently regress, and they are the
// tests to update when macOS reveal becomes available.

final class ProviderCapabilityTests: XCTestCase {

    // MARK: - platform mapping from the Intune operatingSystem string

    func test_platformMapping() {
        XCTAssertEqual(DevicePlatform(intuneOperatingSystem: "Windows"), .windows)
        XCTAssertEqual(DevicePlatform(intuneOperatingSystem: "windows"), .windows)
        XCTAssertEqual(DevicePlatform(intuneOperatingSystem: "macOS"), .macOS)
        XCTAssertEqual(DevicePlatform(intuneOperatingSystem: "Mac OS X"), .macOS)
        XCTAssertEqual(DevicePlatform(intuneOperatingSystem: "iOS"), .other)
        XCTAssertEqual(DevicePlatform(intuneOperatingSystem: nil), .other)
        XCTAssertEqual(DevicePlatform(intuneOperatingSystem: ""), .other)
    }

    // MARK: - Windows: fully supported

    func test_windows_declaresRevealSupported() {
        let p = WindowsLapsProvider(auth: FakeAuth())
        XCTAssertTrue(p.capabilities.supportsReveal)
        XCTAssertTrue(p.capabilities.supportsMetadata)
        XCTAssertFalse(p.capabilities.usesBetaAPI, "Windows reveal must stay on documented v1.0")
        XCTAssertNil(p.capabilities.unavailabilityReason)
        XCTAssertEqual(p.revealScopes, ["DeviceLocalCredential.Read.All"])
    }

    func test_windows_revealRequiresEntraDeviceId() async {
        let p = WindowsLapsProvider(auth: FakeAuth())
        let target = DeviceCredentialTarget(platform: .windows, entraDeviceId: nil, managedDeviceId: "abc")
        do {
            _ = try await p.reveal(for: target)
            XCTFail("expected missingIdentifier")
        } catch let error as CredentialError {
            guard case .missingIdentifier = error else {
                return XCTFail("expected missingIdentifier, got \(error)")
            }
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    // MARK: - macOS: reveal unavailable (verified 2026-08-14)

    func test_macOS_declaresRevealUnsupported_withReason() {
        let p = MacOSLapsProvider(auth: FakeAuth())
        XCTAssertFalse(p.capabilities.supportsReveal,
                       "No documented Graph endpoint returns a macOS LAPS password value.")
        XCTAssertNotNil(p.capabilities.unavailabilityReason)
        XCTAssertTrue(p.capabilities.offersPortalHandoff,
                      "Admins must still have a route to the password.")
        XCTAssertTrue(p.revealScopes.isEmpty,
                      "Don't request a high-privilege scope for a capability we can't perform.")
    }

    func test_macOS_revealThrowsUnsupported() async {
        let p = MacOSLapsProvider(auth: FakeAuth())
        let target = DeviceCredentialTarget(platform: .macOS, entraDeviceId: "e1", managedDeviceId: "m1")
        do {
            _ = try await p.reveal(for: target)
            XCTFail("expected unsupportedOnPlatform")
        } catch let error as CredentialError {
            guard case .unsupportedOnPlatform(let platform, let reason) = error else {
                return XCTFail("expected unsupportedOnPlatform, got \(error)")
            }
            XCTAssertEqual(platform, .macOS)
            XCTAssertFalse(reason.isEmpty, "The UI shows this text; it must never be empty.")
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func test_macOS_rotateOffByDefault() async {
        let p = MacOSLapsProvider(auth: FakeAuth())
        XCTAssertFalse(p.capabilities.supportsRotate, "Beta API must be opt-in (§2.4)")
        let target = DeviceCredentialTarget(platform: .macOS, entraDeviceId: nil, managedDeviceId: "m1")
        do {
            try await p.rotate(for: target)
            XCTFail("expected rotate to be disabled")
        } catch let error as CredentialError {
            guard case .unsupportedOnPlatform = error else {
                return XCTFail("expected unsupportedOnPlatform, got \(error)")
            }
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func test_macOS_rotateEnabledFlagFlipsCapability() {
        let p = MacOSLapsProvider(auth: FakeAuth(), rotateEnabled: true)
        XCTAssertTrue(p.capabilities.supportsRotate)
        XCTAssertTrue(p.capabilities.usesBetaAPI, "UI must warn that rotate rides a preview API.")
    }

    // MARK: - coordinator routing

    func test_coordinator_routesByPlatform() async {
        let c = CredentialCoordinator(auth: FakeAuth())
        let win = await c.capabilities(for: .windows)
        let mac = await c.capabilities(for: .macOS)
        let other = await c.capabilities(for: .other)

        XCTAssertTrue(win.supportsReveal)
        XCTAssertFalse(mac.supportsReveal)
        XCTAssertFalse(other.supportsReveal)
        XCTAssertNotNil(other.unavailabilityReason)
    }

    func test_coordinator_blocksRevealOnUnsupportedPlatform() async {
        let c = CredentialCoordinator(auth: FakeAuth())
        let target = DeviceCredentialTarget(platform: .macOS, entraDeviceId: "e1", managedDeviceId: "m1")
        do {
            _ = try await c.reveal(for: target)
            XCTFail("coordinator must refuse reveal when the provider declares it unsupported")
        } catch let error as CredentialError {
            guard case .unsupportedOnPlatform = error else {
                return XCTFail("expected unsupportedOnPlatform, got \(error)")
            }
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func test_coordinator_baselineScopes_excludeHighPrivilege() async {
        let c = CredentialCoordinator(auth: FakeAuth())
        let scopes = await c.baselineMetadataScopes()
        XCTAssertFalse(scopes.contains("DeviceLocalCredential.Read.All"),
                       "The reveal scope must be requested incrementally, not at sign-in (§4).")
        XCTAssertTrue(scopes.contains("DeviceLocalCredential.ReadBasic.All"))
    }
}

// MARK: - test double

/// Minimal AuthManaging stand-in. Proves CredentialKit is testable with zero
/// Microsoft dependencies — the payoff of the AuthKit protocol seam.
private struct FakeAuth: AuthManaging {
    var currentAccount: AdminAccount? {
        get async { AdminAccount(id: "acct", tenantId: "tenant-1", username: "admin@example.com") }
    }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String { "fake-token" }
    func signIn() async throws -> AdminAccount {
        AdminAccount(id: "acct", tenantId: "tenant-1", username: "admin@example.com")
    }
    func signOut(account: AdminAccount) async throws {}
}
