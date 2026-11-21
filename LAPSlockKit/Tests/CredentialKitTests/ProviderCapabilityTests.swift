import XCTest
import AuthKit
@testable import CredentialKit

// Build Spec §13, capability/platform contract tests. No Microsoft dependency.
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

    /// Pinned on both sides: InventoryKit writes the same string out rather than import it,
    /// so that the inventory, and the Mac menu bar app with it, never links this module.
    func test_theIntuneDeviceReadScopeIsTheInventorysScope() {
        XCTAssertEqual(LapsCredentialScopes.intuneDevices, "DeviceManagementManagedDevices.Read.All")
    }

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

    // MARK: - macOS: reveal behind the Settings switch (reopened 2026-11-08)

    func test_macOS_switchOff_declaresRevealUnsupported_withReason() {
        let p = MacOSLapsProvider(auth: FakeAuth())
        XCTAssertFalse(p.capabilities.supportsReveal, "Off unless the switch is on: the API is beta.")
        XCTAssertNotNil(p.capabilities.unavailabilityReason)
        XCTAssertTrue(p.capabilities.offersPortalHandoff, "Admins must still have a route to the password.")
        XCTAssertTrue(p.capabilities.usesBetaAPI)
    }

    func test_macOS_switchOn_declaresBetaReveal() {
        let p = MacOSLapsProvider(auth: FakeAuth(), revealEnabled: { true })
        XCTAssertTrue(p.capabilities.supportsReveal)
        XCTAssertTrue(p.capabilities.usesBetaAPI, "The UI must say the Mac reveal rides a beta API.")
        XCTAssertNil(p.capabilities.unavailabilityReason)
    }

    func test_macOS_revealScopeIsTheOneTheFunctionAccepts() {
        let p = MacOSLapsProvider(auth: FakeAuth())
        XCTAssertEqual(p.revealScopes, ["DeviceManagementManagedDevices.PrivilegedOperations.All"])
        // DeviceActionsTests pins DeviceActionsKit's copy to the same literal.
        XCTAssertEqual(LapsCredentialScopes.macOSReveal, "DeviceManagementManagedDevices.PrivilegedOperations.All")
        XCTAssertFalse(LapsCredentialScopes.signInBaseline.contains(LapsCredentialScopes.macOSReveal),
                       "Requested at the switch, never at sign-in.")
    }

    func test_macOS_switchOff_revealThrowsUnsupported_beforeAnyRequest() async {
        let auth = CountingAuth()
        let p = MacOSLapsProvider(auth: auth)
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
        let asked = await auth.count
        XCTAssertEqual(asked, 0, "No token, so no consent prompt and no request, while the switch is off.")
    }

    func test_macOS_revealRequiresManagedDeviceId() async {
        let p = MacOSLapsProvider(auth: FakeAuth(), revealEnabled: { true })
        let target = DeviceCredentialTarget(platform: .macOS, entraDeviceId: "e1", managedDeviceId: nil)
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

    func test_coordinator_passesTheSwitchToTheMacProvider() async {
        let on = CredentialCoordinator(auth: FakeAuth(), macOSRevealEnabled: { true })
        let mac = await on.capabilities(for: .macOS)
        XCTAssertTrue(mac.supportsReveal)
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

// MARK: - test doubles

/// Counts token requests, to prove a refused reveal never reaches the token cache.
private actor CountingAuth: AuthManaging {
    private(set) var count = 0
    var currentAccount: AdminAccount? {
        get async { AdminAccount(id: "acct", tenantId: "tenant-1", username: "admin@example.com") }
    }
    func token(scopes: [String], allowInteractive: Bool) async throws -> String { count += 1; return "fake-token" }
    func signIn() async throws -> AdminAccount {
        AdminAccount(id: "acct", tenantId: "tenant-1", username: "admin@example.com")
    }
    func signOut(account: AdminAccount) async throws {}
}

/// Minimal AuthManaging stand-in. Proves CredentialKit is testable with zero
/// Microsoft dependencies, the payoff of the AuthKit protocol seam.
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

final class TemporaryAccessPassParseTests: XCTestCase {
    func test_thePassGoesIntoASensitiveValue() throws {
        let body = #"{"id":"x","temporaryAccessPass":"+drkzqAD","lifetimeInMinutes":60,"isUsableOnce":true,"startDateTime":"2026-10-26T12:00:00Z"}"#
        let issued = try TemporaryAccessPassService.parse(Data(body.utf8))
        XCTAssertEqual(issued.pass.withValue { $0 }, "+drkzqAD")
        XCTAssertEqual(issued.lifetimeMinutes, 60)
        XCTAssertTrue(issued.isUsableOnce)
        issued.pass.wipe()
        XCTAssertTrue(issued.pass.isWiped)
    }

    func test_aResponseWithoutAPassIsADecodeFailure() {
        XCTAssertThrowsError(try TemporaryAccessPassService.parse(Data(#"{"id":"x"}"#.utf8)))
    }

    func test_lifetimeBoundsAreMicrosofts() {
        XCTAssertEqual(TemporaryAccessPassService.lifetimeRange, 10...43_200)
        XCTAssertEqual(TemporaryAccessPassService.scope, "UserAuthMethod-TAP.ReadWrite.All")
    }
}
