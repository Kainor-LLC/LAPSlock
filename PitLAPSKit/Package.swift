// swift-tools-version: 5.9
// PitLAPSKit — module boundaries per Build Spec §3.1.
//
// THE CRITICAL RULE (§3.1): CredentialKit depends on AuthKit + Foundation ONLY.
// Adding a licensing module, any analytics SDK, or any logging framework to
// CredentialKit must remain a COMPILE ERROR. This is the primary defense against
// accidental credential exfiltration and must survive refactors.
// Enforced twice: here, and by scripts/isolation-check.sh in CI.
//
// WHY MSAL LIVES IN ITS OWN TARGET (AuthKitMSAL):
//   1. CredentialKit's link graph contains no third-party binary at all — the
//      credential path depends only on the AuthManaging protocol.
//   2. The test suite builds and runs with zero network access and zero
//      Microsoft dependencies, so tests are fast and deterministic.
//   3. MSAL API drift can only break one target, never the security core.
//
// WHY macOS IS IN `platforms` FOR AN iOS APP:
//   The shipping product is iOS-only. macOS is declared solely so the test suite can
//   run on the "My Mac" destination (much faster than booting a simulator). All
//   testable code — CredentialKit, AuthKit — is pure Foundation and platform-agnostic.
//   AuthKitMSAL's implementation is wrapped in `#if os(iOS)` because MSAL's iOS flow
//   uses UIKit; on macOS that target simply compiles to nothing.
//   The macOS minimum must be >= 10.15 or the MSAL package product fails to resolve.
import PackageDescription

let package = Package(
    name: "PitLAPSKit",
    platforms: [
        .iOS(.v16),      // the shipping target
        .macOS(.v11)     // test-host only; must be >= 10.15 for MSAL
    ],
    products: [
        .library(name: "AuthKit", targets: ["AuthKit"]),
        .library(name: "AuthKitMSAL", targets: ["AuthKitMSAL"]),
        .library(name: "InventoryKit", targets: ["InventoryKit"]),
        .library(name: "CredentialKit", targets: ["CredentialKit"]),
        .library(name: "PlatformSecurity", targets: ["PlatformSecurity"])
    ],
    dependencies: [
        // MSAL for iOS (official). Pinned; review release notes before bumping.
        .package(url: "https://github.com/AzureAD/microsoft-authentication-library-for-objc",
                 .upToNextMajor(from: "1.5.0"))
    ],
    targets: [
        // Pure protocol + models. No third-party dependencies, no MSAL.
        .target(name: "AuthKit"),

        // The ONLY target that links MSAL. Implementation is #if os(iOS).
        .target(
            name: "AuthKitMSAL",
            dependencies: [
                "AuthKit",
                .product(name: "MSAL", package: "microsoft-authentication-library-for-objc")
            ]
        ),

        // Depends on CredentialKit for DevicePlatform / DeviceCredentialTarget so the
        // inventory layer can hand a ready-made target to the credential layer. This does
        // NOT violate §3.1: the rule is that CredentialKit must not depend on others.
        .target(name: "InventoryKit", dependencies: ["AuthKit", "CredentialKit"]),

        // ⚠ ISOLATION BOUNDARY (§3.1). Do NOT add dependencies to this target.
        .target(name: "CredentialKit", dependencies: ["AuthKit"]),

        .target(name: "PlatformSecurity"),

        // Runs with no MSAL and no network. Works on My Mac or a simulator.
        .testTarget(name: "CredentialKitTests", dependencies: ["CredentialKit", "AuthKit"]),
        .testTarget(name: "InventoryKitTests", dependencies: ["InventoryKit", "CredentialKit", "AuthKit"]),
        .testTarget(name: "PlatformSecurityTests", dependencies: ["PlatformSecurity"]),
        .testTarget(name: "AuthKitTests", dependencies: ["AuthKit"])
    ]
)
