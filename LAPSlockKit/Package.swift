// swift-tools-version: 5.9
// LAPSlockKit, module boundaries per Build Spec §3.1.
//
// The rule that matters: CredentialKit depends on AuthKit and Foundation only. Adding a
// licensing module, an analytics SDK or a logging framework to it must remain a compile
// error. Enforced here and by scripts/isolation-check.sh.
//
// MSAL lives in its own target (AuthKitMSAL) so the credential path links no third-party
// binary, the tests run with no network and no Microsoft dependency, and MSAL API drift
// can break one target only.
//
// macOS is declared solely so the tests run on the "My Mac" destination. AuthKitMSAL is
// wrapped in `#if os(iOS)` and compiles to nothing there. The macOS minimum must be at
// least 10.15 or the MSAL package product fails to resolve.
import PackageDescription

let package = Package(
    name: "LAPSlockKit",
    platforms: [
        // iOS 17 floor. Chosen deliberately: iOS 17 shipped September 2023 and runs on
        // iPhone XS and later, so in 2026 it covers essentially every phone an IT
        // administrator carries for work. It buys ContentUnavailableView (proper empty
        // and error states) and the two-parameter onChange, and avoids maintaining
        // availability shims in the screens that matter most. Revisit only if a
        // customer reports a fleet on iPhone 8-era hardware.
        .iOS(.v17),
        .macOS(.v14),    // test-host only
        // The Apple Watch companion links WatchBridgeKit and nothing else from here.
        .watchOS(.v10)
    ],
    products: [
        .library(name: "AuthKit", targets: ["AuthKit"]),
        .library(name: "AuthKitMSAL", targets: ["AuthKitMSAL"]),
        .library(name: "InventoryKit", targets: ["InventoryKit"]),
        .library(name: "CredentialKit", targets: ["CredentialKit"]),
        .library(name: "PlatformSecurity", targets: ["PlatformSecurity"]),
        .library(name: "DiagnosticsKit", targets: ["DiagnosticsKit"]),
        .library(name: "LicensingKit", targets: ["LicensingKit"]),
        .library(name: "PrivilegedAccessKit", targets: ["PrivilegedAccessKit"]),
        .library(name: "SubscriptionKit", targets: ["SubscriptionKit"]),
        .library(name: "ConditionalAccessKit", targets: ["ConditionalAccessKit"]),
        .library(name: "TenantPulseKit", targets: ["TenantPulseKit"]),
        .library(name: "SignInTriageKit", targets: ["SignInTriageKit"]),
        .library(name: "SecurityKit", targets: ["SecurityKit"]),
        .library(name: "ThreatDigestKit", targets: ["ThreatDigestKit"]),
        .library(name: "ActionGateKit", targets: ["ActionGateKit"]),
        .library(name: "DeviceActionsKit", targets: ["DeviceActionsKit"]),
        .library(name: "NotificationsKit", targets: ["NotificationsKit"]),
        .library(name: "ManagedConfigKit", targets: ["ManagedConfigKit"]),
        .library(name: "UserActionsKit", targets: ["UserActionsKit"]),
        .library(name: "GroupWritesKit", targets: ["GroupWritesKit"]),
        .library(name: "ApprovalsKit", targets: ["ApprovalsKit"]),
        .library(name: "WatchBridgeKit", targets: ["WatchBridgeKit"]),
        .library(name: "RelayKit", targets: ["RelayKit"]),
        .library(name: "SavedSearchKit", targets: ["SavedSearchKit"])
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

        // Apple subscriptions. Foundation + StoreKit + LicensingKit, and it must NEVER
        // import CredentialKit.
        //
        // Its own target rather than a folder in LicensingKit because LicensingKit is
        // capped by isolation-check at Foundation + CryptoKit + Security, deliberately, so
        // the module that verifies signed entitlements cannot grow a payments SDK. StoreKit
        // lives out here instead, and LicensingKit stays the pure verifier it was.
        .target(name: "SubscriptionKit", dependencies: ["LicensingKit"]),

        // PIM role activation. Foundation + AuthKit only, and it must NEVER import
        // CredentialKit.
        //
        // Its own module rather than a folder in AuthKit because of what it asks for: this
        // is the one part of the app that requests a privilege ESCALATION. Keeping it
        // structurally unable to see a credential means "activating a role cannot touch a
        // password" is a property of the link graph rather than a claim in a comment, the
        // same argument that isolates CredentialKit and LicensingKit from each other.
        .target(name: "PrivilegedAccessKit", dependencies: ["AuthKit"]),

        .target(name: "PlatformSecurity"),

        // Conditional Access, read-only. Foundation + AuthKit only, and it must NEVER import
        // CredentialKit: it reads policy, and policy must stay structurally unable to see a
        // password. Same argument as PrivilegedAccessKit, enforced by isolation-check.
        .target(name: "ConditionalAccessKit", dependencies: ["AuthKit"]),

        // Tenant pulse, read-only: service health, Message Center, expiring credentials,
        // Secure Score. Foundation + AuthKit only, never CredentialKit.
        .target(name: "TenantPulseKit", dependencies: ["AuthKit"]),

        // Sign-in triage, read-only, with the error glossary bundled as a resource so it
        // works with no network. Foundation + AuthKit only, never CredentialKit.
        .target(
            name: "SignInTriageKit",
            dependencies: ["AuthKit"],
            resources: [.process("Resources")]
        ),

        // Security, read-only: incidents, alerts and their evidence from the Graph security
        // API. Foundation + AuthKit only, never CredentialKit.
        .target(name: "SecurityKit", dependencies: ["AuthKit"]),

        // Threat digest: public feeds from CISA and MSRC, merged and ranked on the phone.
        // Foundation only, no AuthKit: it must never be able to carry a token, a tenant id
        // or anything else of the tenant's to a host that is not Microsoft Graph.
        .target(name: "ThreatDigestKit"),

        // The gate every write goes through: role gate, one send, the shift log. AuthKit for
        // the Graph client, PrivilegedAccessKit for eligibility and the claims challenge.
        // Never CredentialKit, in either direction: a target that performs writes must be
        // structurally unable to see a credential.
        .target(name: "ActionGateKit", dependencies: ["AuthKit", "PrivilegedAccessKit"]),

        // Device actions: the five low-blast-radius Intune actions as WriteActions for the
        // gate, plus the management record. Takes the device as plain values rather than
        // importing InventoryKit, which links CredentialKit; a target that writes must never
        // hold credential code in its link graph.
        .target(name: "DeviceActionsKit", dependencies: ["AuthKit", "ActionGateKit", "PrivilegedAccessKit"]),

        // Notifications: what to post and the preferences, from opaque keys the app hands
        // in. Foundation and Security only; it never sees Graph, a token or a payload.
        .target(name: "NotificationsKit"),

        // Managed app configuration from Intune: parsing and the safe defaults. Foundation
        // only; it can only take things away or ask for more care, never enable a write.
        .target(name: "ManagedConfigKit"),

        // User actions: revoke, block, the authentication wipe, risk. Writes for the gate,
        // never CredentialKit; the Temporary Access Pass lives on the credential path.
        .target(name: "UserActionsKit", dependencies: ["AuthKit", "ActionGateKit", "PrivilegedAccessKit"]),
        .target(name: "GroupWritesKit", dependencies: ["AuthKit", "ActionGateKit", "PrivilegedAccessKit"]),
        .target(name: "ApprovalsKit", dependencies: ["AuthKit", "ActionGateKit", "PrivilegedAccessKit"]),
        .target(name: "WatchBridgeKit"),
        .target(name: "RelayKit"),
        // Saved searches, phase 5 step C. Foundation only.
        .target(name: "SavedSearchKit"),

        // Support diagnostics. Foundation only, and CredentialKit must never import it:
        // diagnostics are recorded by the app layer from typed errors, never from inside
        // the credential path. The isolation guard enforces this.
        // Depends on AuthKit ONLY for GraphResponseTracer, which lives there because
        // CredentialKit is capped at Foundation + AuthKit and so cannot report
        // anything to DiagnosticsKit directly.
        .target(name: "DiagnosticsKit", dependencies: ["AuthKit"]),

        // Free-tier reveal metering. Foundation + CryptoKit only.
        //
        // ⚠ ISOLATION: this target must NOT depend on CredentialKit, and CredentialKit
        // must never import it. The meter counts EVENTS, no type in it has anywhere to
        // put a credential. Wiring happens in the app layer (DeviceDetailModel), which
        // already coordinates the gate, the provider and the reveal session.
        .target(name: "LicensingKit"),

        // Runs with no MSAL and no network. Works on My Mac or a simulator.
        .testTarget(name: "CredentialKitTests", dependencies: ["CredentialKit", "AuthKit"]),
        .testTarget(name: "InventoryKitTests", dependencies: ["InventoryKit", "CredentialKit", "AuthKit"]),
        .testTarget(name: "PlatformSecurityTests", dependencies: ["PlatformSecurity"]),
        .testTarget(name: "AuthKitTests", dependencies: ["AuthKit"]),
        .testTarget(name: "DiagnosticsKitTests", dependencies: ["DiagnosticsKit"]),
        .testTarget(name: "LicensingKitTests", dependencies: ["LicensingKit"]),
        .testTarget(name: "PrivilegedAccessKitTests", dependencies: ["PrivilegedAccessKit", "AuthKit"]),
        .testTarget(name: "SubscriptionKitTests", dependencies: ["SubscriptionKit", "LicensingKit"]),
        .testTarget(name: "ConditionalAccessKitTests", dependencies: ["ConditionalAccessKit", "AuthKit"]),
        .testTarget(name: "TenantPulseKitTests", dependencies: ["TenantPulseKit", "AuthKit"]),
        .testTarget(name: "SignInTriageKitTests", dependencies: ["SignInTriageKit", "AuthKit"]),
        .testTarget(name: "SecurityKitTests", dependencies: ["SecurityKit", "AuthKit"]),
        .testTarget(name: "ThreatDigestKitTests", dependencies: ["ThreatDigestKit"]),
        .testTarget(name: "ActionGateKitTests", dependencies: ["ActionGateKit", "AuthKit", "PrivilegedAccessKit"]),
        .testTarget(name: "DeviceActionsKitTests", dependencies: ["DeviceActionsKit", "ActionGateKit", "AuthKit"]),
        .testTarget(name: "NotificationsKitTests", dependencies: ["NotificationsKit"]),
        .testTarget(name: "ManagedConfigKitTests", dependencies: ["ManagedConfigKit"]),
        .testTarget(name: "UserActionsKitTests", dependencies: ["UserActionsKit", "ActionGateKit", "AuthKit", "PrivilegedAccessKit"]),
        .testTarget(name: "GroupWritesKitTests", dependencies: ["GroupWritesKit", "ActionGateKit", "AuthKit", "PrivilegedAccessKit"]),
        .testTarget(name: "ApprovalsKitTests", dependencies: ["ApprovalsKit", "ActionGateKit", "AuthKit", "PrivilegedAccessKit"]),
        .testTarget(name: "WatchBridgeKitTests", dependencies: ["WatchBridgeKit"]),
        .testTarget(name: "RelayKitTests", dependencies: ["RelayKit"]),
        .testTarget(name: "SavedSearchKitTests", dependencies: ["SavedSearchKit"])
    ]
)
