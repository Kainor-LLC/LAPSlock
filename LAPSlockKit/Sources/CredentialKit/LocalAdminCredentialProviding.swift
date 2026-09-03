import Foundation
import AuthKit

// Build Spec §2.5, §5.2, §6, §8 — the platform seam.
//
// WHY THIS EXISTS
// Windows LAPS and macOS LAPS are different products with different storage, different
// Graph surfaces, and (today) different capabilities. Rather than branching on OS at
// every call site, each platform gets a provider that DECLARES what it can do. The UI
// renders from the declared capabilities, so a platform gaining a capability later is a
// change in exactly one file.
//
// VERIFIED STATE (2026-08-14, tested against a live licensed tenant):
//   Windows : GET /v1.0/directory/deviceLocalCredentials/{entraDeviceId}?$select=credentials
//             returns passwordBase64. GA, documented. FULLY SUPPORTED.
//   macOS   : No documented Graph endpoint returns the password value. The documented
//             beta function retrieveDeviceLocalAdminAccountDetail is specified to return
//             only passwordLastRotationDateTime (no password field), AND it currently
//             returns HTTP 500 from Intune's DeviceFE backend on every ADE-enrolled,
//             LAPS-managed device tested. Reveal is therefore UNAVAILABLE, and the
//             product degrades to a portal handoff.

/// Graph delegated scope names, in one place so they can't drift between the providers,
/// the app registration, and the sign-in code. These MUST match the delegated
/// permissions granted on the Entra app registration.
public enum LapsCredentialScopes {
    /// Device inventory from Intune.
    public static let intuneDevices = "DeviceManagementManagedDevices.Read.All"
    /// Entra device objects, needed for the two-identifier join (§2.5).
    public static let entraDevices = "Device.Read.All"
    /// LAPS metadata only — no password value.
    public static let metadataBasic = "DeviceLocalCredential.ReadBasic.All"
    /// LAPS password reveal. Requested incrementally at first reveal, never at sign-in (§4).
    public static let reveal = "DeviceLocalCredential.Read.All"
    /// BitLocker recovery key metadata (no key values).
    public static let bitLockerKeysBasic = "BitLockerKey.ReadBasic.All"
    /// Permission to MODIFY devices. Required to rotate a BitLocker recovery key.
    /// Never requested at sign-in and never requested unless the user explicitly enables
    /// rotation in Settings — a consent screen that says "modify your devices" is a much
    /// harder ask than one that says "read device inventory", and most customers don't
    /// need it. This is the same scope family that permits wipe and retire.
    public static let deviceWrite = "DeviceManagementManagedDevices.ReadWrite.All"
    /// BitLocker recovery key values. Delegated only — Microsoft does not support
    /// application permissions for retrieving a key, which suits this app exactly.
    /// Requested incrementally at first reveal, never at sign-in.
    public static let bitLockerKeys = "BitLockerKey.Read.All"

    /// Granted at sign-in. Deliberately EXCLUDES both reveal scopes — a first consent
    /// screen should read "reads device inventory", not "reads every password and disk
    /// encryption key in your tenant".
    public static let signInBaseline = [intuneDevices, entraDevices, metadataBasic, bitLockerKeysBasic]
}

public enum DevicePlatform: String, Sendable, CaseIterable {
    case windows
    case macOS
    case other

    /// Maps the Intune `operatingSystem` string onto a platform.
    public init(intuneOperatingSystem raw: String?) {
        switch (raw ?? "").lowercased() {
        case let s where s.contains("windows"): self = .windows
        case let s where s.contains("macos"), let s where s.contains("mac os"): self = .macOS
        default: self = .other
        }
    }
}

/// What a provider can actually do today. The UI reads this; it never hardcodes per-OS rules.
public struct CredentialCapabilities: Sendable, Equatable {
    /// Can show rotation/backup metadata without revealing a password.
    public let supportsMetadata: Bool
    /// Can retrieve the password value via a documented, production-supported API.
    public let supportsReveal: Bool
    /// Can trigger a rotation.
    public let supportsRotate: Bool
    /// Reveal/rotate rides a beta API (must be surfaced in the UI, off by default).
    public let usesBetaAPI: Bool
    /// When reveal is unavailable, a deep link to the admin portal is offered instead.
    public let offersPortalHandoff: Bool
    /// Plain-language reason shown to the admin when a capability is missing.
    /// Written for the end user, not the developer (design guidance: explain + next step).
    public let unavailabilityReason: String?

    public init(
        supportsMetadata: Bool,
        supportsReveal: Bool,
        supportsRotate: Bool,
        usesBetaAPI: Bool,
        offersPortalHandoff: Bool,
        unavailabilityReason: String? = nil
    ) {
        self.supportsMetadata = supportsMetadata
        self.supportsReveal = supportsReveal
        self.supportsRotate = supportsRotate
        self.usesBetaAPI = usesBetaAPI
        self.offersPortalHandoff = offersPortalHandoff
        self.unavailabilityReason = unavailabilityReason
    }
}

/// Identifiers required to address a device across the two Microsoft stores (§2.5).
/// Both are carried because Windows reveal keys on the Entra device id while Intune
/// actions key on the managed device id.
public struct DeviceCredentialTarget: Sendable, Equatable {
    public let platform: DevicePlatform
    /// Entra directory device id — Windows LAPS reveal path.
    public let entraDeviceId: String?
    /// Intune managed device id — Intune action path (rotate).
    public let managedDeviceId: String?
    public let deviceName: String?

    public init(platform: DevicePlatform, entraDeviceId: String?, managedDeviceId: String?, deviceName: String? = nil) {
        self.platform = platform
        self.entraDeviceId = entraDeviceId
        self.managedDeviceId = managedDeviceId
        self.deviceName = deviceName
    }
}

/// Rotation/backup info that is safe to display without the high-privilege scope.
public struct CredentialMetadata: Sendable, Equatable {
    public let accountName: String?
    public let lastBackupDateTime: Date?
    public let nextRefreshDateTime: Date?
    public let lastRotationDateTime: Date?

    public init(
        accountName: String? = nil,
        lastBackupDateTime: Date? = nil,
        nextRefreshDateTime: Date? = nil,
        lastRotationDateTime: Date? = nil
    ) {
        self.accountName = accountName
        self.lastBackupDateTime = lastBackupDateTime
        self.nextRefreshDateTime = nextRefreshDateTime
        self.lastRotationDateTime = lastRotationDateTime
    }
}

/// A revealed password. The value exists only inside `secret` (§3.2).
/// One backed-up version of a local administrator password.
///
/// **Why history matters, and it is not nostalgia.** A device that has not checked in
/// since its last rotation is still using an OLDER password. The admin standing at exactly
/// that machine — the one that stopped checking in, which is why they are standing at it —
/// needs the previous value, and the current one will not work.
public struct CredentialVersion {
    public let accountName: String?
    public let backupDateTime: Date?
    public let secret: SensitiveValue

    public init(accountName: String?, backupDateTime: Date?, secret: SensitiveValue) {
        self.accountName = accountName
        self.backupDateTime = backupDateTime
        self.secret = secret
    }
}

public struct RevealedCredential {
    public let accountName: String?
    public let backupDateTime: Date?
    public let secret: SensitiveValue
    /// Older passwords for the same device, newest first, and **empty unless the tenant's
    /// LAPS policy keeps history** — which is not the default.
    ///
    /// These arrive in the same Graph response as the current password: one request, one
    /// audit event, one metered reveal. Nothing here costs an extra call, which is why
    /// viewing an older version spends no further credit.
    ///
    /// Every one of these holds live bytes. Whoever owns a `RevealedCredential` must wipe
    /// `previousVersions` as well as `secret`.
    public let previousVersions: [CredentialVersion]

    public init(
        accountName: String?,
        backupDateTime: Date?,
        secret: SensitiveValue,
        previousVersions: [CredentialVersion] = []
    ) {
        self.accountName = accountName
        self.backupDateTime = backupDateTime
        self.secret = secret
        self.previousVersions = previousVersions
    }
}

/// Error taxonomy (§8). Each case maps to a distinct, actionable UI state.
public enum CredentialError: Error, Sendable, Equatable {
    case consentRequired                      // 401 — re-auth / grant scope
    case notAuthorized                        // 403 — signed in, lacks the directory role
    case notLapsEnabled                       // 404 — no LAPS record for this device
    case throttled(retryAfter: TimeInterval?) // 429 — honor Retry-After
    case serviceUnavailable(status: Int)      // 5xx — Microsoft-side failure, retryable
    case transport(status: Int)
    case emptyCredentialSet
    case decodeFailure
    case missingIdentifier(String)            // required id absent (§2.5 join gap)
    /// Capability is not offered on this platform. Carries the user-facing reason.
    case unsupportedOnPlatform(platform: DevicePlatform, reason: String)
}

/// The contract each platform implements. Adding macOS reveal later means flipping
/// `supportsReveal` to true in MacOSLapsProvider and implementing one method there.
public protocol LocalAdminCredentialProviding: Sendable {
    var platform: DevicePlatform { get }
    var capabilities: CredentialCapabilities { get }

    /// Graph scopes this provider needs for metadata (low privilege).
    var metadataScopes: [String] { get }
    /// Graph scopes this provider needs for reveal (high privilege, incremental consent).
    var revealScopes: [String] { get }

    func metadata(for target: DeviceCredentialTarget) async throws -> CredentialMetadata
    func reveal(for target: DeviceCredentialTarget) async throws -> RevealedCredential
    func rotate(for target: DeviceCredentialTarget) async throws

    /// Deep link to the admin portal for capabilities the app can't perform itself.
    func portalURL(for target: DeviceCredentialTarget) -> URL?
}

// MARK: - shared HTTP helpers (no bodies are ever logged, §3.4)

enum GraphHTTP {
    static let base = "https://graph.microsoft.com"

    static func url(version: String, path: String, query: [URLQueryItem] = []) -> URL {
        var comps = URLComponents(string: base)!
        comps.path = "/\(version)\(path)"
        if !query.isEmpty { comps.queryItems = query }
        return comps.url!
    }

    /// An ephemeral session: no disk cache, no cookie store, nothing persisted.
    static func makeSession() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.urlCache = nil
        cfg.httpCookieStorage = nil
        cfg.timeoutIntervalForRequest = 30
        return URLSession(configuration: cfg)
    }

    static func validate(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { throw CredentialError.transport(status: -1) }
        // Graph's request-id, captured before the throw. The typed errors below carry no
        // diagnostics payload on purpose — see GraphResponseTracer.
        if !(200...299).contains(http.statusCode) {
            GraphResponseTracer.shared.recordFailure(http)
        }
        switch http.statusCode {
        case 200...299:
            return
        case 401:
            throw CredentialError.consentRequired
        case 403:
            throw CredentialError.notAuthorized
        case 404:
            throw CredentialError.notLapsEnabled
        case 429:
            let retry = http.value(forHTTPHeaderField: "Retry-After").flatMap(TimeInterval.init)
            throw CredentialError.throttled(retryAfter: retry)
        case 500...599:
            // Observed in the wild on macOS retrieveDeviceLocalAdminAccountDetail.
            throw CredentialError.serviceUnavailable(status: http.statusCode)
        default:
            throw CredentialError.transport(status: http.statusCode)
        }
    }

    static func date(_ any: Any?) -> Date? {
        guard let s = any as? String else { return nil }
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return withFraction.date(from: s) ?? ISO8601DateFormatter().date(from: s)
    }
}
