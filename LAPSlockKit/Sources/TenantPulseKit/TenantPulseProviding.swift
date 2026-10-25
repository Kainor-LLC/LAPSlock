import Foundation
import AuthKit

// The seam between the Tenant pulse screen and Microsoft Graph. Four calls, one per card,
// so the screen can render whatever came back and say what did not.

public protocol TenantPulseProviding: Sendable {
    func health() async throws -> ServiceHealthReport
    /// Messages worth showing, already filtered and ordered.
    func messages() async throws -> [ServiceMessage]
    /// Everything with an end date, across app registrations, SAML apps, the Apple push
    /// certificate and VPP tokens. The caller applies the window.
    func expiringItems() async throws -> [ExpiringItem]
    func secureScore() async throws -> SecureScoreSummary?
}

public enum TenantPulseError: Error, Sendable, Equatable {
    case consentRequired
    case notAuthorized
    case throttled(retryAfter: TimeInterval?)
    case serviceUnavailable(status: Int)
    case transport(status: Int)
    case decodeFailure
    case cancelled

    public init(_ error: GraphError) {
        switch error {
        case .consentRequired:                self = .consentRequired
        case .notAuthorized:                  self = .notAuthorized
        case .notFound:                       self = .transport(status: 404)
        case .badRequest:                     self = .transport(status: 400)
        case .throttled(let retryAfter):      self = .throttled(retryAfter: retryAfter)
        case .serviceUnavailable(let status): self = .serviceUnavailable(status: status)
        case .transport(let status):          self = .transport(status: status)
        case .decodeFailure:                  self = .decodeFailure
        case .cancelled:                      self = .cancelled
        }
    }
}

/// The delegated scopes this module asks for, verified against the Graph reference on
/// 2026-10-25. Spec section 5.
public enum TenantPulseScopes {
    /// healthOverviews and issues.
    public static let health = "ServiceHealth.Read.All"
    /// Message Center.
    public static let messages = "ServiceMessage.Read.All"
    /// App registrations and service principals, with their credentials.
    public static let applications = "Application.Read.All"
    /// The Apple push certificate and VPP tokens. The token list also accepts
    /// DeviceManagementApps.Read.All; this one covers both calls, so it is the one asked for.
    public static let deviceConfig = "DeviceManagementServiceConfig.Read.All"
    /// Secure Score.
    public static let security = "SecurityEvents.Read.All"

    /// Requested when the module is first opened.
    public static let module = [health, messages, applications, deviceConfig, security]
}
