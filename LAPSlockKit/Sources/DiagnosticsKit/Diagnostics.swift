import Foundation

// Diagnostics for support: enough to debug a customer's failure, structurally incapable
// of capturing a credential.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE DESIGN PRINCIPLE
//
// Redaction-by-discipline fails eventually. Somebody adds a `details: String` field,
// somebody else passes an error's `localizedDescription` into it, and six months later
// a response body ends up in a support email.
//
// So this module takes the opposite approach: **the diagnostic types cannot represent a
// credential in the first place.** Every field is a typed enum, an Int, a Date, or a
// string drawn from a fixed allowlist. There is no free-text field anywhere in
// `DiagnosticEvent`, and nothing here ever accepts a response body, a header dump, or an
// arbitrary `Error.localizedDescription`.
//
// If a future change needs free text, it needs a new type, and that change should be
// obvious in review — which is the point.
//
// ISOLATION: this module depends on Foundation only, and CredentialKit does NOT import
// it. Diagnostics are recorded by the APP layer from typed errors, never from inside the
// credential path. `scripts/isolation-check.sh` fails the build if that ever changes.
// ─────────────────────────────────────────────────────────────────────────────

/// What kind of operation failed. Fixed set — no free text.
public enum DiagnosticOperation: String, Sendable, Codable, CaseIterable {
    case signIn
    case tokenSilent
    case tokenInteractive
    case deviceListFirstPage
    case deviceListNextPage
    case credentialMetadata
    case credentialReveal
    case credentialRotate
    case biometricGate
    /// Switching to a customer organization (MSP tiers). Added 2026-09-02 because that path
    /// cannot be tested by the vendor — the first person to hit a failure is a customer, so
    /// the report has to carry enough to answer them.
    case tenantSwitch
    /// Just-in-time PIM activation. Added 2026-09-02: the tenant policy that refuses one is
    /// not reproducible by the vendor, so the Microsoft error code is the only explanation
    /// a customer can hand over.
    case roleActivation
}

/// Why it failed. Mirrors the error taxonomies without carrying their payloads.
public enum DiagnosticOutcome: String, Sendable, Codable, CaseIterable {
    case success
    case consentRequired
    case notAuthorized
    case notFound
    case throttled
    case serviceUnavailable
    case transportError
    case decodeFailure
    case missingIdentifier
    case unsupportedOnPlatform
    case tenantMismatch
    case userCancelled
    case biometricUnavailable
    case biometricFailed
    case unknown
}

/// One recorded event. Note what ISN'T here: no device name, no UPN, no serial, no URL,
/// no response body, no free-form message.
public struct DiagnosticEvent: Sendable, Codable, Identifiable {
    public let id: UUID
    public let timestamp: Date
    public let operation: DiagnosticOperation
    public let outcome: DiagnosticOutcome
    /// HTTP status when the failure came from a network call.
    public let httpStatus: Int?
    /// Microsoft Graph's `request-id` header. This is the single most useful field for a
    /// Microsoft support case, and it identifies a REQUEST, not a person or a secret.
    public let graphRequestId: String?
    /// Endpoint TEMPLATE, not the real URL — "/directory/deviceLocalCredentials/{id}".
    /// Identifiers are never interpolated in, so a device ID can't leak through here.
    public let endpointTemplate: String?
    /// Platform of the device involved, when relevant. A category, not an identity.
    public let devicePlatform: String?
    /// Milliseconds the operation took, for diagnosing "Graph is slow" reports.
    public let durationMs: Int?

    // Auth failure detail, added 2026-09-02 after the broker bug proved it necessary. Each
    // is allowlisted here again, independently of whoever produced it: this type does not
    // trust its callers to have sanitised. A description string is deliberately NOT among
    // them — an MSAL description can carry a redirect URL, and a redirect URL can carry an
    // authorization code.

    /// `NSError.code` from the MSAL domain. A number.
    public let msalErrorCode: Int?
    /// Entra error code, `AADSTS` followed by digits, and nothing else. The field Microsoft
    /// support asks for first.
    public let aadErrorCode: String?
    /// RFC 6749 error string such as `invalid_grant`. Lowercase words only.
    public let oauthError: String?
    /// Entra correlation ID. A GUID identifying a request, not a person.
    public let correlationId: String?
    /// Whether the Authenticator broker handled the request.
    public let brokerInvolved: Bool?

    public init(
        operation: DiagnosticOperation,
        outcome: DiagnosticOutcome,
        httpStatus: Int? = nil,
        graphRequestId: String? = nil,
        endpointTemplate: String? = nil,
        devicePlatform: String? = nil,
        durationMs: Int? = nil,
        msalErrorCode: Int? = nil,
        aadErrorCode: String? = nil,
        oauthError: String? = nil,
        correlationId: String? = nil,
        brokerInvolved: Bool? = nil
    ) {
        self.id = UUID()
        self.timestamp = Date()
        self.operation = operation
        self.outcome = outcome
        self.httpStatus = httpStatus
        // A Graph request-id is a GUID; anything else shaped differently is rejected
        // rather than trusted, so a stray value can't ride along in this field.
        self.graphRequestId = Self.sanitizedRequestId(graphRequestId)
        self.endpointTemplate = endpointTemplate
        self.devicePlatform = devicePlatform
        self.durationMs = durationMs
        self.msalErrorCode = msalErrorCode
        self.aadErrorCode = Self.sanitizedShape(aadErrorCode, "^AADSTS[0-9]{4,8}$")
        self.oauthError = Self.sanitizedShape(oauthError, "^[a-z_]{3,40}$")
        self.correlationId = Self.sanitizedRequestId(correlationId)
        self.brokerInvolved = brokerInvolved
    }

    /// Keeps a value only if it matches the given shape exactly. Anything else becomes nil.
    static func sanitizedShape(_ raw: String?, _ pattern: String) -> String? {
        guard let raw else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.range(of: pattern, options: .regularExpression) != nil ? trimmed : nil
    }

    /// Accepts only GUID-shaped strings. Anything else becomes nil.
    static func sanitizedRequestId(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let pattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        guard trimmed.range(of: pattern, options: .regularExpression) != nil else { return nil }
        return trimmed
    }

    /// One line for the exported report.
    public var reportLine: String {
        let time = ISO8601DateFormatter().string(from: timestamp)
        var parts = ["\(time)", operation.rawValue, outcome.rawValue]
        if let httpStatus { parts.append("http=\(httpStatus)") }
        if let endpointTemplate { parts.append("endpoint=\(endpointTemplate)") }
        if let devicePlatform { parts.append("platform=\(devicePlatform)") }
        if let durationMs { parts.append("ms=\(durationMs)") }
        if let graphRequestId { parts.append("graph-request-id=\(graphRequestId)") }
        if let msalErrorCode { parts.append("msal=\(msalErrorCode)") }
        if let aadErrorCode { parts.append("aad=\(aadErrorCode)") }
        if let oauthError { parts.append("oauth=\(oauthError)") }
        if let brokerInvolved { parts.append("broker=\(brokerInvolved ? "yes" : "no")") }
        if let correlationId { parts.append("correlation-id=\(correlationId)") }
        return parts.joined(separator: "  ")
    }
}

/// Environment facts that help triage, gathered once.
public struct DiagnosticEnvironment: Sendable, Codable {
    public let appVersion: String
    public let buildNumber: String
    public let osVersion: String
    public let deviceModel: String
    /// The signed-in TENANT id, included only when the user opts in on export. It
    /// identifies the customer organization, so it is their choice to share, and it is
    /// what lets Microsoft support correlate an audit log.
    public let tenantId: String?

    public init(appVersion: String, buildNumber: String, osVersion: String, deviceModel: String, tenantId: String?) {
        self.appVersion = appVersion
        self.buildNumber = buildNumber
        self.osVersion = osVersion
        self.deviceModel = deviceModel
        self.tenantId = tenantId
    }
}

/// In-memory ring buffer of recent events.
///
/// DELIBERATELY NOT PERSISTED. Writing diagnostics to disk would create a file that
/// outlives the app session and could be swept up by a backup or a file-sharing
/// mistake. The cost is that a crash loses the log and the user has to reproduce the
/// problem before exporting — an acceptable trade for a tool that handles administrator
/// credentials.
public actor DiagnosticsRecorder {
    public static let shared = DiagnosticsRecorder()

    private var events: [DiagnosticEvent] = []
    private let capacity: Int

    public init(capacity: Int = 200) {
        self.capacity = max(10, capacity)
    }

    public func record(_ event: DiagnosticEvent) {
        events.append(event)
        if events.count > capacity {
            events.removeFirst(events.count - capacity)
        }
    }

    /// Convenience for the common call site.
    public func record(
        _ operation: DiagnosticOperation,
        _ outcome: DiagnosticOutcome,
        httpStatus: Int? = nil,
        graphRequestId: String? = nil,
        endpointTemplate: String? = nil,
        devicePlatform: String? = nil,
        durationMs: Int? = nil
    ) {
        record(DiagnosticEvent(
            operation: operation,
            outcome: outcome,
            httpStatus: httpStatus,
            graphRequestId: graphRequestId,
            endpointTemplate: endpointTemplate,
            devicePlatform: devicePlatform,
            durationMs: durationMs
        ))
    }

    public func recentEvents() -> [DiagnosticEvent] { events }

    public func clear() { events.removeAll() }

    /// Builds the text a user shares with support. Every line is assembled from typed
    /// fields, so there is no path by which arbitrary text enters the report.
    public func buildReport(environment: DiagnosticEnvironment, includeTenantId: Bool) -> String {
        var lines: [String] = []
        lines.append("LAPSlock diagnostic report")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("")
        lines.append("App: \(environment.appVersion) (\(environment.buildNumber))")
        lines.append("OS: \(environment.osVersion)")
        lines.append("Device: \(environment.deviceModel)")
        if includeTenantId, let tenantId = environment.tenantId {
            lines.append("Tenant: \(tenantId)")
        } else {
            lines.append("Tenant: not included")
        }
        lines.append("")
        lines.append("This report contains no passwords, recovery keys, usernames, device names, or response data. It lists operation outcomes and Microsoft Graph request identifiers only.")
        lines.append("")
        lines.append("Recent events (newest last, \(events.count) of max \(capacity)):")
        if events.isEmpty {
            lines.append("  (none recorded this session)")
        } else {
            for event in events {
                lines.append("  " + event.reportLine)
            }
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - endpoint templates

/// Endpoint identifiers as TEMPLATES. Call sites reference these constants rather than
/// building a string from a real URL, so a device or tenant id can never be recorded.
public enum DiagnosticEndpoint {
    public static let managedDevicesList = "/v1.0/deviceManagement/managedDevices"
    public static let deviceLocalCredentials = "/v1.0/directory/deviceLocalCredentials/{entraDeviceId}"
    public static let macLocalAdminDetail = "/beta/deviceManagement/managedDevices/{id}/retrieveDeviceLocalAdminAccountDetail"
    public static let macRotate = "/beta/deviceManagement/managedDevices/{id}/rotateLocalAdminPassword"
}
