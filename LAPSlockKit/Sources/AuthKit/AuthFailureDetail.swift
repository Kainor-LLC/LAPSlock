import Foundation

// Build Spec — structured auth failure detail for the support report.
//
// WHY THIS EXISTS. On 2026-08-26 a device-only sign-in failure surfaced as "check your
// connection". Diagnosing it took a cable, Xcode and Console.app; the MSAL log named the
// cause in one line. A customer hitting the same thing has none of those, and the support
// report gave them nothing to send. This type is what the report was missing.
//
// WHY IT IS SHAPED LIKE THIS. The obvious fix — put the error description in the report — is
// the one thing that must not happen. MSAL error descriptions can carry the URL that failed,
// and a broker redirect URL can carry an authorization code. So this is an ALLOWLIST: every
// field is a number, a bool, or a string that has been checked against a fixed shape.
// There is no description field, and there must never be one.
//
// AuthKit is protocols and plain types only, so this lives here and both AuthKitMSAL (which
// fills it in) and the app (which records it) can see it without a new module dependency.

/// Which auth step failed.
public enum AuthStep: String, Sendable, Codable, Equatable {
    case signIn
    case tokenSilent
    case tokenInteractive
}

/// What a failed MSAL call is willing to tell support. Every field allowlisted.
public struct AuthFailureDetail: Sendable, Equatable, Codable {
    public let step: AuthStep
    /// `NSError.code` from the MSAL error domain. A number; carries nothing.
    public let msalErrorCode: Int?
    /// Entra's own code, e.g. `AADSTS50076`. Extracted from the error text by shape and
    /// stored WITHOUT the text around it. This is the field Microsoft support asks for.
    public let aadErrorCode: String?
    /// OAuth error string, e.g. `invalid_grant`. Fixed vocabulary, checked by shape.
    public let oauthError: String?
    /// Entra correlation ID for the request. A GUID. Identifies a request, not a person.
    public let correlationId: String?
    /// HTTP status of the token endpoint response, when there was one.
    public let httpStatus: Int?
    /// Whether the Microsoft Authenticator broker handled the request. The 2026-08-26
    /// failure was a broker-path bug, and knowing which path was taken is half the diagnosis.
    public let brokerInvolved: Bool?

    public init(
        step: AuthStep,
        msalErrorCode: Int? = nil,
        aadErrorCode: String? = nil,
        oauthError: String? = nil,
        correlationId: String? = nil,
        httpStatus: Int? = nil,
        brokerInvolved: Bool? = nil
    ) {
        self.step = step
        self.msalErrorCode = msalErrorCode
        self.aadErrorCode = Self.sanitizedAADCode(aadErrorCode)
        self.oauthError = Self.sanitizedOAuthError(oauthError)
        self.correlationId = Self.sanitizedGUID(correlationId)
        self.httpStatus = httpStatus
        self.brokerInvolved = brokerInvolved
    }

    // MARK: - allowlist shapes

    /// Finds an `AADSTS` code inside arbitrary text and returns ONLY the code. The text is
    /// discarded. This is how an error description contributes to the report without the
    /// description itself ever being stored.
    public static func extractAADCode(from text: String?) -> String? {
        guard let text,
              let range = text.range(of: "AADSTS[0-9]{4,8}", options: .regularExpression)
        else { return nil }
        return String(text[range])
    }

    static func sanitizedAADCode(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.range(of: "^AADSTS[0-9]{4,8}$", options: .regularExpression) != nil ? t : nil
    }

    /// RFC 6749 error strings are lowercase words and underscores. Anything else is not
    /// an OAuth error and is dropped.
    static func sanitizedOAuthError(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.range(of: "^[a-z_]{3,40}$", options: .regularExpression) != nil ? t : nil
    }

    static func sanitizedGUID(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let pattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        return t.range(of: pattern, options: .regularExpression) != nil ? t.lowercased() : nil
    }

    /// The report fragment. Fixed keys, allowlisted values, nothing else.
    public var reportFragment: String {
        var parts: [String] = ["auth=\(step.rawValue)"]
        if let msalErrorCode { parts.append("msal=\(msalErrorCode)") }
        if let aadErrorCode { parts.append("aad=\(aadErrorCode)") }
        if let oauthError { parts.append("oauth=\(oauthError)") }
        if let httpStatus { parts.append("http=\(httpStatus)") }
        if let brokerInvolved { parts.append("broker=\(brokerInvolved ? "yes" : "no")") }
        if let correlationId { parts.append("correlation-id=\(correlationId)") }
        return parts.joined(separator: "  ")
    }
}
