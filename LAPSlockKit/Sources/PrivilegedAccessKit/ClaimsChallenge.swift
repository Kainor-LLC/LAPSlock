import Foundation

// Build Spec — the claims challenge, which is the reason PIM is a project and not an
// afternoon.
//
// WHAT IT IS. Microsoft requires the caller to have satisfied MFA in the CURRENT session
// before it will let anyone self-activate a privileged role. When the token in hand does not
// meet that bar, Graph answers 401 with a `WWW-Authenticate` header carrying a base64 blob of
// JSON describing what it wants — typically an `acr` value of `c1`. The client decodes that,
// hands it to MSAL as a claims request, re-authenticates, and retries.
//
// WHY THIS IS CORRECT AND NOT AN OBSTACLE TO ROUTE AROUND. It is the mechanism that stops
// this app quietly escalating its own privilege. An app that could activate a role from a
// stale token would be a worse app. The right response to a claims challenge is always to
// re-authenticate, never to retry harder or to fall back to some other path.
//
// THE PARSING IS THE SECURITY-RELEVANT PART. The header is attacker-influenceable in
// principle, and its contents are passed into MSAL, so this file treats it as untrusted
// input: the blob must be valid base64, must decode to a JSON OBJECT, and must be small.
// A hostile challenge should at worst cause one unnecessary sign-in prompt, never anything
// stranger.

/// A decoded claims challenge, ready to hand to MSAL.
public struct ClaimsChallenge: Sendable, Equatable {
    /// The claims JSON, decoded from the header's base64. This is what MSAL wants.
    public let json: String

    public init?(json: String) {
        guard ClaimsChallenge.isPlausibleClaimsObject(json) else { return nil }
        self.json = json
    }

    /// Largest challenge we will accept. Real ones are a couple of hundred bytes; the cap is
    /// here so a hostile response cannot hand MSAL something enormous.
    static let maxDecodedBytes = 4096

    /// Extracts a challenge from a `WWW-Authenticate` header value.
    ///
    /// Returns nil when there is no challenge, which is the ordinary case for every other
    /// 401 — a genuinely expired token, a missing scope, a revoked session. Only an
    /// `insufficient_claims` style response carries one, and treating an ordinary 401 as a
    /// claims challenge would send the user into a re-authentication loop that could never
    /// resolve.
    public static func parse(wwwAuthenticate header: String) -> ClaimsChallenge? {
        guard let encoded = quotedValue(of: "claims", in: header) else { return nil }
        guard let data = decodeBase64Tolerantly(encoded), data.count <= maxDecodedBytes else { return nil }
        guard let json = String(data: data, encoding: .utf8) else { return nil }
        return ClaimsChallenge(json: json)
    }

    /// Extracts a challenge from a Graph ERROR MESSAGE.
    ///
    /// PIM does not challenge the way the rest of Graph does. When a group or role policy
    /// requires a Conditional Access authentication context and the token lacks it, Graph
    /// answers **400** with code `RoleAssignmentRequestAcrsValidationFailed` and puts the
    /// required claim in the message text:
    ///
    ///     claims={"access_token":{"acrs":{"essential":true,"value":"c1"}}}
    ///
    /// Raw JSON, not base64, and in a body rather than a `WWW-Authenticate` header — which
    /// is why a retry that only watched 401 and 403 never fired, and activation failed with
    /// a bare 400 instead.
    ///
    /// The blob is treated exactly as untrusted as the header form: it must parse as a JSON
    /// object and stay under the size cap before it reaches MSAL.
    public static func parse(graphErrorMessage message: String) -> ClaimsChallenge? {
        guard let json = balancedObject(after: "claims=", in: message) else { return nil }
        return ClaimsChallenge(json: json)
    }

    /// Takes the balanced `{...}` immediately following `marker`.
    ///
    /// Brace-counted rather than regex-matched: the claims object is nested, and a greedy or
    /// lazy pattern either swallows the rest of the message or stops at the first inner
    /// brace. Bails out past the size cap so a hostile message cannot make this scan forever.
    static func balancedObject(after marker: String, in text: String) -> String? {
        guard let markerRange = text.range(of: marker) else { return nil }
        var depth = 0
        var started = false
        var collected = ""

        for character in text[markerRange.upperBound...] {
            if character == "{" {
                depth += 1
                started = true
            }
            if started {
                collected.append(character)
                if collected.utf8.count > maxDecodedBytes { return nil }
            } else if !character.isWhitespace {
                // Something other than an object follows the marker.
                return nil
            }
            if character == "}" {
                depth -= 1
                if depth == 0 { return started ? collected : nil }
            }
        }
        return nil   // unbalanced
    }

    /// Pulls `key="value"` out of a comma-separated challenge header.
    ///
    /// Hand-parsed rather than split on commas: the base64 in a claims value can itself
    /// contain characters that a naive split mangles, and the value is quoted precisely so it
    /// can. Scans for the key, then takes everything to the closing quote.
    static func quotedValue(of key: String, in header: String) -> String? {
        let pattern = "(?:^|[\\s,])\(key)\\s*=\\s*\"([^\"]*)\""
        guard let range = header.range(of: pattern, options: [.regularExpression, .caseInsensitive]) else {
            return nil
        }
        let match = String(header[range])
        guard let open = match.range(of: "\"") ,
              let close = match.range(of: "\"", options: .backwards),
              open.upperBound <= close.lowerBound
        else { return nil }
        let value = String(match[open.upperBound..<close.lowerBound])
        return value.isEmpty ? nil : value
    }

    /// Entra has been observed to send both standard and URL-safe base64 here, and to omit
    /// padding. Accept all of it rather than failing on a variant and leaving the user with
    /// an unexplained dead end.
    static func decodeBase64Tolerantly(_ value: String) -> Data? {
        var normalised = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let remainder = normalised.count % 4
        if remainder > 0 { normalised += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: normalised)
    }

    /// A claims request is a JSON object. Anything else — an array, a bare string, a number,
    /// junk — is not a claims challenge and is not passed on to MSAL.
    static func isPlausibleClaimsObject(_ json: String) -> Bool {
        guard let data = json.data(using: .utf8), data.count <= maxDecodedBytes else { return false }
        guard let parsed = try? JSONSerialization.jsonObject(with: data) else { return false }
        return parsed is [String: Any]
    }
}
