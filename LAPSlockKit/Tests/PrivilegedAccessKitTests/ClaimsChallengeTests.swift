import XCTest
@testable import PrivilegedAccessKit

/// The claims challenge, which is the mechanism that stops this app escalating its own
/// privilege from a stale token.
///
/// Two failure directions matter and they pull opposite ways. Missing a real challenge means
/// PIM activation never works. Treating an ORDINARY 401 as a challenge means sending the user
/// into a re-authentication loop that can never resolve, because re-authenticating does not
/// fix an expired token or a missing scope. Both are covered below.
final class ClaimsChallengeTests: XCTestCase {

    /// `{"access_token":{"acr":{"essential":true,"value":"c1"}}}` — the real shape Entra
    /// sends when it wants MFA satisfied in-session.
    private let claimsJSON = #"{"access_token":{"acr":{"essential":true,"value":"c1"}}}"#

    private func encoded(_ json: String, urlSafe: Bool = false, padded: Bool = true) -> String {
        var s = Data(json.utf8).base64EncodedString()
        if urlSafe { s = s.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_") }
        if !padded { s = s.replacingOccurrences(of: "=", with: "") }
        return s
    }

    func test_aRealChallengeIsParsed() {
        let header = #"Bearer realm="", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize", error="insufficient_claims", claims="\#(encoded(claimsJSON))""#
        let challenge = ClaimsChallenge.parse(wwwAuthenticate: header)
        XCTAssertEqual(challenge?.json, claimsJSON)
    }

    func test_urlSafeAndUnpaddedBase64AreAccepted() {
        // Entra has been seen sending both variants. Failing on one would leave the user at
        // an unexplained dead end that looks like a broken feature.
        for (urlSafe, padded) in [(true, true), (false, false), (true, false)] {
            let header = "Bearer claims=\"\(encoded(claimsJSON, urlSafe: urlSafe, padded: padded))\""
            XCTAssertEqual(
                ClaimsChallenge.parse(wwwAuthenticate: header)?.json, claimsJSON,
                "urlSafe=\(urlSafe) padded=\(padded) should parse")
        }
    }

    func test_anOrdinary401CarriesNoChallenge() {
        // The critical negative. Re-authenticating does not fix an expired token or a
        // missing scope, so mistaking these for a claims challenge is an infinite loop.
        for header in [
            "Bearer",
            #"Bearer realm="", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize""#,
            #"Bearer error="invalid_token", error_description="The access token expired""#,
            #"Bearer error="insufficient_scope""#,
            "",
        ] {
            XCTAssertNil(ClaimsChallenge.parse(wwwAuthenticate: header), "\(header) should carry no challenge")
        }
    }

    func test_theClaimsKeyIsNotMatchedInsideAnotherKey() {
        // A header with `error_claims="..."` must not be read as a claims challenge.
        let header = #"Bearer error_claims="\#(encoded(claimsJSON))""#
        XCTAssertNil(ClaimsChallenge.parse(wwwAuthenticate: header))
    }

    func test_junkIsRejectedRatherThanPassedToMSAL() {
        // The value reaches MSAL, so it is treated as untrusted input.
        for value in [
            "not base64 at all !!!",
            encoded("[1,2,3]"),             // valid JSON, but an array not an object
            encoded(#""a string""#),        // valid JSON, not an object
            encoded("42"),
            encoded("{not json}"),
            "",
        ] {
            XCTAssertNil(
                ClaimsChallenge.parse(wwwAuthenticate: "Bearer claims=\"\(value)\""),
                "\(value.prefix(20)) should be rejected")
        }
    }

    func test_anEnormousChallengeIsRefused() {
        // A hostile response should not be able to hand MSAL something huge.
        let big = #"{"access_token":{"acr":{"essential":true,"value":""# + String(repeating: "A", count: 5000) + #""}}}"#
        XCTAssertNil(ClaimsChallenge.parse(wwwAuthenticate: "Bearer claims=\"\(encoded(big))\""))
    }

    func test_aChallengeCannotBeConstructedFromNonObjectJSON() {
        XCTAssertNil(ClaimsChallenge(json: "[1,2,3]"))
        XCTAssertNil(ClaimsChallenge(json: "garbage"))
        XCTAssertNotNil(ClaimsChallenge(json: claimsJSON))
    }

    func test_parsingIsCaseInsensitiveOnTheKey() {
        // Header keys are case-insensitive per RFC 7235.
        let header = "Bearer Claims=\"\(encoded(claimsJSON))\""
        XCTAssertEqual(ClaimsChallenge.parse(wwwAuthenticate: header)?.json, claimsJSON)
    }
}
