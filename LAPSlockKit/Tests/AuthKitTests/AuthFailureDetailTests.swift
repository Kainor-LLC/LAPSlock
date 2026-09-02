import XCTest
@testable import AuthKit

/// The support-report auth detail is an ALLOWLIST. These tests exist to keep it one: every
/// case here is a way an error description could smuggle something into the report, and
/// every one must come out as nil or as a bare code.
final class AuthFailureDetailTests: XCTestCase {

    func test_aadCodeIsExtractedFromTextAndTheTextIsDropped() {
        // The real shape of an MSAL description, including a redirect URL with a code in
        // the query — which is exactly what must never be stored.
        let description = "AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication. Trace ID: 1f2e3d4c-0000-0000-0000-000000000000 redirect_uri=msauth.com.kainor.lapslock://auth?code=SECRET_AUTH_CODE_VALUE"
        let code = AuthFailureDetail.extractAADCode(from: description)
        XCTAssertEqual(code, "AADSTS50076")
        XCTAssertFalse(code!.contains("SECRET"))
        XCTAssertFalse(code!.contains("redirect"))
    }

    func test_aadCodeFieldRejectsAnythingButABareCode() {
        XCTAssertEqual(AuthFailureDetail(step: .signIn, aadErrorCode: "AADSTS50076").aadErrorCode, "AADSTS50076")
        XCTAssertEqual(AuthFailureDetail(step: .signIn, aadErrorCode: " AADSTS65001 ").aadErrorCode, "AADSTS65001")
        // A code with text around it is a description, not a code. Dropped.
        XCTAssertNil(AuthFailureDetail(step: .signIn, aadErrorCode: "AADSTS50076: you must use MFA").aadErrorCode)
        XCTAssertNil(AuthFailureDetail(step: .signIn, aadErrorCode: "code=abc AADSTS50076").aadErrorCode)
        XCTAssertNil(AuthFailureDetail(step: .signIn, aadErrorCode: "50076").aadErrorCode)
        XCTAssertNil(AuthFailureDetail(step: .signIn, aadErrorCode: "").aadErrorCode)
    }

    func test_oauthErrorMustLookLikeAnOAuthError() {
        XCTAssertEqual(AuthFailureDetail(step: .tokenSilent, oauthError: "invalid_grant").oauthError, "invalid_grant")
        XCTAssertEqual(AuthFailureDetail(step: .tokenSilent, oauthError: "interaction_required").oauthError, "interaction_required")
        XCTAssertNil(AuthFailureDetail(step: .tokenSilent, oauthError: "invalid_grant: the refresh token has expired").oauthError)
        XCTAssertNil(AuthFailureDetail(step: .tokenSilent, oauthError: "Invalid_Grant").oauthError)
        XCTAssertNil(AuthFailureDetail(step: .tokenSilent, oauthError: "code=abcdef").oauthError)
        XCTAssertNil(AuthFailureDetail(step: .tokenSilent, oauthError: "ab").oauthError)
    }

    func test_correlationIdMustBeAGUID() {
        let guid = "1F2E3D4C-1111-2222-3333-444455556666"
        XCTAssertEqual(AuthFailureDetail(step: .signIn, correlationId: guid).correlationId, guid.lowercased())
        XCTAssertNil(AuthFailureDetail(step: .signIn, correlationId: "not-a-guid").correlationId)
        XCTAssertNil(AuthFailureDetail(step: .signIn, correlationId: "\(guid)?code=abc").correlationId)
        XCTAssertNil(AuthFailureDetail(step: .signIn, correlationId: "").correlationId)
    }

    func test_numbersAndBoolsPassThrough() {
        let d = AuthFailureDetail(step: .tokenInteractive, msalErrorCode: -50005, httpStatus: 400, brokerInvolved: true)
        XCTAssertEqual(d.msalErrorCode, -50005)
        XCTAssertEqual(d.httpStatus, 400)
        XCTAssertEqual(d.brokerInvolved, true)
    }

    func test_reportFragmentHasFixedKeysOnly() {
        let d = AuthFailureDetail(
            step: .signIn, msalErrorCode: -50005, aadErrorCode: "AADSTS50076",
            oauthError: "interaction_required", correlationId: "1f2e3d4c-1111-2222-3333-444455556666",
            httpStatus: 400, brokerInvolved: true)
        XCTAssertEqual(
            d.reportFragment,
            "auth=signIn  msal=-50005  aad=AADSTS50076  oauth=interaction_required  http=400  broker=yes  correlation-id=1f2e3d4c-1111-2222-3333-444455556666")
    }

    func test_thereIsNoWayToPutFreeTextInTheFragment() {
        // Belt and braces: build the worst-case detail from hostile inputs and confirm the
        // fragment contains none of them.
        let hostile = "code=SECRET redirect=msauth://x?code=SECRET AADSTS50076 invalid_grant"
        let d = AuthFailureDetail(step: .signIn, aadErrorCode: hostile, oauthError: hostile, correlationId: hostile)
        XCTAssertEqual(d.reportFragment, "auth=signIn")
    }
}
