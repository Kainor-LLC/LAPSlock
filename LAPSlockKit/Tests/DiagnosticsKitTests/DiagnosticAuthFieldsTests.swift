import XCTest
@testable import DiagnosticsKit

/// The event type re-sanitises auth fields itself rather than trusting whoever produced
/// them. These tests pin that: a caller passing a description where a code belongs gets nil.
final class DiagnosticAuthFieldsTests: XCTestCase {

    func test_authFieldsAreSanitisedIndependentlyOfTheCaller() {
        let e = DiagnosticEvent(
            operation: .signIn, outcome: .unknown,
            msalErrorCode: -50005,
            aadErrorCode: "AADSTS50076: message with redirect?code=SECRET",
            oauthError: "invalid_grant: expired",
            correlationId: "not a guid",
            brokerInvolved: true)
        XCTAssertEqual(e.msalErrorCode, -50005)
        XCTAssertNil(e.aadErrorCode)
        XCTAssertNil(e.oauthError)
        XCTAssertNil(e.correlationId)
        XCTAssertEqual(e.brokerInvolved, true)
        XCTAssertFalse(e.reportLine.contains("SECRET"))
    }

    func test_wellFormedAuthFieldsAreKeptAndReported() {
        let e = DiagnosticEvent(
            operation: .tokenSilent, outcome: .consentRequired,
            msalErrorCode: -50002, aadErrorCode: "AADSTS65001", oauthError: "interaction_required",
            correlationId: "1f2e3d4c-1111-2222-3333-444455556666", brokerInvolved: false)
        let line = e.reportLine
        XCTAssertTrue(line.contains("msal=-50002"))
        XCTAssertTrue(line.contains("aad=AADSTS65001"))
        XCTAssertTrue(line.contains("oauth=interaction_required"))
        // "responded", not "involved" or "opened": the flag is only ever set on a broker
        // RESPONSE, so an abandoned Authenticator launch reads as no. The label must not
        // promise more than that.
        XCTAssertTrue(line.contains("broker-responded=no"))
        XCTAssertFalse(line.contains("broker=no"), "the old label overstated what was known")
        XCTAssertTrue(line.contains("correlation-id=1f2e3d4c-1111-2222-3333-444455556666"))
    }

    func test_existingCallSitesAreUnaffected() {
        // The new parameters all default to nil; an event built the old way has no auth
        // fields and its report line is unchanged in shape.
        let e = DiagnosticEvent(operation: .credentialReveal, outcome: .success, httpStatus: 200, durationMs: 617)
        XCTAssertNil(e.msalErrorCode)
        XCTAssertNil(e.aadErrorCode)
        XCTAssertFalse(e.reportLine.contains("msal="))
        XCTAssertTrue(e.reportLine.contains("http=200"))
    }
}
