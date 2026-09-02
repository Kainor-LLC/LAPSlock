import XCTest
@testable import PrivilegedAccessKit

/// Reading the tenant's activation rules instead of guessing at them.
///
/// The duration was a hardcoded guess, then a fixed picker, and both were wrong the same
/// way: every PIM policy caps activation length, the cap is per-tenant and often per-group,
/// and asking for longer than allowed is refused with a bare 400 naming no reason. Offering
/// "8 hours" to a tenant that permits three is offering a button that cannot work.
final class ActivationPolicyTests: XCTestCase {

    private func rules(_ items: [[String: Any]]) -> [[String: Any]] { items }

    // MARK: durations

    func test_aThreeHourPolicyOffersItsOwnMaximum() {
        // The observed case: a custom maximum that is not one of the standard options. It
        // has to appear, or the user cannot use the allowance they actually have.
        let policy = ActivationPolicy(maximumDuration: "PT3H")
        XCTAssertEqual(policy.offeredDurations.map(\.iso), ["PT1H", "PT2H", "PT3H"])
        XCTAssertEqual(policy.offeredDurations.last?.label, "3 hours")
    }

    func test_nothingLongerThanThePolicyIsOffered() {
        let policy = ActivationPolicy(maximumDuration: "PT2H")
        XCTAssertEqual(policy.offeredDurations.map(\.iso), ["PT1H", "PT2H"])
        XCTAssertFalse(policy.offeredDurations.contains { $0.iso == "PT4H" })
    }

    func test_aStandardMaximumIsNotDuplicated() {
        let policy = ActivationPolicy(maximumDuration: "PT4H")
        XCTAssertEqual(policy.offeredDurations.map(\.iso), ["PT1H", "PT2H", "PT4H"])
    }

    func test_anUnreadablePolicyFallsBackToTheStandardOptions() {
        // A policy read that failed must leave the UI exactly as it behaved before the read
        // existed. It is here to stop offering refusals, not to become a new failure.
        XCTAssertEqual(
            ActivationPolicy.unknown.offeredDurations.map(\.iso),
            ActivationRequest.durations.map(\.iso))
    }

    func test_aSubHourPolicyStillOffersSomething() {
        // Under an hour leaves no standard option, and an empty picker is worse than one
        // entry the tenant actually permits.
        let policy = ActivationPolicy(maximumDuration: "PT30M")
        XCTAssertEqual(policy.offeredDurations.map(\.iso), ["PT30M"])
    }

    func test_minutesRoundDownNeverUp() {
        // A 90-minute policy offers one hour. Rounding up would offer a refusal.
        XCTAssertEqual(ActivationPolicy.hours("PT90M"), 1)
        XCTAssertEqual(ActivationPolicy.hours("PT30M"), 0)
        XCTAssertEqual(ActivationPolicy.hours("PT3H"), 3)
        XCTAssertEqual(ActivationPolicy.hours("P1D"), 24)
    }

    func test_anUnparseableDurationYieldsNilRatherThanAGuess() {
        for iso in ["", "PT", "3H", "P1M", "banana", "PT1H30M"] {
            XCTAssertNil(ActivationPolicy.hours(iso), "\(iso) must not produce a number")
        }
    }

    // MARK: rules

    func test_theEndUserRulesAreRead() {
        let policy = ActivationPolicy.from(rules: rules([
            ["id": "Expiration_EndUser_Assignment", "maximumDuration": "PT3H"],
            ["id": "Enablement_EndUser_Assignment",
             "enabledRules": ["Justification", "Ticketing", "MultiFactorAuthentication"]],
            ["id": "AuthenticationContext_EndUser_Assignment", "isEnabled": true, "claimValue": "c1"],
        ]))
        XCTAssertEqual(policy.maximumDuration, "PT3H")
        XCTAssertTrue(policy.justificationRequired)
        XCTAssertTrue(policy.ticketRequired)
        XCTAssertTrue(policy.multiFactorRequired)
        XCTAssertEqual(policy.authenticationContextClaim, "c1")
    }

    func test_aDisabledAuthenticationContextIsIgnored() {
        // A disabled rule still carries a claim value. Requesting a context the policy does
        // not want would prompt the user for nothing.
        let policy = ActivationPolicy.from(rules: rules([
            ["id": "AuthenticationContext_EndUser_Assignment", "isEnabled": false, "claimValue": "c1"],
        ]))
        XCTAssertNil(policy.authenticationContextClaim)
    }

    func test_ruleIdsAreMatchedNotDisplayNames() {
        // Display names are localised; rule ids are immutable and identical in every tenant.
        let policy = ActivationPolicy.from(rules: rules([
            ["id": "Expiration_Admin_Eligibility", "maximumDuration": "P365D"],
        ]))
        XCTAssertNil(policy.maximumDuration, "an admin-eligibility rule is not the end-user one")
    }

    func test_unknownRulesAreIgnored() {
        let policy = ActivationPolicy.from(rules: rules([
            ["id": "Something_Microsoft_Adds_Later", "someProperty": "value"],
            ["id": "Expiration_EndUser_Assignment", "maximumDuration": "PT1H"],
        ]))
        XCTAssertEqual(policy.maximumDuration, "PT1H")
    }

    func test_junkYieldsTheUnknownPolicy() {
        XCTAssertEqual(ActivationPolicy.from(policiesResponse: [:]), .unknown)
        XCTAssertEqual(ActivationPolicy.from(policiesResponse: ["value": "not an array"]), .unknown)
        XCTAssertEqual(ActivationPolicy.from(rules: []), .unknown)
    }

    func test_aPolicyResponseIsRead() {
        let policy = ActivationPolicy.from(policiesResponse: [
            "value": [["id": "p1", "rules": [
                ["id": "Expiration_EndUser_Assignment", "maximumDuration": "PT3H"],
            ]]],
        ])
        XCTAssertEqual(policy.maximumDuration, "PT3H")
    }

    // MARK: the acrs claim request

    func test_theClaimRequestMatchesWhatGraphAsksFor() throws {
        let json = try XCTUnwrap(PrivilegedAccessService.claimsRequest(forAcrs: "c1"))
        let parsed = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let token = try XCTUnwrap(parsed["access_token"] as? [String: Any])
        let acrs = try XCTUnwrap(token["acrs"] as? [String: Any])
        XCTAssertEqual(acrs["value"] as? String, "c1")
        XCTAssertEqual(acrs["essential"] as? Bool, true)
    }

    func test_aClaimValueWithAQuoteCannotProduceMalformedJSON() throws {
        // Built with JSONSerialization rather than interpolation, so a policy value
        // containing a quote is escaped instead of breaking the request.
        let json = try XCTUnwrap(PrivilegedAccessService.claimsRequest(forAcrs: "c1\"evil"))
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: Data(json.utf8)))
    }
}
