import XCTest
@testable import AuthKit

// Build Spec §13, consent onboarding tests.
//
// These matter because the failure they guard against is invisible to the person who
// causes it: an admin who consents without ticking the organization checkbox sees a
// working app while their whole team is locked out. The classification below is what
// turns that dead end into a shareable link.

final class AdminConsentLinkTests: XCTestCase {

    private func query(_ url: URL?) -> [String: String] {
        let items = url.flatMap { URLComponents(url: $0, resolvingAgainstBaseURL: false)?.queryItems } ?? []
        return Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
    }

    func test_buildsURLWithTenantGuid() {
        let url = AdminConsentLink.url(registration: .read, tenant: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        XCTAssertNotNil(url)
        let s = url!.absoluteString
        XCTAssertTrue(s.contains("login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
        XCTAssertTrue(s.contains("/v2.0/adminconsent"))
        XCTAssertEqual(query(url)["client_id"], AppRegistration.read.clientId)
    }

    func test_buildsURLWithDomain() {
        let url = AdminConsentLink.url(registration: .read, tenant: "contoso.com")
        XCTAssertTrue(url!.absoluteString.contains("login.microsoftonline.com/contoso.com"))
    }

    func test_nilTenantUsesOrganizations() {
        // `organizations` lets the admin sign in and have their tenant resolved, which
        // is the right default when we don't know it yet.
        let url = AdminConsentLink.url(registration: .read, tenant: nil)
        XCTAssertTrue(url!.absoluteString.contains("/organizations/"))
    }

    func test_emptyTenantTreatedAsNil() {
        let url = AdminConsentLink.url(registration: .read, tenant: "")
        XCTAssertTrue(url!.absoluteString.contains("/organizations/"))
    }

    /// `.default` on the shared read registration would ask for TenantKeep Posture's
    /// permissions too. Every link names what it asks for.
    func test_namesItsScopesAndNeverUsesDefault() {
        for registration in AppRegistration.allCases {
            let scope = query(AdminConsentLink.url(registration: registration))["scope"] ?? ""
            XCTAssertFalse(scope.contains(".default"), registration.rawValue)
            XCTAssertEqual(scope.split(separator: " ").map(String.init), registration.qualifiedScopes, registration.rawValue)
        }
    }

    func test_aModuleCanAskForItsShareOfTheReadRegistration() {
        let url = AdminConsentLink.url(registration: .read, scopes: ["AuditLog.Read.All", "Policy.Read.All"])
        XCTAssertEqual(query(url)["scope"], "https://graph.microsoft.com/AuditLog.Read.All https://graph.microsoft.com/Policy.Read.All")
    }

    func test_returnsToTheConsentPageAndSaysWhichApp() {
        let url = AdminConsentLink.url(registration: .deviceActions, tenant: "contoso.com")
        XCTAssertEqual(query(url)["redirect_uri"], "https://tenantkeep.app/consent/")
        XCTAssertEqual(query(url)["state"], "oncall.deviceActions")
        XCTAssertEqual(query(url)["client_id"], AppRegistration.deviceActions.clientId)
    }

    func test_theAlertsLinkNamesItsOwnScope() {
        let url = AdminConsentLink.url(registration: .alerts)
        XCTAssertEqual(query(url)["scope"], "api://" + AppRegistration.alerts.clientId + "/Alerts.Register")
    }

    // MARK: - the forwardable message

    func test_requestMessageExplainsTheOrgCheckboxTrap() {
        let url = AdminConsentLink.url(registration: .read, tenant: "contoso.com")
        let msg = AdminConsentLink.requestMessage(consentURL: url)
        XCTAssertTrue(msg.contains("on behalf of your organization"),
                      "The message must name the exact checkbox that gets missed.")
        XCTAssertTrue(msg.contains(url!.absoluteString))
    }

    func test_requestMessageStatesDelegatedAndAudited() {
        // An admin deciding whether to approve a password-reading app needs the two
        // facts that make it safe: delegated access, and audit logging.
        let msg = AdminConsentLink.requestMessage(consentURL: nil)
        XCTAssertTrue(msg.lowercased().contains("delegated"))
        XCTAssertTrue(msg.lowercased().contains("audit"))
    }

    func test_requestMessageWorksWithoutURL() {
        let msg = AdminConsentLink.requestMessage(consentURL: nil)
        XCTAssertFalse(msg.isEmpty)
        XCTAssertFalse(msg.contains("Approval link:"))
    }
}

final class ConsentDiagnosticsTests: XCTestCase {

    func test_detectsAADSTS65001() {
        let state = ConsentDiagnostics.state(
            fromErrorDescription: "AADSTS65001: The user or administrator has not consented to use the application."
        )
        XCTAssertEqual(state, .organizationApprovalRequired)
    }

    func test_detectsAdminConsentRequiredCodes() {
        XCTAssertEqual(ConsentDiagnostics.state(fromErrorDescription: "AADSTS90094 blah"),
                       .organizationApprovalRequired)
        XCTAssertEqual(ConsentDiagnostics.state(fromErrorDescription: "error AADSTS900971 here"),
                       .organizationApprovalRequired)
    }

    func test_detectsRoleMissingDistinctFromConsent() {
        // Consent and authorization are different failures with different fixes.
        // Conflating them would send an admin chasing the wrong problem.
        let state = ConsentDiagnostics.state(
            fromErrorDescription: "Authorization_RequestDenied: Insufficient privileges to complete the operation."
        )
        XCTAssertEqual(state, .roleMissing)
    }

    func test_unknownErrorReturnsNil() {
        XCTAssertNil(ConsentDiagnostics.state(fromErrorDescription: "network timed out"))
        XCTAssertNil(ConsentDiagnostics.state(fromErrorDescription: nil))
        XCTAssertNil(ConsentDiagnostics.state(fromErrorDescription: ""))
    }

    func test_mapsAuthErrorConsentRequired() {
        XCTAssertEqual(ConsentDiagnostics.state(from: .consentRequired), .organizationApprovalRequired)
    }

    func test_mapsUnderlyingAuthErrorByCode() {
        XCTAssertEqual(ConsentDiagnostics.state(from: .underlying("AADSTS65001 not consented")),
                       .organizationApprovalRequired)
    }

    func test_unrelatedAuthErrorsHaveNoConsentState() {
        XCTAssertNil(ConsentDiagnostics.state(from: .userCancelled))
        XCTAssertNil(ConsentDiagnostics.state(from: .noAccount))
        XCTAssertNil(ConsentDiagnostics.state(from: .tenantMismatch))
    }

    // MARK: - copy quality

    func test_everyStateHasTitleAndExplanation() {
        let states: [ConsentState] = [
            .granted, .organizationApprovalRequired, .grantedForThisUserOnly, .roleMissing
        ]
        for state in states {
            XCTAssertFalse(state.title.isEmpty, "\(state) needs a title")
            XCTAssertFalse(state.explanation.isEmpty, "\(state) needs an explanation")
        }
    }

    func test_grantedStateOffersNoAction() {
        XCTAssertNil(ConsentState.granted.actionLabel)
    }

    /// Narrowed 2026-09-02. It used to assert that `roleMissing` offers an action too, which
    /// encoded a reasonable intent, the state IS recoverable, but the only screen that
    /// renders `actionLabel` is the SIGNED-OUT one, and its button opens the admin-consent
    /// sheet. So the action sent somebody with a role problem to an explanation about
    /// approving the app, and it could not have done better: you cannot activate a role
    /// while signed out, because activation needs a token.
    ///
    /// A missing role is recoverable where the app has a session and knows Graph refused for
    /// want of a role, which is the failed reveal. That is where PIM activation is offered.
    func test_consentStatesOfferAnApprovalAction() {
        XCTAssertNotNil(ConsentState.organizationApprovalRequired.actionLabel)
        XCTAssertNotNil(ConsentState.grantedForThisUserOnly.actionLabel)
    }

    func test_roleMissingExplanationNamesLeastPrivilegedRole() {
        // Telling an admin "you lack permission" is useless; naming the role is not.
        let text = ConsentState.roleMissing.explanation
        XCTAssertTrue(text.contains("Cloud Device Administrator"))
    }
}

// MARK: - roleMissing must not offer a consent action

extension ConsentDiagnosticsTests {

    /// A role problem and a consent problem have different fixes, and the only screen that
    /// renders `actionLabel` opens the admin-consent sheet. Offering an action here sent
    /// somebody who needs a directory role to an explanation about approving the app.
    func test_roleMissingOffersNoAction() {
        XCTAssertNil(ConsentState.roleMissing.actionLabel)
        XCTAssertNil(ConsentState.granted.actionLabel)
        XCTAssertNotNil(ConsentState.organizationApprovalRequired.actionLabel)
        XCTAssertNotNil(ConsentState.grantedForThisUserOnly.actionLabel)
    }

    /// With no button, the explanation has to stand alone, so it names both the
    /// least-privileged role that works and the way to obtain it.
    func test_roleMissingExplainsItselfWithoutAnAction() {
        let explanation = ConsentState.roleMissing.explanation
        XCTAssertTrue(explanation.contains("Privileged Identity Management"))
    }

    /// A missing role is a Graph 403, never a sign-in failure: Entra authenticates you
    /// regardless of which directory roles you hold. So this state cannot be produced from
    /// an AuthError, and anything that tries to detect it at sign-in is looking in the wrong
    /// place.
    func test_aMissingRoleIsNotASignInFailure() {
        for error in [AuthError.noAccount, .interactionRequired, .userCancelled, .tenantMismatch] {
            XCTAssertNotEqual(ConsentDiagnostics.state(from: error), .roleMissing)
        }
        XCTAssertEqual(ConsentDiagnostics.state(from: .consentRequired), .organizationApprovalRequired)
        // It comes from a Graph payload instead.
        XCTAssertEqual(
            ConsentDiagnostics.state(fromErrorDescription: "Authorization_RequestDenied"),
            .roleMissing)
    }
}
