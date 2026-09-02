import XCTest
@testable import PrivilegedAccessKit

/// Building an activation request and reading its outcome.
///
/// The test that matters most here is the pending-approval one. Graph returns 201 whether a
/// role was granted or merely requested, and only `status` tells them apart. Reporting a
/// pending request as success would send an administrator back to a broken machine believing
/// they have access they do not have.
final class ActivationRequestTests: XCTestCase {

    private let principal = "aaaaaaaa-1111-2222-3333-444455556666"
    private let roleDef = "7698a772-787b-4ac8-901f-60d6b08affd2"   // Cloud Device Administrator

    // MARK: - the request, for both PIM surfaces

    private var role: EligibleAccess {
        EligibleAccess(
            id: "sched-role",
            kind: .directoryRole(roleDefinitionId: roleDef, directoryScopeId: "/"),
            displayName: "Cloud Device Administrator",
            eligibilityEndsAt: nil)
    }

    private var groupMembership: EligibleAccess {
        EligibleAccess(
            id: "sched-group",
            kind: .group(groupId: "gggggggg-1111-2222-3333-444455556666", accessId: .member),
            displayName: "LAPS Readers",
            eligibilityEndsAt: nil)
    }

    private func prepared(_ access: EligibleAccess, ticket: String? = nil) -> ActivationRequest.Prepared {
        ActivationRequest.selfActivate(
            access,
            principalId: principal,
            justification: "Retrieving a LAPS password for a helpdesk ticket",
            ticketNumber: ticket)
    }

    func test_aRoleGoesToTheRoleManagementEndpoint() {
        let p = prepared(role)
        XCTAssertEqual(p.path, PrivilegedAccessGraph.roleActivationPath)
        XCTAssertEqual(p.fields["roleDefinitionId"], roleDef)
        XCTAssertEqual(p.fields["directoryScopeId"], "/")
        XCTAssertNil(p.fields["groupId"], "a role body must not carry group fields")
        XCTAssertNil(p.fields["accessId"])
    }

    func test_aGroupGoesToThePrivilegedAccessEndpoint() {
        // PIM for Groups is a separate surface with a separate body. Posting one shape to
        // the other endpoint is the mistake pairing path and body together prevents.
        let p = prepared(groupMembership)
        XCTAssertEqual(p.path, PrivilegedAccessGraph.groupActivationPath)
        XCTAssertEqual(p.fields["groupId"], "gggggggg-1111-2222-3333-444455556666")
        XCTAssertEqual(p.fields["accessId"], "member")
        XCTAssertNil(p.fields["roleDefinitionId"], "a group body must not carry role fields")
        XCTAssertNil(p.fields["directoryScopeId"])
    }

    func test_ownershipIsDistinctFromMembership() {
        // Activating ownership when membership was eligible would be a larger grant than
        // the user holds.
        let owner = EligibleAccess(
            id: "o", kind: .group(groupId: "g", accessId: .owner),
            displayName: nil, eligibilityEndsAt: nil)
        XCTAssertEqual(prepared(owner).fields["accessId"], "owner")
    }

    func test_bothSurfacesRequestSelfActivationOnly() {
        // Any other action would be administering somebody else's access, which this app
        // must never do.
        for access in [role, groupMembership] {
            XCTAssertEqual(prepared(access).fields["action"], "selfActivate")
            XCTAssertEqual(prepared(access).fields["principalId"], principal)
        }
    }

    func test_aJustificationIsAlwaysSent() {
        // It lands in the customer's own audit log: an activation should be as traceable as
        // the credential read it unblocks.
        XCTAssertEqual(
            prepared(role).fields["justification"],
            "Retrieving a LAPS password for a helpdesk ticket")
    }

    func test_theActivationIsBoundedAndExpiresOnItsOwn() {
        let json = prepared(role).json
        let expiration = (json["scheduleInfo"] as? [String: Any])?["expiration"] as? [String: Any]
        XCTAssertEqual(expiration?["type"] as? String, "afterDuration")
        XCTAssertEqual(expiration?["duration"] as? String, "PT5H")
    }

    func test_ticketInfoIsOmittedWhenThereIsNoTicket() {
        XCTAssertNil(prepared(role).ticket)
        XCTAssertNil(prepared(role, ticket: "").ticket)
        let schedule = prepared(role).json["scheduleInfo"] as? [String: Any]
        XCTAssertNil(schedule?["ticketInfo"], "an empty ticketInfo is noise in an audit log")
    }

    func test_aTicketIsPassedThroughWhenGiven() {
        let schedule = prepared(role, ticket: "INC-4471").json["scheduleInfo"] as? [String: Any]
        let info = schedule?["ticketInfo"] as? [String: Any]
        XCTAssertEqual(info?["ticketNumber"] as? String, "INC-4471")
    }

    // MARK: - the outcome, where over-reporting success is the danger

    private func response(status: String, endDateTime: String? = nil) -> [String: Any] {
        var json: [String: Any] = ["id": "req-1", "status": status]
        if let endDateTime {
            json["scheduleInfo"] = ["expiration": ["endDateTime": endDateTime]]
        }
        return json
    }

    func test_provisionedMeansActive() {
        let outcome = ActivationRequest.outcome(from: response(status: "Provisioned", endDateTime: "2026-09-02T20:00:00Z"))
        guard case .activated(let until) = outcome else { return XCTFail("expected activated, got \(outcome)") }
        XCTAssertEqual(until, ISO8601DateFormatter.graphNoFraction.date(from: "2026-09-02T20:00:00Z"))
    }

    func test_fractionalSecondsInTheExpiryAreParsed() {
        // Graph emits fractional seconds on some endpoints and not others. A formatter
        // configured for one silently returns nil for the other, which would show a role as
        // active with no expiry.
        let outcome = ActivationRequest.outcome(from: response(status: "Provisioned", endDateTime: "2026-09-02T20:00:00.123Z"))
        guard case .activated(let until) = outcome else { return XCTFail("expected activated") }
        XCTAssertNotNil(until, "fractional-second expiry should parse")
    }

    func test_pendingApprovalIsNeverReportedAsActive() {
        // THE test in this file. Graph answers 201 either way; only status distinguishes
        // them. An administrator told their role is live when it is merely requested walks
        // back to a broken machine and fails again.
        for status in ["PendingApproval", "PendingAdminDecision", "Granted ", "pending", "Failed", "Canceled", ""] {
            let outcome = ActivationRequest.outcome(from: response(status: status))
            guard case .pendingApproval = outcome else {
                return XCTFail("status '\(status)' must not be reported as activated")
            }
        }
    }

    func test_anUnrecognisedStatusIsTreatedAsPending() {
        // Fail toward "not yet active", which is the safe direction: it under-promises.
        let outcome = ActivationRequest.outcome(from: ["id": "req-2", "status": "SomethingNew"])
        guard case .pendingApproval(let id) = outcome else { return XCTFail("expected pending") }
        XCTAssertEqual(id, "req-2")
    }

    func test_aResponseWithNoStatusIsPending() {
        guard case .pendingApproval = ActivationRequest.outcome(from: [:]) else {
            return XCTFail("a statusless response must not read as activated")
        }
    }

    // MARK: - eligibility, both surfaces

    private func page(_ items: [[String: Any]]) -> [String: Any] { ["value": items] }

    func test_eligibleRolesAreParsed() {
        let roles = ActivationRequest.eligibleRoles(from: page([[
            "id": "sched-1",
            "roleDefinitionId": roleDef,
            "directoryScopeId": "/",
            "roleDefinition": ["displayName": "Cloud Device Administrator"],
        ]]))
        XCTAssertEqual(roles.count, 1)
        XCTAssertEqual(roles.first?.label, "Cloud Device Administrator")
        XCTAssertTrue(roles.first?.canReadLocalCredentials == true)
    }

    func test_eligibleGroupsAreParsed() {
        // PIM for Groups. Tenants that manage access most carefully often use this instead
        // of direct role eligibility, so an implementation that only read roles would show
        // them "no eligible access".
        let groups = ActivationRequest.eligibleGroups(from: page([[
            "id": "sched-g1",
            "groupId": "gggggggg-1111-2222-3333-444455556666",
            "accessId": "member",
            "group": ["displayName": "LAPS Readers"],
        ]]))
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups.first?.label, "LAPS Readers")
        XCTAssertEqual(groups.first?.kind, .group(groupId: "gggggggg-1111-2222-3333-444455556666", accessId: .member))
    }

    func test_aGroupIsNeverClaimedToReadCredentials() {
        // A group's id says nothing about which roles it carries. Claiming it grants
        // credential access when it might not would be worse than staying quiet.
        let groups = ActivationRequest.eligibleGroups(from: page([[
            "groupId": "g", "accessId": "member", "group": ["displayName": "Global Administrators"],
        ]]))
        XCTAssertFalse(groups.first?.canReadLocalCredentials == true)
    }

    func test_anUnknownAccessIdIsSkippedRatherThanGuessed() {
        // Guessing "member" for an unrecognised value could activate a different grant than
        // the user is eligible for.
        let groups = ActivationRequest.eligibleGroups(from: page([
            ["groupId": "g1", "accessId": "somethingNew"],
            ["groupId": "g2", "accessId": "OWNER"],
        ]))
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups.first?.kind, .group(groupId: "g2", accessId: .owner))
    }

    func test_credentialReadingRolesSortFirstAcrossBothSurfaces() {
        // The combined list exists to unblock a reveal, so the entry that unblocks it must
        // not be third.
        let roles = ActivationRequest.eligibleRoles(from: page([
            ["id": "a", "roleDefinitionId": "11111111-1111-1111-1111-111111111111",
             "roleDefinition": ["displayName": "Billing Administrator"]],
            ["id": "b", "roleDefinitionId": roleDef,
             "roleDefinition": ["displayName": "Cloud Device Administrator"]],
        ]))
        let groups = ActivationRequest.eligibleGroups(from: page([
            ["groupId": "g", "accessId": "member", "group": ["displayName": "AAA First Alphabetically"]],
        ]))
        let combined = ActivationRequest.combined(roles: roles, groups: groups)
        XCTAssertEqual(combined.first?.label, "Cloud Device Administrator")
        XCTAssertEqual(combined.count, 3)
    }

    func test_accessWithNoExpandedNameStillAppears() {
        // Without $expand Graph returns only ids. Hiding the entry would be worse than a
        // generic label.
        let roles = ActivationRequest.eligibleRoles(from: page([["id": "x", "roleDefinitionId": roleDef]]))
        XCTAssertEqual(roles.first?.label, "Directory role")
        XCTAssertEqual(roles.first?.kind, .directoryRole(roleDefinitionId: roleDef, directoryScopeId: "/"))

        let owner = ActivationRequest.eligibleGroups(from: page([["groupId": "g", "accessId": "owner"]]))
        XCTAssertEqual(owner.first?.label, "Group ownership")
    }

    func test_oneMalformedEntryDoesNotHideTheOthers() {
        let roles = ActivationRequest.eligibleRoles(from: page([
            ["id": "broken"],
            ["id": "blank", "roleDefinitionId": "   "],
            ["id": "good", "roleDefinitionId": roleDef, "roleDefinition": ["displayName": "Cloud Device Administrator"]],
        ]))
        XCTAssertEqual(roles.map(\.id), ["good"])
    }

    func test_junkYieldsNothingRatherThanThrowing() {
        for parser in [ActivationRequest.eligibleRoles, ActivationRequest.eligibleGroups] {
            XCTAssertTrue(parser([:]).isEmpty)
            XCTAssertTrue(parser(["value": "not an array"]).isEmpty)
        }
    }
}

/// The scope sets, which shipped wrong once.
final class PrivilegedScopeTests: XCTestCase {

    /// The toggle consents to `allScopes`. It used to consent to `activateScopes` alone,
    /// which left the read scopes unconsented — so opening the sheet made a silent request
    /// for a scope nobody had approved, and the failure surfaced as "your account may not be
    /// eligible", a message about a different problem entirely.
    func test_allScopesCoversBothReadingAndActivating() {
        let all = Set(PrivilegedAccessGraph.allScopes)
        XCTAssertTrue(all.isSuperset(of: PrivilegedAccessGraph.readScopes), "reading eligibility must be consented")
        XCTAssertTrue(all.isSuperset(of: PrivilegedAccessGraph.activateScopes), "activating must be consented")
    }

    func test_bothPIMSurfacesAreCoveredInEachDirection() {
        // Four scopes: read and activate, roles and groups. Missing any one shows a tenant
        // "no eligible access" or refuses activation, both of which read as the feature
        // being broken rather than a permission being absent.
        XCTAssertEqual(Set(PrivilegedAccessGraph.allScopes).count, 4)
        for scope in [
            PrivilegedAccessGraph.roleReadScope,
            PrivilegedAccessGraph.roleActivateScope,
            PrivilegedAccessGraph.groupReadScope,
            PrivilegedAccessGraph.groupActivateScope,
        ] {
            XCTAssertTrue(PrivilegedAccessGraph.allScopes.contains(scope), "\(scope) must be requested")
        }
    }

    func test_readAndActivateScopesAreDistinct() {
        // A read scope where an activate scope belongs would fail only at the moment of
        // activation, which is the worst time to discover it.
        XCTAssertTrue(Set(PrivilegedAccessGraph.readScopes)
            .isDisjoint(with: Set(PrivilegedAccessGraph.activateScopes)))
    }
}

/// The eligibility endpoints, which shipped wrong once.
final class PrivilegedEndpointTests: XCTestCase {

    /// Both must use the self-service function, and for different reasons.
    ///
    /// Groups: Graph documents that listing group eligibility REQUIRES a principalId or
    /// groupId filter, so the plain collection is an invalid request. It returned nothing,
    /// one surface failing is tolerated by design, and a tenant with PIM for Groups
    /// configured showed no groups — a silent half-failure rather than an error.
    ///
    /// Roles: the plain collection returns every schedule the caller can see, which needs
    /// directory-wide read. It works for a Global Administrator and returns nothing useful
    /// for the ordinary admin this feature exists to help.
    func test_bothSurfacesUseTheSelfServiceFunction() {
        for path in [PrivilegedAccessGraph.roleEligibilityPath, PrivilegedAccessGraph.groupEligibilityPath] {
            XCTAssertTrue(
                path.hasSuffix("filterByCurrentUser(on='principal')"),
                "\(path) must scope itself to the caller")
        }
    }

    func test_activationPathsAreNotFiltered() {
        // The activation endpoints take a body naming the principal, so a filter function
        // there would be wrong — and would silently post to a URL Graph does not serve.
        for path in [PrivilegedAccessGraph.roleActivationPath, PrivilegedAccessGraph.groupActivationPath] {
            XCTAssertFalse(path.contains("filterByCurrentUser"), "\(path) must not be filtered")
            XCTAssertTrue(path.hasSuffix("ScheduleRequests"))
        }
    }

    func test_theTwoSurfacesUseDifferentGraphAreas() {
        // Roles live under roleManagement, groups under identityGovernance. Confusing them
        // is a 404 at best and the wrong object at worst.
        XCTAssertTrue(PrivilegedAccessGraph.roleEligibilityPath.contains("/roleManagement/directory/"))
        XCTAssertTrue(PrivilegedAccessGraph.groupEligibilityPath.contains("/identityGovernance/privilegedAccess/group/"))
    }

    func test_everyPathIsAValidURLOnceBuilt() {
        // The self-service function puts parentheses and quotes in the path. If
        // URLComponents ever refuses one of these, every call silently fails.
        for path in [
            PrivilegedAccessGraph.roleEligibilityPath, PrivilegedAccessGraph.groupEligibilityPath,
            PrivilegedAccessGraph.roleActivationPath, PrivilegedAccessGraph.groupActivationPath,
        ] {
            var comps = URLComponents(string: "https://graph.microsoft.com")!
            comps.path = path
            XCTAssertNotNil(comps.url, "\(path) did not survive URL construction")
        }
    }
}
