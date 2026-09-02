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

    // MARK: - the request body

    private func body(ticket: String? = nil) -> [String: Any] {
        ActivationRequest.selfActivateBody(
            principalId: principal,
            roleDefinitionId: roleDef,
            directoryScopeId: "/",
            justification: "Retrieving a LAPS password for a helpdesk ticket",
            ticketNumber: ticket)
    }

    func test_theBodyRequestsSelfActivationAndNothingElse() {
        // `selfActivate` acts on the caller's own existing eligibility. Any other action
        // would be managing somebody else's access, which this app must never do.
        XCTAssertEqual(body()["action"] as? String, "selfActivate")
        XCTAssertEqual(body()["principalId"] as? String, principal)
        XCTAssertEqual(body()["roleDefinitionId"] as? String, roleDef)
        XCTAssertEqual(body()["directoryScopeId"] as? String, "/")
    }

    func test_aJustificationIsAlwaysSent() {
        // It lands in the customer's own audit log, which is the point: activation should be
        // as traceable as the credential read it unblocks.
        XCTAssertEqual(
            body()["justification"] as? String,
            "Retrieving a LAPS password for a helpdesk ticket")
    }

    func test_theDurationIsBoundedAndExpiresOnItsOwn() {
        let schedule = body()["scheduleInfo"] as? [String: Any]
        let expiration = schedule?["expiration"] as? [String: Any]
        XCTAssertEqual(expiration?["type"] as? String, "afterDuration")
        XCTAssertEqual(expiration?["duration"] as? String, "PT5H")
        XCTAssertNotNil(schedule?["startDateTime"] as? String)
    }

    func test_ticketInfoIsOmittedWhenThereIsNoTicket() {
        // An empty ticketInfo is noise in an audit log.
        XCTAssertNil(body()["ticketInfo"])
        XCTAssertNil(body(ticket: "")["ticketInfo"])
        XCTAssertNotNil(body(ticket: "INC-4471")["ticketInfo"])
    }

    func test_aTicketIsPassedThroughWhenGiven() {
        let info = body(ticket: "INC-4471")["ticketInfo"] as? [String: Any]
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

    // MARK: - eligibility list

    private func schedules(_ items: [[String: Any]]) -> [String: Any] { ["value": items] }

    func test_eligibleRolesAreParsed() {
        let roles = ActivationRequest.eligibleRoles(from: schedules([[
            "id": "sched-1",
            "roleDefinitionId": roleDef,
            "directoryScopeId": "/",
            "roleDefinition": ["displayName": "Cloud Device Administrator"],
        ]]))
        XCTAssertEqual(roles.count, 1)
        XCTAssertEqual(roles.first?.label, "Cloud Device Administrator")
        XCTAssertEqual(roles.first?.id, "sched-1")
        XCTAssertTrue(roles.first?.canReadLocalCredentials == true)
    }

    func test_credentialReadingRolesSortFirst() {
        // The list exists to unblock a reveal, so the role that unblocks it must not be
        // third.
        let roles = ActivationRequest.eligibleRoles(from: schedules([
            ["id": "a", "roleDefinitionId": "11111111-1111-1111-1111-111111111111",
             "roleDefinition": ["displayName": "Billing Administrator"]],
            ["id": "b", "roleDefinitionId": roleDef,
             "roleDefinition": ["displayName": "Cloud Device Administrator"]],
        ]))
        XCTAssertEqual(roles.first?.label, "Cloud Device Administrator")
    }

    func test_aRoleWithNoExpandedNameStillAppears() {
        // Without $expand Graph returns only ids. Hiding the role would be worse than
        // showing it with a generic label.
        let roles = ActivationRequest.eligibleRoles(from: schedules([["id": "x", "roleDefinitionId": roleDef]]))
        XCTAssertEqual(roles.count, 1)
        XCTAssertEqual(roles.first?.label, "Directory role")
        XCTAssertEqual(roles.first?.directoryScopeId, "/", "scope defaults to tenant-wide")
    }

    func test_oneMalformedEntryDoesNotHideTheOthers() {
        let roles = ActivationRequest.eligibleRoles(from: schedules([
            ["id": "broken"],                                    // no roleDefinitionId
            ["id": "empty", "roleDefinitionId": ""],
            ["id": "good", "roleDefinitionId": roleDef, "roleDefinition": ["displayName": "Cloud Device Administrator"]],
        ]))
        XCTAssertEqual(roles.map(\.id), ["good"])
    }

    func test_junkYieldsNoRolesRatherThanThrowing() {
        XCTAssertTrue(ActivationRequest.eligibleRoles(from: [:]).isEmpty)
        XCTAssertTrue(ActivationRequest.eligibleRoles(from: ["value": "not an array"]).isEmpty)
    }
}
