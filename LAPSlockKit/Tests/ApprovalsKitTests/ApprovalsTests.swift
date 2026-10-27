import XCTest
import AuthKit
import ActionGateKit
@testable import ApprovalsKit

final class ApprovalsTests: XCTestCase {

    func testDurationsInWords() {
        XCTAssertEqual(PendingApproval.words(isoDuration: "PT8H"), "8 hours")
        XCTAssertEqual(PendingApproval.words(isoDuration: "PT1H30M"), "1 hour 30 minutes")
        XCTAssertEqual(PendingApproval.words(isoDuration: "P1DT2H"), "1 day 2 hours")
        XCTAssertNil(PendingApproval.words(isoDuration: "garbage"))
    }

    func testARoleDecisionIsABetaPatchOnTheStep() throws {
        let approval = DemoApprovalsProvider.samples()[0]
        let action = ApprovalsService.action(approval, .approve, justification: "ok, CHG-2207 checked",
                                             stagePath: "/roleManagement/directory/roleAssignmentApprovals/ap-1/steps/s1",
                                             version: .beta, scope: ApprovalScopes.roles)
        XCTAssertEqual(action.request.method, .patch)
        XCTAssertEqual(action.request.version, .beta)
        XCTAssertEqual(action.request.template, "/roleManagement/directory/roleAssignmentApprovals/{id}/steps/{stepId}")
        XCTAssertEqual(action.tier, .confirm)
        XCTAssertEqual(action.id, "pim.approve")
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(action.request.body)) as? [String: String])
        XCTAssertEqual(json["reviewResult"], "Approve")
        XCTAssertEqual(json["justification"], "ok, CHG-2207 checked")
        XCTAssertEqual(action.request.scopes, ["RoleAssignmentSchedule.ReadWrite.Directory"])
    }

    func testAGroupDecisionIsAV1PatchOnTheStage() {
        let approval = DemoApprovalsProvider.samples()[1]
        let action = ApprovalsService.action(approval, .deny, justification: "not on the rota",
                                             stagePath: "/x", version: .v1_0, scope: ApprovalScopes.groups)
        XCTAssertEqual(action.request.template, "/identityGovernance/privilegedAccess/group/assignmentApprovals/{id}/stages/{stageId}")
        XCTAssertEqual(action.id, "pim.deny")
        XCTAssertTrue(action.successCopy.hasPrefix("Denied."))
        XCTAssertEqual(action.target.label, "Priya Natarajan for Ops On-Call (PIM), member")
    }

    func testDecodingAPendingRequest() throws {
        let json = #"""
        {"value":[
         {"id":"r1","approvalId":"a1","status":"PendingApproval","justification":"Audit","createdDateTime":"2026-10-27T01:00:00Z",
          "principal":{"@odata.type":"#microsoft.graph.user","displayName":"Sam Reyes","userPrincipalName":"sam@c.com"},
          "roleDefinition":{"displayName":"Global Reader"},
          "scheduleInfo":{"startDateTime":"2026-10-27T01:00:00Z","expiration":{"type":"afterDuration","duration":"PT4H"}},
          "ticketInfo":{"ticketNumber":"INC-1","ticketSystem":"ServiceNow"}},
         {"id":"r2","approvalId":"","status":"PendingApproval"},
         {"id":"r3","approvalId":"a3","status":"Granted"}
        ]}
        """#
        struct Page: Decodable { let value: [RequestRecord] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let page = try decoder.decode(Page.self, from: Data(json.utf8))
        let models = page.value.compactMap { $0.model(.role) }
        XCTAssertEqual(models.count, 1, "no approval id, or already granted, is not waiting on anyone")
        let first = try XCTUnwrap(models.first)
        XCTAssertEqual(first.requester, "Sam Reyes")
        XCTAssertEqual(first.target, "Global Reader")
        XCTAssertEqual(first.ticket, "ServiceNow INC-1")
        XCTAssertEqual(first.durationText, "4 hours")
        XCTAssertNil(first.access)
    }

    func testDemoDecisionsRemoveTheRequestAndAreLogged() async throws {
        let demo = DemoApprovalsProvider(latency: .zero)
        let before = try await demo.pending()
        XCTAssertEqual(before.count, 3)
        let outcome = await demo.decide(before[0], .approve, justification: "checked")
        XCTAssertTrue(outcome.isRequested)
        let after = try await demo.pending()
        XCTAssertEqual(after.count, 2)
        let entry = await demo.lastLogEntry(requestId: before[0].id)
        XCTAssertEqual(entry?.actionId, "pim.approve")
    }

    func testTheQuietDemoCustomerHasNothingWaiting() async throws {
        let demo = DemoApprovalsProvider(latency: .zero, quiet: true)
        let pending = try await demo.pending()
        XCTAssertTrue(pending.isEmpty)
    }

    func testApprovingNeedsNoNewScope() {
        XCTAssertEqual(Set(ApprovalScopes.module), ["RoleAssignmentSchedule.ReadWrite.Directory", "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup"])
    }
}
