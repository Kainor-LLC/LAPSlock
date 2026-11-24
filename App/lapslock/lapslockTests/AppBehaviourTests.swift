import XCTest
import ActionGateKit
import ApprovalsKit
import CredentialKit
import ManagedConfigKit
import WatchBridgeKit
@testable import lapslock

// The app target's own tests, run inside the app on a simulator (second review, R2-30). Until
// 2.1 every guard in the app target was held by a test that reads its source as text, and the
// second review's break-it runs passed with those guards broken. These run the code instead.

/// Approvals that only count what is sent.
private actor CountingApprovals: ApprovalsProviding {
    private(set) var decisions = 0
    let waiting: [PendingApproval]
    init(waiting: [PendingApproval]) { self.waiting = waiting }
    func pending() async throws -> [PendingApproval] { waiting }
    func decide(_ approval: PendingApproval, _ decision: ApprovalDecision, justification: String) async -> ActionOutcome {
        decisions += 1
        return .requested(requestId: nil)
    }
    func lastLogEntry(requestId: String) async -> ShiftLogEntry? { nil }
}

final class WatchPrivilegedAccessTests: XCTestCase {
    private let request = PendingApproval(id: "r-1", kind: .role, approvalId: "a-1", requester: "Sam Rivera",
                                          requesterUPN: "sam@example.com", target: "Global Reader", justification: "Ticket",
                                          ticket: nil, requested: Date(), start: nil, duration: "PT1H")

    override func tearDown() {
        UserDefaults.standard.removeObject(forKey: ManagedConfiguration.userDefaultsKey)
        super.tearDown()
    }

    /// R2-3: an organization that turned Privileged Access off gets no decision from the wrist.
    func testADecisionIsRefusedBeforeAnythingIsSentWhenPrivilegedAccessIsOff() async {
        UserDefaults.standard.set(["modules.disabled": ["privilegedAccess"]], forKey: ManagedConfiguration.userDefaultsKey)
        let approvals = CountingApprovals(waiting: [request])
        let reply = await WatchHandlers.decide(approvals, id: request.id, approve: true, reason: "On call", known: [request])
        XCTAssertEqual(reply.outcome, .failed)
        XCTAssertEqual(reply.message, WatchHandlers.privilegedAccessOffMessage)
        let sent = await approvals.decisions
        XCTAssertEqual(sent, 0)
    }

    func testADecisionIsSentWhenPrivilegedAccessIsOn() async {
        let approvals = CountingApprovals(waiting: [request])
        let reply = await WatchHandlers.decide(approvals, id: request.id, approve: true, reason: "On call", known: [request])
        XCTAssertEqual(reply.outcome, .done)
        let sent = await approvals.decisions
        XCTAssertEqual(sent, 1)
    }
}

@MainActor
final class InstantAlertsSignOutTests: XCTestCase {
    /// R2-18: sign-out gives up waiting for a token after its limit.
    func testTheWaitForATokenHasALimitOfItsOwn() async {
        let started = Date()
        let late: String? = await RelayCoordinator.within(seconds: 0.2) {
            try? await Task.sleep(for: .seconds(5))
            return "late"
        }
        XCTAssertNil(late)
        XCTAssertLessThan(Date().timeIntervalSince(started), 2)
        let quick: String? = await RelayCoordinator.within(seconds: 2) { "now" }
        XCTAssertEqual(quick, "now")
    }

    /// R2-9: who turned Instant alerts on is kept as a digest, the same for the same person.
    func testThePersonIsKeptAsADigest() {
        let a = RelayCoordinator.digest("AAAA-1111.TENANT")
        XCTAssertEqual(a, RelayCoordinator.digest("aaaa-1111.tenant"))
        XCTAssertNotEqual(a, RelayCoordinator.digest("bbbb-2222.tenant"))
        XCTAssertEqual(a.count, 64)
        XCTAssertFalse(a.contains("aaaa"))
    }
}

@MainActor
final class TemporaryAccessPassLogTests: XCTestCase {
    /// R2-22: a pass that may exist is logged as not known, and a refusal as a refusal.
    func testAPassLostOnTheWayIsNotKnownAndARefusalIsARefusal() {
        if case .failed(let failure) = UserActionsModel.passOutcome(for: .transport(status: 0)) {
            XCTAssertTrue(failure.mayHaveHappened)
        } else { XCTFail("expected a failure") }
        if case .failed(let failure) = UserActionsModel.passOutcome(for: .decodeFailure) {
            XCTAssertTrue(failure.mayHaveHappened, "Microsoft accepted it; the answer could not be read")
        } else { XCTFail("expected a failure") }
        if case .failed(let failure) = UserActionsModel.passOutcome(for: .throttled(retryAfter: 5)) {
            XCTAssertFalse(failure.mayHaveHappened)
        } else { XCTFail("expected a failure") }
        XCTAssertEqual(UserActionsModel.passOutcome(for: .notAuthorized), .notAuthorized(eligible: []))
    }
}
