import XCTest
@testable import AuthKit

/// Which app registration a kind of write goes through, from what an organization approved.
/// The rule is small and it decides which sign-in a person is sent to, so every branch is
/// pinned.
final class ApprovalProbeTests: XCTestCase {

    private func lowered(_ registration: AppRegistration) -> Set<String> {
        Set(registration.scopes.map { $0.lowercased() })
    }

    func testTheSeparateRegistrationWinsWhenBothAreApproved() {
        let approved: [AppRegistration: Set<String>] = [.deviceActions: lowered(.deviceActions), .actions: lowered(.actions)]
        XCTAssertEqual(ApprovalProbe.choose(for: .deviceActions, approved: approved), .deviceActions)
    }

    func testTheCombinedRegistrationIsUsedWhenOnlyItIsApproved() {
        let approved: [AppRegistration: Set<String>] = [.deviceActions: [], .actions: lowered(.actions)]
        XCTAssertEqual(ApprovalProbe.choose(for: .deviceActions, approved: approved), .actions)
    }

    func testNeitherApprovedIsNotAnAnswer() {
        let approved: [AppRegistration: Set<String>] = [.deviceActions: [], .actions: []]
        XCTAssertNil(ApprovalProbe.choose(for: .deviceActions, approved: approved))
    }

    func testUnreadableApprovalsAreNotAnAnswer() {
        XCTAssertNil(ApprovalProbe.choose(for: .deviceActions, approved: nil))
    }

    /// Half a registration's permissions is not that registration approved: sending a
    /// person through it would leave half its actions failing.
    func testAPartlyApprovedRegistrationDoesNotCount() {
        let half: Set<String> = ["devicemanagementmanageddevices.privilegedoperations.all"]
        XCTAssertNil(ApprovalProbe.choose(for: .deviceActions, approved: [.deviceActions: half, .actions: []]))
        XCTAssertEqual(ApprovalProbe.choose(for: .deviceActions, approved: [.deviceActions: half, .actions: lowered(.actions)]), .actions)
        // The combined registration counts for the kinds of action it was approved for.
        XCTAssertEqual(ApprovalProbe.choose(for: .groupMembership, approved: [.groupMembership: [], .actions: lowered(.groupMembership)]), .actions)
        XCTAssertNil(ApprovalProbe.choose(for: .accountRecovery, approved: [.accountRecovery: [], .actions: lowered(.groupMembership)]))
    }

    func testOnlyAKindOfWriteHasARoute() {
        let everything: [AppRegistration: Set<String>] = [.read: lowered(.read), .actions: lowered(.actions), .alerts: []]
        XCTAssertNil(ApprovalProbe.choose(for: .read, approved: everything))
        XCTAssertNil(ApprovalProbe.choose(for: .alerts, approved: everything))
        XCTAssertNil(ApprovalProbe.choose(for: .actions, approved: everything))
    }

    /// A grant one person made for themselves says nothing about a colleague's sign-in.
    /// App protection is signed into unasked only where the organization approved it for
    /// everyone. Its one permission is on a service other than Graph, and a grant records
    /// it by name alone.
    func testAppProtectionCountsAsApprovedOnlyWhenItsPermissionIsGrantedForEveryone() {
        XCTAssertTrue(ApprovalProbe.approvedInFull(.appProtection, approved: [.appProtection: ["devicemanagementmanagedapps.readwrite"]]))
        XCTAssertFalse(ApprovalProbe.approvedInFull(.appProtection, approved: [.appProtection: []]))
        XCTAssertFalse(ApprovalProbe.approvedInFull(.appProtection, approved: [.appProtection: ["user.read"]]))
        XCTAssertFalse(ApprovalProbe.approvedInFull(.appProtection, approved: [.read: ["devicemanagementmanagedapps.readwrite"]]))
        XCTAssertFalse(ApprovalProbe.approvedInFull(.appProtection, approved: nil))
        // A registration that holds nothing to approve is never "approved in full".
        XCTAssertFalse(ApprovalProbe.approvedInFull(.alerts, approved: [.alerts: []]))
        XCTAssertTrue(ApprovalProbe.approvedInFull(.groupMembership, approved: [.groupMembership: ["groupmember.readwrite.all"]]))
    }

    func testOnlyOrganizationWideGrantsCount() {
        let grants = [
            ApprovalProbe.Grant(consentType: "Principal", scope: "GroupMember.ReadWrite.All"),
            ApprovalProbe.Grant(consentType: "AllPrincipals", scope: "User.RevokeSessions.All  User.Read.All"),
            ApprovalProbe.Grant(consentType: "allprincipals", scope: "IdentityRiskyUser.ReadWrite.All"),
            ApprovalProbe.Grant(consentType: nil, scope: nil)
        ]
        XCTAssertEqual(ApprovalProbe.organizationWide(grants),
                       ["user.revokesessions.all", "user.read.all", "identityriskyuser.readwrite.all"])
    }
}
