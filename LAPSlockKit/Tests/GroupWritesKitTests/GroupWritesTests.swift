import XCTest
import AuthKit
import ActionGateKit
@testable import GroupWritesKit

final class GroupWritePolicyTests: XCTestCase {

    private let tagged = GroupWritePolicy(mode: .tagged, prefix: "HD-")
    private let all = GroupWritePolicy(mode: .all)
    private let plain = DirectoryGroup(id: "g1", displayName: "VPN Users")
    private let prefixed = DirectoryGroup(id: "g2", displayName: "HD-VPN Users")

    func testNoneAllowsNothing() {
        let decision = GroupWritePolicy(mode: .none).decide(prefixed, GroupFacts(ownedByYou: true), adding: true)
        XCTAssertFalse(decision.isAllowed)
    }

    func testHardBlocksApplyInEveryModeEvenToOwnedGroups() {
        let owned = GroupFacts(inAdministrativeUnit: true, ownedByYou: true)
        let blocked = [
            DirectoryGroup(id: "r", displayName: "HD-Admins", isAssignableToRole: true),
            DirectoryGroup(id: "d", displayName: "HD-All", groupTypes: ["DynamicMembership"]),
            DirectoryGroup(id: "s", displayName: "HD-Finance", onPremisesSyncEnabled: true),
            DirectoryGroup(id: "m", displayName: "HD-Announce", securityEnabled: false, mailEnabled: true)
        ]
        for policy in [tagged, all] {
            for group in blocked {
                XCTAssertFalse(policy.decide(group, owned, adding: true).isAllowed, group.name + " in " + policy.mode.rawValue)
                XCTAssertFalse(policy.decide(group, owned, adding: false).isAllowed, group.name + " removing")
            }
            XCTAssertFalse(policy.decide(prefixed, GroupFacts(ownedByYou: true, pim: .eligible), adding: true).isAllowed)
        }
    }

    func testAMicrosoft365GroupIsNotMailOnly() {
        let m365 = DirectoryGroup(id: "u", displayName: "HD-Team", groupTypes: ["Unified"], mailEnabled: true)
        XCTAssertFalse(m365.isMailOnly)
        XCTAssertTrue(tagged.decide(m365, GroupFacts(), adding: true).isAllowed)
    }

    func testTaggedAllowsTheUnitThePrefixAndOwnedGroupsOnly() {
        XCTAssertFalse(tagged.decide(plain, GroupFacts(), adding: true).isAllowed)
        XCTAssertTrue(tagged.decide(plain, GroupFacts(inAdministrativeUnit: true), adding: true).isAllowed)
        XCTAssertTrue(tagged.decide(plain, GroupFacts(ownedByYou: true), adding: true).isAllowed)
        XCTAssertTrue(tagged.decide(prefixed, GroupFacts(), adding: true).isAllowed)
        XCTAssertTrue(tagged.decide(DirectoryGroup(id: "x", displayName: "hd-lower"), GroupFacts(), adding: true).isAllowed, "the prefix ignores case")
        XCTAssertTrue(all.decide(plain, GroupFacts(), adding: true).isAllowed)
    }

    func testConditionalAccessBlocksInTaggedAndNeedsTheTypedNameInAll() {
        let excluded = GroupFacts(inAdministrativeUnit: true, conditionalAccessExcludes: ["Require MFA for all users"])
        XCTAssertFalse(tagged.decide(prefixed, excluded, adding: true).isAllowed)
        let decision = all.decide(plain, excluded, adding: true)
        XCTAssertTrue(decision.isAllowed)
        XCTAssertTrue(decision.requiresTypedName)
        XCTAssertEqual(decision.tier, .destructive)
        XCTAssertTrue(decision.warnings.contains { $0.contains("exempts them from Require MFA for all users") })
        XCTAssertTrue(all.decide(plain, excluded, adding: false).warnings.contains { $0.contains("puts them back under") })
    }

    func testUnreadablePoliciesCountAsAReference() {
        let context = GroupWriteContext(administrativeUnitGroupIds: ["g2"], conditionalAccessKnown: false)
        let facts = context.facts(for: prefixed, pim: .none, grantsAppAccess: false, memberCount: 3)
        XCTAssertFalse(tagged.decide(prefixed, facts, adding: true).isAllowed)
        XCTAssertTrue(all.decide(prefixed, facts, adding: true).requiresTypedName)
    }

    func testUnknownPIMWarnsAndNeedsTheTypedName() {
        let decision = tagged.decide(prefixed, GroupFacts(pim: .unknown), adding: true)
        XCTAssertTrue(decision.isAllowed)
        XCTAssertTrue(decision.requiresTypedName)
        XCTAssertTrue(decision.badges.contains(.pimUnknown))
    }

    func testLicensingAppsAndTeamsWarnWithoutTheTypedName() {
        let group = DirectoryGroup(id: "t", displayName: "HD-Sales", groupTypes: ["Unified"], mailEnabled: true,
                                   resourceProvisioningOptions: ["Team"], assignedLicenses: [.init(skuId: "s")])
        let decision = tagged.decide(group, GroupFacts(grantsAppAccess: true), adding: true)
        XCTAssertTrue(decision.isAllowed)
        XCTAssertFalse(decision.requiresTypedName)
        XCTAssertEqual(decision.tier, .confirm)
        XCTAssertEqual(decision.warnings.count, 3)
        XCTAssertEqual(Set(decision.badges), [.helpdesk, .licensing, .appAccess, .teams])
        XCTAssertTrue(tagged.decide(prefixed, GroupFacts(grantsAppAccess: nil), adding: true).warnings.contains { $0.contains("Couldn't check") })
    }

    func testOwnersNeedNoRoleOthersNeedAGroupsRole() {
        XCTAssertEqual(tagged.decide(plain, GroupFacts(ownedByYou: true), adding: true).requiredRoleTemplateIds, [])
        XCTAssertEqual(tagged.decide(prefixed, GroupFacts(), adding: true).requiredRoleTemplateIds, GroupWriteRoles.all)
    }
}

final class GroupWriteActionTests: XCTestCase {

    private let group = DirectoryGroup(id: "g1", displayName: "HD-VPN Users")
    private let member = GroupMember(userId: "u1", label: "jane@example.com")
    private let decision = GroupWritePolicy(mode: .tagged, prefix: "HD-").decide(DirectoryGroup(id: "g1", displayName: "HD-VPN Users"), GroupFacts(), adding: true)

    func testAddPostsAReferenceToTheMember() throws {
        let action = GroupWriteKind.add.action(group: group, member: member, decision: decision, strict: false)
        XCTAssertEqual(action.request.method, .post)
        XCTAssertEqual(action.request.path, "/groups/g1/members/$ref")
        XCTAssertEqual(action.request.template, "/groups/{id}/members/$ref")
        XCTAssertEqual(action.request.scopes, ["GroupMember.ReadWrite.All"])
        let body = try XCTUnwrap(action.request.body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: String])
        XCTAssertEqual(json["@odata.id"], "https://graph.microsoft.com/v1.0/directoryObjects/u1")
        XCTAssertEqual(action.tier, .confirm)
    }

    func testRemoveDeletesTheReference() {
        let action = GroupWriteKind.remove.action(group: group, member: member, decision: decision, strict: false)
        XCTAssertEqual(action.request.method, .delete)
        XCTAssertEqual(action.request.path, "/groups/g1/members/u1/$ref")
        XCTAssertEqual(action.request.template, "/groups/{id}/members/{userId}/$ref")
        XCTAssertNil(action.request.body)
    }

    func testStrictMovesConfirmToDestructive() {
        XCTAssertEqual(GroupWriteKind.add.action(group: group, member: member, decision: decision, strict: true).tier, .destructive)
    }

    func testTheWriteNeverAsksForGroupReadWriteAll() {
        XCTAssertFalse(GroupWriteScopes.module.contains("Group.ReadWrite.All"))
        XCTAssertFalse(GroupWriteScopes.module.contains("Directory.ReadWrite.All"))
    }
}

final class DemoGroupWritesTests: XCTestCase {

    func testEveryBadgeIsShownSomewhereInTheDemo() async throws {
        let demo = DemoGroupWritesProvider(latency: .zero)
        let policy = GroupWritePolicy(mode: .tagged, prefix: "HD-")
        let context = await demo.context(administrativeUnit: "Helpdesk Managed Groups")
        var seen = Set<GroupBadge>()
        for group in DemoGroupWritesProvider.groups {
            let facts = await demo.facts(for: group, in: context)
            seen.formUnion(policy.badges(group, facts))
        }
        XCTAssertEqual(seen, Set(GroupBadge.allCases).subtracting([.pimUnknown]))
    }

    func testAddingAndRemovingChangesTheDemoMemberships() async throws {
        let demo = DemoGroupWritesProvider(latency: .zero)
        let member = GroupMember(userId: "u9", label: "a@demo.example")
        let before = try await demo.groups(of: member).map(\.id)
        XCTAssertFalse(before.contains("g-hd-printers"))
        let printers = try XCTUnwrap(DemoGroupWritesProvider.groups.first { $0.id == "g-hd-printers" })
        let policy = GroupWritePolicy(mode: .tagged, prefix: "HD-")
        let context = await demo.context(administrativeUnit: "x")
        let decision = policy.decide(printers, await demo.facts(for: printers, in: context), adding: true)
        _ = await demo.run(GroupWriteKind.add.action(group: printers, member: member, decision: decision, strict: false))
        let after = try await demo.groups(of: member).map(\.id)
        XCTAssertTrue(after.contains("g-hd-printers"))
        let entry = await demo.lastLogEntry(userId: "u9")
        XCTAssertEqual(entry?.actionId, "group.addMember")
    }
}
