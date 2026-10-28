import Foundation
import AuthKit
import ActionGateKit
import PrivilegedAccessKit

// Group membership writes. Spec section 3.10, decision D10, phase 3 step G.
//
// Adding a person to a group, or removing them, is the write with the most ways to go
// wrong: a group can carry a role, a licence, an app's access, or a Conditional Access
// exclusion. So the decision is plain code with no network in it, `GroupWritePolicy`,
// tested on its own, and every write goes through the gate like every other.
//
// This target imports Foundation, AuthKit, ActionGateKit and PrivilegedAccessKit (for
// the claims challenge). The isolation guard keeps CredentialKit out of its link graph.

public enum GroupWriteScopes {
    /// The write. The narrow one: membership only, never `Group.ReadWrite.All`.
    public static let write = "GroupMember.ReadWrite.All"
    /// Group properties, licences, app role assignments, the administrative unit's
    /// members, and the groups the signed-in admin owns.
    public static let directory = "Directory.Read.All"
    /// Which Conditional Access policies name a group.
    public static let policies = "Policy.Read.All"
    /// Whether a group is onboarded to PIM for groups.
    public static let pim = "PrivilegedEligibilitySchedule.Read.AzureADGroup"

    public static let module = [write, directory, policies, pim]
    public static let reads = [directory]
}

/// Role templates that can change membership. A group's owner needs none of them.
public enum GroupWriteRoles {
    public static let groupsAdministrator = "fdd7a751-b60b-444a-984c-02652fe8fa1c"
    public static let userAdministrator = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    public static let globalAdministrator = "62e90394-69f5-4237-9190-012177145e10"
    public static let all = [groupsAdministrator, userAdministrator, globalAdministrator]
}

// MARK: - the group

public struct DirectoryGroup: Sendable, Equatable, Identifiable, Decodable {
    public struct License: Sendable, Equatable, Decodable {
        public let skuId: String?
        public init(skuId: String?) { self.skuId = skuId }
    }

    public let id: String
    public let displayName: String?
    public let description: String?
    public let groupTypes: [String]?
    public let isAssignableToRole: Bool?
    public let securityEnabled: Bool?
    public let mailEnabled: Bool?
    public let onPremisesSyncEnabled: Bool?
    public let resourceProvisioningOptions: [String]?
    public let assignedLicenses: [License]?

    public static let selectFields = [
        "id", "displayName", "description", "groupTypes", "isAssignableToRole", "securityEnabled",
        "mailEnabled", "onPremisesSyncEnabled", "resourceProvisioningOptions", "assignedLicenses"
    ]

    public init(id: String, displayName: String?, description: String? = nil, groupTypes: [String]? = nil,
                isAssignableToRole: Bool? = nil, securityEnabled: Bool? = true, mailEnabled: Bool? = false,
                onPremisesSyncEnabled: Bool? = nil, resourceProvisioningOptions: [String]? = nil,
                assignedLicenses: [License]? = nil) {
        self.id = id
        self.displayName = displayName
        self.description = description
        self.groupTypes = groupTypes
        self.isAssignableToRole = isAssignableToRole
        self.securityEnabled = securityEnabled
        self.mailEnabled = mailEnabled
        self.onPremisesSyncEnabled = onPremisesSyncEnabled
        self.resourceProvisioningOptions = resourceProvisioningOptions
        self.assignedLicenses = assignedLicenses
    }

    public var name: String { displayName ?? id }
    public var isDynamic: Bool { groupTypes?.contains("DynamicMembership") ?? false }
    public var isMicrosoft365: Bool { groupTypes?.contains("Unified") ?? false }
    public var isTeam: Bool { resourceProvisioningOptions?.contains("Team") ?? false }
    public var isRoleAssignable: Bool { isAssignableToRole ?? false }
    public var isSynced: Bool { onPremisesSyncEnabled ?? false }
    /// Distribution lists and mail-enabled security groups: Graph cannot change their
    /// members; Exchange can.
    public var isMailOnly: Bool { (mailEnabled ?? false) && !isMicrosoft365 }
    public var assignsLicenses: Bool { !(assignedLicenses ?? []).isEmpty }
}

/// What the app found out about a group beyond its own properties. Each part can be
/// unknown, and unknown is never treated as "fine" where it matters.
public struct GroupFacts: Sendable, Equatable {
    public enum PIM: Sendable, Equatable { case none, eligible, unknown }

    public var inAdministrativeUnit: Bool
    public var ownedByYou: Bool
    /// Conditional Access policies that include the group.
    public var conditionalAccessIncludes: [String]
    /// Conditional Access policies that exclude the group, usually a break-glass or a
    /// trusted-device carve-out. Changing these members changes who a policy skips.
    public var conditionalAccessExcludes: [String]
    public var pim: PIM
    /// Nil when it could not be read.
    public var grantsAppAccess: Bool?
    public var memberCount: Int?

    public init(inAdministrativeUnit: Bool = false, ownedByYou: Bool = false, conditionalAccessIncludes: [String] = [],
                conditionalAccessExcludes: [String] = [], pim: PIM = .none, grantsAppAccess: Bool? = false, memberCount: Int? = nil) {
        self.inAdministrativeUnit = inAdministrativeUnit
        self.ownedByYou = ownedByYou
        self.conditionalAccessIncludes = conditionalAccessIncludes
        self.conditionalAccessExcludes = conditionalAccessExcludes
        self.pim = pim
        self.grantsAppAccess = grantsAppAccess
        self.memberCount = memberCount
    }

    public var conditionalAccessPolicies: [String] { conditionalAccessIncludes + conditionalAccessExcludes }
}

// MARK: - the decision

public enum GroupWriteMode: String, Sendable, Equatable, CaseIterable {
    case tagged, all, none
}

/// A label on a group in the list. Blocking badges say why it cannot be changed here.
public enum GroupBadge: String, Sendable, Equatable, CaseIterable, Identifiable {
    case helpdesk, ownedByYou, roleAssignable, pim, dynamic, synced, mailOnly
    case conditionalAccess, licensing, appAccess, teams, pimUnknown

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .helpdesk:          return "Helpdesk"
        case .ownedByYou:        return "Owned by you"
        case .roleAssignable:    return "Role-assignable"
        case .pim:               return "PIM"
        case .dynamic:           return "Dynamic"
        case .synced:            return "Synced"
        case .mailOnly:          return "Mail"
        case .conditionalAccess: return "Conditional Access"
        case .licensing:         return "Licensing"
        case .appAccess:         return "App access"
        case .teams:             return "Teams"
        case .pimUnknown:        return "PIM unchecked"
        }
    }

    public var isBlocking: Bool {
        switch self {
        case .roleAssignable, .pim, .dynamic, .synced, .mailOnly: return true
        default: return false
        }
    }
}

public struct GroupWriteDecision: Sendable, Equatable {
    /// Nil when the change is allowed.
    public var blockedReason: String?
    /// Said before the confirm, one line each.
    public var warnings: [String]
    /// The group's name typed back, Face ID and the countdown, on top of the confirm.
    public var requiresTypedName: Bool
    public var requiredRoleTemplateIds: [String]
    public var badges: [GroupBadge]

    public var isAllowed: Bool { blockedReason == nil }
    public var tier: ActionTier { requiresTypedName ? .destructive : .confirm }
}

public struct GroupWritePolicy: Sendable, Equatable {
    public var mode: GroupWriteMode
    public var prefix: String?
    public var administrativeUnit: String

    public init(mode: GroupWriteMode, prefix: String? = nil, administrativeUnit: String = "Helpdesk Managed Groups") {
        self.mode = mode
        self.prefix = prefix.flatMap { $0.isEmpty ? nil : $0 }
        self.administrativeUnit = administrativeUnit
    }

    public func isTagged(_ group: DirectoryGroup, _ facts: GroupFacts) -> Bool {
        if facts.inAdministrativeUnit || facts.ownedByYou { return true }
        if let prefix, group.name.lowercased().hasPrefix(prefix.lowercased()) { return true }
        return false
    }

    public func badges(_ group: DirectoryGroup, _ facts: GroupFacts) -> [GroupBadge] {
        var out: [GroupBadge] = []
        if facts.inAdministrativeUnit || (prefix.map { group.name.lowercased().hasPrefix($0.lowercased()) } ?? false) { out.append(.helpdesk) }
        if facts.ownedByYou { out.append(.ownedByYou) }
        if group.isRoleAssignable { out.append(.roleAssignable) }
        if facts.pim == .eligible { out.append(.pim) }
        if facts.pim == .unknown { out.append(.pimUnknown) }
        if group.isDynamic { out.append(.dynamic) }
        if group.isSynced { out.append(.synced) }
        if group.isMailOnly { out.append(.mailOnly) }
        if !facts.conditionalAccessPolicies.isEmpty { out.append(.conditionalAccess) }
        if group.assignsLicenses { out.append(.licensing) }
        if facts.grantsAppAccess == true { out.append(.appAccess) }
        if group.isTeam { out.append(.teams) }
        return out
    }

    /// The same rules for adding and removing: taking someone out of an exclusion group is
    /// as consequential as putting them in.
    public func decide(_ group: DirectoryGroup, _ facts: GroupFacts, adding: Bool) -> GroupWriteDecision {
        let badges = badges(group, facts)
        let roles = facts.ownedByYou ? [] : GroupWriteRoles.all
        func blocked(_ reason: String) -> GroupWriteDecision {
            GroupWriteDecision(blockedReason: reason, warnings: [], requiresTypedName: false, requiredRoleTemplateIds: roles, badges: badges)
        }

        if mode == .none { return blocked("Your organization has turned off group changes in this app.") }
        if group.isRoleAssignable { return blocked("Role-assignable groups grant admin roles. Change them in Entra, with PIM.") }
        if facts.pim == .eligible { return blocked("This group is managed with PIM. Membership comes through PIM, not a direct change.") }
        if group.isDynamic { return blocked("Dynamic group: its rule decides the members.") }
        if group.isSynced { return blocked("Synced from on-premises Active Directory. Change it there.") }
        if group.isMailOnly { return blocked("Distribution lists and mail-enabled security groups are changed in Exchange, not here.") }

        var warnings: [String] = []
        var typed = false
        if !facts.conditionalAccessPolicies.isEmpty {
            if mode == .tagged {
                return blocked("Conditional Access policies name this group (" + facts.conditionalAccessPolicies.joined(separator: ", ") + "). Your organization allows changes to helpdesk groups only.")
            }
            if !facts.conditionalAccessExcludes.isEmpty {
                warnings.append((adding ? "Adding them exempts them from " : "Removing them puts them back under ") + facts.conditionalAccessExcludes.joined(separator: ", ") + ".")
            }
            if !facts.conditionalAccessIncludes.isEmpty {
                warnings.append((adding ? "Adding them brings them under " : "Removing them takes them out of ") + facts.conditionalAccessIncludes.joined(separator: ", ") + ".")
            }
            typed = true
        }
        if mode == .tagged && !isTagged(group, facts) {
            return blocked("Not a helpdesk group. Your organization allows changes to groups in " + administrativeUnit
                           + (prefix.map { ", groups starting " + $0 } ?? "") + ", and groups you own.")
        }
        if facts.pim == .unknown {
            warnings.append("Couldn't check whether PIM manages this group.")
            typed = true
        }
        if group.assignsLicenses { warnings.append(adding ? "This group assigns licenses. Adding them uses a license." : "This group assigns licenses. Removing them takes the license away.") }
        if facts.grantsAppAccess == true { warnings.append("This group grants access to an application.") }
        if facts.grantsAppAccess == nil { warnings.append("Couldn't check whether this group grants app access.") }
        if group.isTeam { warnings.append(adding ? "Teams-connected: they join the team and its files." : "Teams-connected: they leave the team and lose its files.") }
        return GroupWriteDecision(blockedReason: nil, warnings: warnings, requiresTypedName: typed, requiredRoleTemplateIds: roles, badges: badges)
    }
}

// MARK: - the write

public struct GroupMember: Sendable, Equatable {
    public let userId: String
    public let label: String
    public init(userId: String, label: String) {
        self.userId = userId
        self.label = label
    }
}

public enum GroupWriteKind: String, Sendable, Equatable {
    case add, remove

    public var title: String { self == .add ? "Add to group" : "Remove from group" }
    public var actionId: String { "group." + rawValue + "Member" }

    /// POST /groups/{id}/members/$ref, or DELETE /groups/{id}/members/{userId}/$ref.
    public func action(group: DirectoryGroup, member: GroupMember, decision: GroupWriteDecision, strict: Bool) -> WriteAction {
        let request: GraphRequest
        switch self {
        case .add:
            let body = try? JSONSerialization.data(withJSONObject: ["@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/" + member.userId])
            request = GraphRequest(method: .post, path: "/groups/" + group.id + "/members/$ref",
                                   template: "/groups/{id}/members/$ref", body: body, scopes: [GroupWriteScopes.write])
        case .remove:
            request = GraphRequest(method: .delete, path: "/groups/" + group.id + "/members/" + member.userId + "/$ref",
                                   template: "/groups/{id}/members/{userId}/$ref", scopes: [GroupWriteScopes.write])
        }
        let words = self == .add ? member.label + " added to " + group.name + "." : member.label + " removed from " + group.name + "."
        return WriteAction(id: actionId, title: title, tier: decision.tier.effective(strict: strict),
                           target: ActionTarget(label: member.label + " in " + group.name, id: group.id + "/" + member.userId),
                           request: request, requiredRoleTemplateIds: decision.requiredRoleTemplateIds, successCopy: words)
    }
}

// MARK: - providers

/// What is loaded once per session: the helpdesk administrative unit's groups, the groups
/// the admin owns, and which Conditional Access policies name which groups.
public struct GroupWriteContext: Sendable, Equatable {
    public var administrativeUnitGroupIds: Set<String>
    public var administrativeUnitFound: Bool
    public var ownedGroupIds: Set<String>
    /// Group id to policy names.
    public var conditionalAccessIncludes: [String: [String]]
    public var conditionalAccessExcludes: [String: [String]]
    /// False when the policies could not be read; every group then counts as named by one.
    public var conditionalAccessKnown: Bool

    public init(administrativeUnitGroupIds: Set<String> = [], administrativeUnitFound: Bool = false, ownedGroupIds: Set<String> = [],
                conditionalAccessIncludes: [String: [String]] = [:], conditionalAccessExcludes: [String: [String]] = [:],
                conditionalAccessKnown: Bool = true) {
        self.administrativeUnitGroupIds = administrativeUnitGroupIds
        self.administrativeUnitFound = administrativeUnitFound
        self.ownedGroupIds = ownedGroupIds
        self.conditionalAccessIncludes = conditionalAccessIncludes
        self.conditionalAccessExcludes = conditionalAccessExcludes
        self.conditionalAccessKnown = conditionalAccessKnown
    }

    public func facts(for group: DirectoryGroup, pim: GroupFacts.PIM, grantsAppAccess: Bool?, memberCount: Int?) -> GroupFacts {
        var includes = conditionalAccessIncludes[group.id] ?? []
        if !conditionalAccessKnown { includes.append("policies that could not be read") }
        return GroupFacts(inAdministrativeUnit: administrativeUnitGroupIds.contains(group.id),
                          ownedByYou: ownedGroupIds.contains(group.id),
                          conditionalAccessIncludes: includes,
                          conditionalAccessExcludes: conditionalAccessExcludes[group.id] ?? [],
                          pim: pim, grantsAppAccess: grantsAppAccess, memberCount: memberCount)
    }
}

public protocol GroupWritesProviding: Sendable {
    func groups(of member: GroupMember) async throws -> [DirectoryGroup]
    func search(_ text: String) async throws -> [DirectoryGroup]
    func context(administrativeUnit: String) async -> GroupWriteContext
    func facts(for group: DirectoryGroup, in context: GroupWriteContext) async -> GroupFacts
    func run(_ action: WriteAction) async -> ActionOutcome
    func resume(_ action: WriteAction, satisfying challenge: ClaimsChallenge) async -> ActionOutcome
    func lastLogEntry(userId: String) async -> ShiftLogEntry?
    /// The role check on its own, for the review sheet as it opens, so "activate first"
    /// comes before the typed name and Face ID. The check just before sending stays.
    /// Nil means go ahead, as for `ActionRunner.checkRoles`.
    func checkRoles(_ action: WriteAction) async -> ActionOutcome?
}

public extension GroupWritesProviding {
    func checkRoles(_ action: WriteAction) async -> ActionOutcome? { nil }
}

public actor GroupWritesService: GroupWritesProviding {
    private let graph: GraphClient
    private let runner: ActionRunner
    private let log: any ShiftLogging
    private let tenantId: @Sendable () async -> String
    private let now: @Sendable () -> Date
    private var cachedContext: (unit: String, context: GroupWriteContext, readAt: Date)?
    /// How long the context is used before it is read again. A write clears it at once.
    static let contextLasts: TimeInterval = 10 * 60

    public init(graph: GraphClient, runner: ActionRunner, log: any ShiftLogging, tenantId: @escaping @Sendable () async -> String,
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.graph = graph
        self.runner = runner
        self.log = log
        self.tenantId = tenantId
        self.now = now
    }

    private var select: URLQueryItem { URLQueryItem(name: "$select", value: DirectoryGroup.selectFields.joined(separator: ",")) }

    /// GET /users/{id}/memberOf/microsoft.graph.group: direct memberships only, which are
    /// the only ones a membership change can touch. 999 a page, Graph's most, so a person
    /// in a few hundred groups is one request rather than three.
    public func groups(of member: GroupMember) async throws -> [DirectoryGroup] {
        let request = GraphRequest(path: "/users/" + member.userId + "/memberOf/microsoft.graph.group",
                                   template: "/users/{id}/memberOf/microsoft.graph.group",
                                   query: [select, URLQueryItem(name: "$top", value: "999")],
                                   scopes: GroupWriteScopes.reads)
        return try await graph.collection(DirectoryGroup.self, from: request, maxPages: 3).items
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    /// GET /groups?$search, the advanced query, so a word inside the name matches.
    public func search(_ text: String) async throws -> [DirectoryGroup] {
        let cleaned = text.replacingOccurrences(of: "\"", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleaned.count >= 2 else { return [] }
        let request = GraphRequest(path: "/groups", template: "/groups?search",
                                   query: [URLQueryItem(name: "$search", value: "\"displayName:" + cleaned + "\""),
                                           select, URLQueryItem(name: "$top", value: "25"),
                                           URLQueryItem(name: "$count", value: "true")],
                                   headers: ["ConsistencyLevel": "eventual"],
                                   scopes: GroupWriteScopes.reads)
        return try await graph.collection(DirectoryGroup.self, from: request, maxPages: 1).items
    }

    private struct IdOnly: Decodable, Sendable { let id: String }
    private struct UnitRecord: Decodable, Sendable { let id: String }
    private struct PolicyRecord: Decodable, Sendable {
        struct Conditions: Decodable, Sendable {
            struct Users: Decodable, Sendable { let includeGroups: [String]?; let excludeGroups: [String]? }
            let users: Users?
        }
        let displayName: String?
        let state: String?
        let conditions: Conditions?
    }

    /// The three reads run together, and their answer is used for `contextLasts`, or until
    /// a write here changes what they say.
    public func context(administrativeUnit: String) async -> GroupWriteContext {
        if let cached = cachedContext, cached.unit == administrativeUnit, now().timeIntervalSince(cached.readAt) < Self.contextLasts {
            return cached.context
        }
        async let unit = unitGroupIds(administrativeUnit)
        async let owned = ownedGroupIds()
        async let policies = policyRecords()
        var context = GroupWriteContext()
        if let ids = await unit {
            context.administrativeUnitFound = true
            context.administrativeUnitGroupIds = ids
        }
        context.ownedGroupIds = await owned
        if let list = await policies {
            for policy in list where policy.state != "disabled" {
                let name = policy.displayName ?? "an unnamed policy"
                for id in policy.conditions?.users?.includeGroups ?? [] { context.conditionalAccessIncludes[id, default: []].append(name) }
                for id in policy.conditions?.users?.excludeGroups ?? [] { context.conditionalAccessExcludes[id, default: []].append(name) }
            }
        } else {
            context.conditionalAccessKnown = false
        }
        cachedContext = (administrativeUnit, context, now())
        return context
    }

    /// The unit's groups, or nil when there is no unit by that name. A unit whose members
    /// could not be read is found, with no groups, as before.
    private func unitGroupIds(_ administrativeUnit: String) async -> Set<String>? {
        let escaped = administrativeUnit.replacingOccurrences(of: "'", with: "''")
        let unitRequest = GraphRequest(path: "/directory/administrativeUnits", template: "/directory/administrativeUnits?name",
                                       query: [URLQueryItem(name: "$filter", value: "displayName eq '" + escaped + "'"),
                                               URLQueryItem(name: "$select", value: "id")],
                                       scopes: GroupWriteScopes.reads)
        guard let unit = try? await graph.collection(UnitRecord.self, from: unitRequest, maxPages: 1).items.first else { return nil }
        let members = GraphRequest(path: "/directory/administrativeUnits/" + unit.id + "/members/microsoft.graph.group",
                                   template: "/directory/administrativeUnits/{id}/members/microsoft.graph.group",
                                   query: [URLQueryItem(name: "$select", value: "id"), URLQueryItem(name: "$top", value: "999")],
                                   scopes: GroupWriteScopes.reads)
        let ids = (try? await graph.collection(IdOnly.self, from: members, maxPages: 5).items) ?? []
        return Set(ids.map(\.id))
    }

    private func ownedGroupIds() async -> Set<String> {
        let owned = GraphRequest(path: "/me/ownedObjects/microsoft.graph.group", template: "/me/ownedObjects/microsoft.graph.group",
                                 query: [URLQueryItem(name: "$select", value: "id"), URLQueryItem(name: "$top", value: "999")],
                                 scopes: GroupWriteScopes.reads)
        let ids = (try? await graph.collection(IdOnly.self, from: owned, maxPages: 5).items) ?? []
        return Set(ids.map(\.id))
    }

    /// Nil when the policies could not be read.
    private func policyRecords() async -> [PolicyRecord]? {
        let policies = GraphRequest(path: "/identity/conditionalAccess/policies", template: "/identity/conditionalAccess/policies?groups",
                                    query: [URLQueryItem(name: "$select", value: "displayName,state,conditions")],
                                    scopes: [GroupWriteScopes.policies])
        return try? await graph.collection(PolicyRecord.self, from: policies, maxPages: 5).items
    }

    public func facts(for group: DirectoryGroup, in context: GroupWriteContext) async -> GroupFacts {
        async let pim = pimState(group)
        async let apps = appAccess(group)
        async let count = memberCount(group)
        return context.facts(for: group, pim: await pim, grantsAppAccess: await apps, memberCount: await count)
    }

    /// A group onboarded to PIM has eligibility schedules. A 404 means PIM has nothing for
    /// the group, which is "not managed by PIM". Any other failure, such as no permission or
    /// no P2, stays unknown rather than being read as "no".
    private func pimState(_ group: DirectoryGroup) async -> GroupFacts.PIM {
        let request = GraphRequest(path: "/identityGovernance/privilegedAccess/group/eligibilitySchedules",
                                   template: "/identityGovernance/privilegedAccess/group/eligibilitySchedules?groupId",
                                   query: [URLQueryItem(name: "$filter", value: "groupId eq '" + group.id + "'"),
                                           URLQueryItem(name: "$top", value: "1")],
                                   scopes: [GroupWriteScopes.pim])
        do {
            let items = try await graph.collection(IdOnly.self, from: request, maxPages: 1).items
            return items.isEmpty ? .none : .eligible
        } catch GraphError.notFound {
            return .none
        } catch {
            return .unknown
        }
    }

    private func appAccess(_ group: DirectoryGroup) async -> Bool? {
        let request = GraphRequest(path: "/groups/" + group.id + "/appRoleAssignments", template: "/groups/{id}/appRoleAssignments",
                                   query: [URLQueryItem(name: "$top", value: "1"), URLQueryItem(name: "$select", value: "id")],
                                   scopes: GroupWriteScopes.reads)
        guard let items = try? await graph.collection(IdOnly.self, from: request, maxPages: 1).items else { return nil }
        return !items.isEmpty
    }

    private func memberCount(_ group: DirectoryGroup) async -> Int? {
        let request = GraphRequest(path: "/groups/" + group.id + "/members/$count", template: "/groups/{id}/members/$count",
                                   headers: ["ConsistencyLevel": "eventual"], scopes: GroupWriteScopes.reads)
        guard let response = try? await graph.send(request),
              let text = String(data: response.data, encoding: .utf8) else { return nil }
        return Int(text.trimmingCharacters(in: .whitespacesAndNewlines).filter(\.isNumber))
    }

    public func run(_ action: WriteAction) async -> ActionOutcome {
        let outcome = await runner.run(action)
        if outcome.isRequested { cachedContext = nil }
        return outcome
    }

    public func resume(_ action: WriteAction, satisfying challenge: ClaimsChallenge) async -> ActionOutcome {
        await runner.resume(action, satisfying: challenge)
    }

    public func checkRoles(_ action: WriteAction) async -> ActionOutcome? {
        await runner.checkRoles(action)
    }

    public func lastLogEntry(userId: String) async -> ShiftLogEntry? {
        let tenant = await tenantId()
        return await log.entries(tenantId: tenant).first { $0.targetId.hasSuffix("/" + userId) }
    }
}

/// Demo: one group for every badge, so a reviewer sees each rule. Changes land in memory.
public actor DemoGroupWritesProvider: GroupWritesProviding {
    public static let tenant = "demo"
    private let latency: Duration
    private let log = InMemoryShiftLog()
    private var memberships: [String: Set<String>] = [:]

    public static let groups: [DirectoryGroup] = [
        DirectoryGroup(id: "g-hd-vpn", displayName: "HD-VPN Users", description: "Remote access"),
        DirectoryGroup(id: "g-hd-printers", displayName: "HD-Floor 3 Printers", description: "Printer queues"),
        DirectoryGroup(id: "g-sales", displayName: "Sales Team", description: "Sales", groupTypes: ["Unified"], mailEnabled: true,
                       resourceProvisioningOptions: ["Team"]),
        DirectoryGroup(id: "g-e5", displayName: "License - Microsoft 365 E5", assignedLicenses: [.init(skuId: "demo-sku")]),
        DirectoryGroup(id: "g-bg", displayName: "CA Exclusion - Break Glass"),
        DirectoryGroup(id: "g-mfa", displayName: "CA - Require MFA Pilot"),
        DirectoryGroup(id: "g-helpdesk-admins", displayName: "Helpdesk Admins", isAssignableToRole: true),
        DirectoryGroup(id: "g-all-staff", displayName: "All Staff (dynamic)", groupTypes: ["DynamicMembership"]),
        DirectoryGroup(id: "g-ad-finance", displayName: "Finance (AD)", onPremisesSyncEnabled: true),
        DirectoryGroup(id: "g-dl", displayName: "Announcements", securityEnabled: false, mailEnabled: true),
        DirectoryGroup(id: "g-pim-ops", displayName: "Ops On-Call (PIM)"),
        DirectoryGroup(id: "g-salesforce", displayName: "Salesforce Users")
    ]

    /// The large demo tenant: everyone is in 300 groups, and each group's facts take as
    /// long as the three reads behind them would.
    private let large: [DirectoryGroup]?

    public init(latency: Duration = .seconds(1), large: Bool = false) {
        self.latency = latency
        self.large = large ? Self.largeGroups() : nil
    }

    public func groups(of member: GroupMember) async throws -> [DirectoryGroup] {
        try? await Task.sleep(for: .milliseconds(300))
        if let large { return large.sorted { $0.name < $1.name } }
        let ids = memberships[member.userId] ?? ["g-hd-vpn", "g-sales", "g-e5", "g-mfa", "g-all-staff", "g-salesforce"]
        if memberships[member.userId] == nil { memberships[member.userId] = ids }
        return Self.groups.filter { ids.contains($0.id) }.sorted { $0.name < $1.name }
    }

    public func search(_ text: String) async throws -> [DirectoryGroup] {
        try? await Task.sleep(for: .milliseconds(300))
        let needle = text.lowercased()
        guard needle.count >= 2 else { return [] }
        return ((large ?? []) + Self.groups).filter { $0.name.lowercased().contains(needle) }.prefix(25).map { $0 }
    }

    public func context(administrativeUnit: String) async -> GroupWriteContext {
        GroupWriteContext(administrativeUnitGroupIds: ["g-hd-printers"], administrativeUnitFound: true,
                          ownedGroupIds: ["g-sales"],
                          conditionalAccessIncludes: ["g-mfa": ["Require MFA for pilot users"]],
                          conditionalAccessExcludes: ["g-bg": ["Require MFA for all users", "Block legacy authentication"]])
    }

    public func facts(for group: DirectoryGroup, in context: GroupWriteContext) async -> GroupFacts {
        try? await Task.sleep(for: .milliseconds(large == nil ? 200 : 450))
        let pim: GroupFacts.PIM = group.id == "g-pim-ops" ? .eligible : .none
        return context.facts(for: group, pim: pim, grantsAppAccess: group.id == "g-salesforce",
                             memberCount: group.name.count * 3)
    }

    public func run(_ action: WriteAction) async -> ActionOutcome {
        try? await Task.sleep(for: latency)
        let parts = action.target.id.split(separator: "/").map(String.init)
        if parts.count == 2 {
            if action.id.hasSuffix("addMember") { memberships[parts[1], default: []].insert(parts[0]) }
            else { memberships[parts[1], default: []].remove(parts[0]) }
        }
        await log.append(ShiftLogEntry(at: Date(), tenantId: Self.tenant, actionId: action.id, actionTitle: action.title,
                                       targetLabel: action.target.label, targetId: action.target.id,
                                       outcome: "requested", requestId: "demo"))
        return .requested(requestId: "demo")
    }

    public func resume(_ action: WriteAction, satisfying challenge: ClaimsChallenge) async -> ActionOutcome {
        await run(action)
    }

    public func lastLogEntry(userId: String) async -> ShiftLogEntry? {
        await log.entries(tenantId: Self.tenant).first { $0.targetId.hasSuffix("/" + userId) }
    }
}
