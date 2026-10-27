import Foundation
import AuthKit
import PrivilegedAccessKit

// The role gate. Spec section 4: before any write, check the active role assignments, and
// if the required role is eligible but not active, offer activation inline instead of
// letting Graph return 403.
//
// The gate is a courtesy, not the authority. Microsoft decides whether the write is
// allowed; the gate exists so the person hears "activate Intune Administrator" before the
// call rather than "forbidden" after it. When the gate cannot read (no opt-in to the PIM
// scopes, no network), the runner proceeds and the 403 path offers activation instead.

public protocol RoleGateChecking: Sendable {
    /// Role template ids the signed-in person holds right now, assigned or activated.
    /// Throws when it cannot tell.
    func activeRoleTemplateIds() async throws -> Set<String>
    /// What the person could activate. Empty when nothing, or when PIM is not opted in.
    func eligibleAccess() async -> [EligibleAccess]
}

/// Live: the current person's role assignment schedule instances, which is exactly their
/// own active roles and needs no directory-wide read.
public struct GraphRoleGate: RoleGateChecking {

    public static let instancesPath = "/roleManagement/directory/roleAssignmentScheduleInstances/filterByCurrentUser(on='principal')"
    /// The ReadWrite scope the PIM opt-in already consented to, so the gate never adds a
    /// consent prompt of its own. Least privilege on the page is
    /// `RoleAssignmentSchedule.Read.Directory`; asking for it would prompt again for a
    /// strict subset of what was granted.
    public static let scope = PrivilegedAccessGraph.roleActivateScope

    private let graph: GraphClient
    private let privileged: any PrivilegedAccessProviding

    public init(graph: GraphClient, privileged: any PrivilegedAccessProviding) {
        self.graph = graph
        self.privileged = privileged
    }

    public func activeRoleTemplateIds() async throws -> Set<String> {
        let request = GraphRequest(
            path: Self.instancesPath,
            query: [URLQueryItem(name: "$select", value: "roleDefinitionId,assignmentType,endDateTime")],
            scopes: [Self.scope])
        let page = try await graph.collection(Instance.self, from: request, maxPages: 2)
        let now = Date()
        // Built-in role definition ids are the role template ids, the same GUIDs in every
        // tenant, which is what makes a table of required roles possible at all.
        return Set(page.items.compactMap { instance in
            if let end = instance.endDateTime, end < now { return nil }
            return instance.roleDefinitionId?.lowercased()
        })
    }

    public func eligibleAccess() async -> [EligibleAccess] {
        (try? await privileged.eligibleAccess()) ?? []
    }

    /// The person's roles active right now, by name, with when each ends (nil for a
    /// permanent assignment), soonest ending first. For the Apple Watch glance.
    public func activeRoles() async throws -> [ActiveRole] {
        let request = GraphRequest(
            path: Self.instancesPath,
            template: "/roleManagement/directory/roleAssignmentScheduleInstances/filterByCurrentUser(principal)?names",
            query: [URLQueryItem(name: "$select", value: "roleDefinitionId,assignmentType,endDateTime"),
                    URLQueryItem(name: "$expand", value: "roleDefinition($select=displayName)")],
            scopes: [Self.scope])
        let now = Date()
        let items = try await graph.collection(NamedInstance.self, from: request, maxPages: 2).items
        return items.compactMap { item in
            if let end = item.endDateTime, end < now { return nil }
            return ActiveRole(name: item.roleDefinition?.displayName ?? "A directory role", endsAt: item.endDateTime,
                              activated: (item.assignmentType ?? "").caseInsensitiveCompare("Activated") == .orderedSame)
        }
        .sorted { ($0.endsAt ?? .distantFuture) < ($1.endsAt ?? .distantFuture) }
    }

    struct Instance: Decodable, Sendable {
        let roleDefinitionId: String?
        let assignmentType: String?
        let endDateTime: Date?
    }

    struct NamedInstance: Decodable, Sendable {
        struct Definition: Decodable, Sendable { let displayName: String? }
        let assignmentType: String?
        let endDateTime: Date?
        let roleDefinition: Definition?
    }
}

/// A role the person holds now. `activated` is true for a PIM activation, false for a
/// standing assignment.
public struct ActiveRole: Sendable, Equatable {
    public let name: String
    public let endsAt: Date?
    public let activated: Bool
    public init(name: String, endsAt: Date?, activated: Bool) {
        self.name = name
        self.endsAt = endsAt
        self.activated = activated
    }
}

/// Decides nothing and offers nothing: for demo mode and for tenants without the PIM opt-in.
public struct NoRoleGate: RoleGateChecking {
    public init() {}
    public func activeRoleTemplateIds() async throws -> Set<String> {
        throw ActionGateError.gateUnavailable
    }
    public func eligibleAccess() async -> [EligibleAccess] { [] }
}

public enum ActionGateError: Error, Sendable, Equatable {
    case gateUnavailable
}
