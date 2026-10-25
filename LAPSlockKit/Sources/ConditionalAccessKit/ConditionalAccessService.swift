import Foundation
import AuthKit

// Conditional Access over Microsoft Graph, through the shared GraphClient. Read-only.
//
// Four lookups turn ids into names, each on the endpoint that owns the object: users and
// groups through getByIds, roles through the role templates (a policy names a role by its
// template id, not by an activated role's id), applications through service principals by
// appId (a policy names an app by its appId, not by any object id), and locations through
// the tenant's named locations. One failing is not the module failing: the policy list is
// the point, names are a courtesy, and a 403 on service principals leaves the app ids on
// screen rather than taking the list down.
//
// Audit entries come from the directory audit log and need a scope the policy list does
// not, so they are fetched only when asked for.

public actor ConditionalAccessService: ConditionalAccessProviding {

    private let graph: GraphClient
    private var nameCache: [DirectoryReference: String] = [:]
    /// Whether the role templates were fetched once this session.
    private var roleTemplatesLoaded = false
    private var locationsLoaded = false

    public init(graph: GraphClient) {
        self.graph = graph
    }

    public static let policiesPath = "/identity/conditionalAccess/policies"
    public static let namedLocationsPath = "/identity/conditionalAccess/namedLocations"
    public static let getByIdsPath = "/directoryObjects/getByIds"
    public static let roleTemplatesPath = "/directoryRoleTemplates"
    public static let servicePrincipalsPath = "/servicePrincipals"
    public static let directoryAuditsPath = "/auditLogs/directoryAudits"

    // MARK: - policies

    public func policies() async throws -> [ConditionalAccessPolicy] {
        let request = GraphRequest(
            path: Self.policiesPath,
            scopes: ConditionalAccessScopes.module)
        do {
            let page = try await graph.collection(ConditionalAccessPolicy.self, from: request, maxPages: 10)
            return page.items.sorted(by: Self.newestChangeFirst)
        } catch let error as GraphError {
            throw ConditionalAccessError(error)
        }
    }

    static func newestChangeFirst(_ a: ConditionalAccessPolicy, _ b: ConditionalAccessPolicy) -> Bool {
        switch (a.lastChanged, b.lastChanged) {
        case let (x?, y?) where x != y: return x > y
        case (nil, _?):                 return false
        case (_?, nil):                 return true
        default:                        return a.displayName.localizedCaseInsensitiveCompare(b.displayName) == .orderedAscending
        }
    }

    // MARK: - names

    public func names(for references: Set<DirectoryReference>) async throws -> [DirectoryReference: String] {
        let missing = references.filter { nameCache[$0] == nil }
        if !missing.isEmpty {
            let byKind = Dictionary(grouping: missing, by: \.kind)
            async let objects = resolveObjects(byKind[.user, default: []] + byKind[.group, default: []])
            async let roles = resolveRoles(byKind[.role, default: []])
            async let apps = resolveApplications(byKind[.application, default: []])
            async let locations = resolveLocations(byKind[.location, default: []])
            for resolved in await [objects, roles, apps, locations] {
                nameCache.merge(resolved) { _, new in new }
            }
        }
        var result: [DirectoryReference: String] = [:]
        for reference in references {
            if let name = nameCache[reference] { result[reference] = name }
        }
        return result
    }

    public func reset() {
        nameCache.removeAll()
        roleTemplatesLoaded = false
        locationsLoaded = false
    }

    /// Users and groups, by id, in batches of at most 1000, which is Graph's limit per call.
    private func resolveObjects(_ refs: [DirectoryReference]) async -> [DirectoryReference: String] {
        guard !refs.isEmpty else { return [:] }
        var found: [DirectoryReference: String] = [:]
        let byId = Dictionary(refs.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        for chunk in Array(byId.keys).chunked(1000) {
            let body = try? JSONSerialization.data(withJSONObject: ["ids": chunk, "types": ["user", "group"]])
            let request = GraphRequest(
                method: .post,
                path: Self.getByIdsPath,
                body: body,
                scopes: ConditionalAccessScopes.module)
            guard let page = try? await graph.collection(DirectoryObjectName.self, from: request, maxPages: 1) else { continue }
            for object in page.items {
                if let ref = byId[object.id], let name = object.displayName { found[ref] = name }
            }
        }
        return found
    }

    /// Role templates, fetched once per session: the tenant has about a hundred and a
    /// policy may name any of them.
    private func resolveRoles(_ refs: [DirectoryReference]) async -> [DirectoryReference: String] {
        guard !refs.isEmpty, !roleTemplatesLoaded else { return [:] }
        let request = GraphRequest(
            path: Self.roleTemplatesPath,
            query: [URLQueryItem(name: "$select", value: "id,displayName")],
            scopes: ConditionalAccessScopes.module)
        guard let page = try? await graph.collection(DirectoryObjectName.self, from: request, maxPages: 3) else { return [:] }
        roleTemplatesLoaded = true
        var found: [DirectoryReference: String] = [:]
        for template in page.items {
            if let name = template.displayName {
                found[DirectoryReference(kind: .role, id: template.id)] = name
            }
        }
        return found
    }

    /// Service principals by appId, in small batches so the filter stays inside the URL
    /// length Graph accepts.
    private func resolveApplications(_ refs: [DirectoryReference]) async -> [DirectoryReference: String] {
        guard !refs.isEmpty else { return [:] }
        var found: [DirectoryReference: String] = [:]
        let byAppId = Dictionary(refs.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        for chunk in Array(byAppId.keys).chunked(15) {
            let list = chunk.map { "'" + $0 + "'" }.joined(separator: ",")
            let request = GraphRequest(
                path: Self.servicePrincipalsPath,
                template: Self.servicePrincipalsPath + "?appId",
                query: [
                    URLQueryItem(name: "$filter", value: "appId in (" + list + ")"),
                    URLQueryItem(name: "$select", value: "appId,displayName")
                ],
                scopes: ConditionalAccessScopes.module)
            guard let page = try? await graph.collection(ServicePrincipalName.self, from: request, maxPages: 1) else { continue }
            for principal in page.items {
                if let appId = principal.appId, let ref = byAppId[appId], let name = principal.displayName {
                    found[ref] = name
                }
            }
        }
        return found
    }

    /// Named locations, fetched once per session.
    private func resolveLocations(_ refs: [DirectoryReference]) async -> [DirectoryReference: String] {
        guard !refs.isEmpty, !locationsLoaded else { return [:] }
        let request = GraphRequest(
            path: Self.namedLocationsPath,
            query: [URLQueryItem(name: "$select", value: "id,displayName")],
            scopes: ConditionalAccessScopes.module)
        guard let page = try? await graph.collection(DirectoryObjectName.self, from: request, maxPages: 3) else { return [:] }
        locationsLoaded = true
        var found: [DirectoryReference: String] = [:]
        for location in page.items {
            if let name = location.displayName {
                found[DirectoryReference(kind: .location, id: location.id)] = name
            }
        }
        return found
    }

    private struct DirectoryObjectName: Decodable, Sendable {
        let id: String
        let displayName: String?
    }

    private struct ServicePrincipalName: Decodable, Sendable {
        let appId: String?
        let displayName: String?
    }

    // MARK: - who changed this

    public func changes(forPolicyId policyId: String) async throws -> [PolicyChange] {
        // The id goes into a filter string, so it must be exactly a GUID. Anything else
        // is refused here rather than sent.
        guard ConditionalAccessVocabulary.isDirectoryId(policyId) else { return [] }
        let request = GraphRequest(
            path: Self.directoryAuditsPath,
            template: Self.directoryAuditsPath + "?policy",
            query: [
                URLQueryItem(name: "$filter", value: "targetResources/any(t: t/id eq '" + policyId + "')"),
                URLQueryItem(name: "$orderby", value: "activityDateTime desc"),
                URLQueryItem(name: "$top", value: "25")
            ],
            scopes: ConditionalAccessScopes.changes)
        do {
            let page = try await graph.collection(AuditEntry.self, from: request, maxPages: 1)
            return page.items.map { $0.change }
        } catch let error as GraphError {
            throw ConditionalAccessError(error)
        }
    }

    struct AuditEntry: Decodable, Sendable {
        struct InitiatedBy: Decodable, Sendable {
            struct User: Decodable, Sendable {
                let userPrincipalName: String?
                let displayName: String?
            }
            struct App: Decodable, Sendable {
                let displayName: String?
                let servicePrincipalName: String?
            }
            let user: User?
            let app: App?
        }
        struct Target: Decodable, Sendable {
            struct Property: Decodable, Sendable {
                let displayName: String?
            }
            let id: String?
            let modifiedProperties: [Property]?
        }

        let id: String
        let activityDisplayName: String?
        let activityDateTime: Date?
        let result: String?
        let initiatedBy: InitiatedBy?
        let targetResources: [Target]?

        var change: PolicyChange {
            let actor = initiatedBy?.user?.userPrincipalName
                ?? initiatedBy?.user?.displayName
                ?? initiatedBy?.app?.displayName
                ?? initiatedBy?.app?.servicePrincipalName
            let properties = (targetResources ?? [])
                .flatMap { $0.modifiedProperties ?? [] }
                .compactMap(\.displayName)
            return PolicyChange(
                id: id,
                activity: activityDisplayName ?? "Change",
                at: activityDateTime,
                actor: actor,
                result: result,
                changedProperties: properties)
        }
    }
}

extension Array {
    func chunked(_ size: Int) -> [[Element]] {
        guard size > 0, !isEmpty else { return isEmpty ? [] : [self] }
        return stride(from: 0, to: count, by: size).map { Array(self[$0..<Swift.min($0 + size, count)]) }
    }
}
