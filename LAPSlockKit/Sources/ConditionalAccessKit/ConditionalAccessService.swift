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
//
// A reference Graph answered for without a name, such as a deleted group or an app with
// no service principal here, is remembered until `reset()`, so a refresh does not ask for
// it again (OPTIMIZATION-PLAN.md, step G). One whose lookup failed is asked again.

public actor ConditionalAccessService: ConditionalAccessProviding {

    private let graph: GraphClient
    private var nameCache: [DirectoryReference: String] = [:]
    /// References Graph answered for without a name, this session.
    private var unresolved: Set<DirectoryReference> = []
    /// Whether the role templates were fetched once this session.
    private var roleTemplatesLoaded = false
    private var locationsLoaded = false
    /// Set when Graph refused `$select` on getByIds; the session then asks without it.
    private var objectSelectRefused = false
    /// Service principal lookups in flight at once. HTTP/2 carries them on one connection.
    static let lookupWidth = 4

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

    /// When a policy last changed, and nothing else.
    public struct PolicyStamp: Decodable, Sendable, Equatable {
        public let id: String
        public let createdDateTime: Date?
        public let modifiedDateTime: Date?
        public var lastChanged: Date? { modifiedDateTime ?? createdDateTime }

        public init(id: String, createdDateTime: Date?, modifiedDateTime: Date?) {
            self.id = id
            self.createdDateTime = createdDateTime
            self.modifiedDateTime = modifiedDateTime
        }
    }

    /// Every policy's id and change times, for the background check, which needs no more
    /// to tell a change: not every condition and control of every policy. Falls back to
    /// the full read when Graph refuses the `$select`.
    public func policyStamps() async throws -> [PolicyStamp] {
        let request = GraphRequest(
            path: Self.policiesPath,
            template: Self.policiesPath + "?select=stamps",
            query: [URLQueryItem(name: "$select", value: "id,createdDateTime,modifiedDateTime")],
            scopes: ConditionalAccessScopes.module)
        do {
            return try await graph.collection(PolicyStamp.self, from: request, maxPages: 10).items
        } catch GraphError.badRequest {
            return try await policies().map {
                PolicyStamp(id: $0.id, createdDateTime: $0.createdDateTime, modifiedDateTime: $0.modifiedDateTime)
            }
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
        let missing = references.filter { nameCache[$0] == nil && !unresolved.contains($0) }
        if !missing.isEmpty {
            let byKind = Dictionary(grouping: missing, by: \.kind)
            async let objects = resolveObjects(byKind[.user, default: []] + byKind[.group, default: []])
            async let roles = resolveRoles(byKind[.role, default: []])
            async let apps = resolveApplications(byKind[.application, default: []])
            async let locations = resolveLocations(byKind[.location, default: []])
            for resolution in await [objects, roles, apps, locations] {
                nameCache.merge(resolution.found) { _, new in new }
                unresolved.formUnion(resolution.answered.filter { resolution.found[$0] == nil && nameCache[$0] == nil })
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
        unresolved.removeAll()
        roleTemplatesLoaded = false
        locationsLoaded = false
        objectSelectRefused = false
    }

    /// What one lookup found, and every reference Graph answered for, named or not.
    private struct Resolution: Sendable {
        var found: [DirectoryReference: String] = [:]
        var answered: Set<DirectoryReference> = []

        mutating func merge(_ other: Resolution) {
            found.merge(other.found) { _, new in new }
            answered.formUnion(other.answered)
        }
    }

    /// Users and groups, by id, in batches of at most 1000, which is Graph's limit per call.
    private func resolveObjects(_ refs: [DirectoryReference]) async -> Resolution {
        guard !refs.isEmpty else { return Resolution() }
        var resolution = Resolution()
        let byId = Dictionary(refs.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        for chunk in Array(byId.keys).chunked(1000) {
            resolution.merge(await objects(chunk, byId))
        }
        return resolution
    }

    /// One getByIds call, with the id and name only unless this tenant refused that.
    private func objects(_ chunk: [String], _ byId: [String: DirectoryReference]) async -> Resolution {
        let body = try? JSONSerialization.data(withJSONObject: ["ids": chunk, "types": ["user", "group"]])
        let select = !objectSelectRefused
        let request = GraphRequest(
            method: .post,
            path: Self.getByIdsPath,
            template: Self.getByIdsPath + (select ? "?select" : ""),
            query: select ? [URLQueryItem(name: "$select", value: "id,displayName")] : [],
            body: body,
            scopes: ConditionalAccessScopes.module,
            readOnly: true)
        let page: GraphCollection<DirectoryObjectName>
        do {
            page = try await graph.collection(DirectoryObjectName.self, from: request, maxPages: 1)
        } catch GraphError.badRequest where select {
            objectSelectRefused = true
            return await objects(chunk, byId)
        } catch {
            return Resolution()
        }
        var resolution = Resolution(answered: Set(chunk.compactMap { byId[$0] }))
        for object in page.items {
            if let ref = byId[object.id], let name = object.displayName { resolution.found[ref] = name }
        }
        return resolution
    }

    /// Role templates, fetched once per session: the tenant has about a hundred and a
    /// policy may name any of them. Once they are in, a role not among them is a miss.
    private func resolveRoles(_ refs: [DirectoryReference]) async -> Resolution {
        guard !refs.isEmpty else { return Resolution() }
        guard !roleTemplatesLoaded else { return Resolution(answered: Set(refs)) }
        let request = GraphRequest(
            path: Self.roleTemplatesPath,
            query: [URLQueryItem(name: "$select", value: "id,displayName")],
            scopes: ConditionalAccessScopes.module)
        guard let page = try? await graph.collection(DirectoryObjectName.self, from: request, maxPages: 3) else { return Resolution() }
        roleTemplatesLoaded = true
        var resolution = Resolution(answered: Set(refs))
        for template in page.items {
            if let name = template.displayName {
                resolution.found[DirectoryReference(kind: .role, id: template.id)] = name
            }
        }
        return resolution
    }

    /// Service principals by appId, in small batches so the filter stays inside the URL
    /// length Graph accepts, `lookupWidth` of them at a time rather than one after another.
    private func resolveApplications(_ refs: [DirectoryReference]) async -> Resolution {
        guard !refs.isEmpty else { return Resolution() }
        let byAppId = Dictionary(refs.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var waiting = Array(byAppId.keys).chunked(15)[...]
        var resolution = Resolution()
        await withTaskGroup(of: Resolution.self) { group in
            for _ in 0..<Self.lookupWidth {
                guard let chunk = waiting.popFirst() else { break }
                group.addTask { await self.applications(chunk, byAppId) }
            }
            for await done in group {
                resolution.merge(done)
                if let chunk = waiting.popFirst() {
                    group.addTask { await self.applications(chunk, byAppId) }
                }
            }
        }
        return resolution
    }

    private func applications(_ chunk: [String], _ byAppId: [String: DirectoryReference]) async -> Resolution {
        let list = chunk.map { "'" + $0 + "'" }.joined(separator: ",")
        let request = GraphRequest(
            path: Self.servicePrincipalsPath,
            template: Self.servicePrincipalsPath + "?appId",
            query: [
                URLQueryItem(name: "$filter", value: "appId in (" + list + ")"),
                URLQueryItem(name: "$select", value: "appId,displayName")
            ],
            scopes: ConditionalAccessScopes.module)
        guard let page = try? await graph.collection(ServicePrincipalName.self, from: request, maxPages: 1) else { return Resolution() }
        var resolution = Resolution(answered: Set(chunk.compactMap { byAppId[$0] }))
        for principal in page.items {
            if let appId = principal.appId, let ref = byAppId[appId], let name = principal.displayName {
                resolution.found[ref] = name
            }
        }
        return resolution
    }

    /// Named locations, fetched once per session. Once they are in, a location not among
    /// them is a miss.
    private func resolveLocations(_ refs: [DirectoryReference]) async -> Resolution {
        guard !refs.isEmpty else { return Resolution() }
        guard !locationsLoaded else { return Resolution(answered: Set(refs)) }
        let request = GraphRequest(
            path: Self.namedLocationsPath,
            query: [URLQueryItem(name: "$select", value: "id,displayName")],
            scopes: ConditionalAccessScopes.module)
        guard let page = try? await graph.collection(DirectoryObjectName.self, from: request, maxPages: 3) else { return Resolution() }
        locationsLoaded = true
        var resolution = Resolution(answered: Set(refs))
        for location in page.items {
            if let name = location.displayName {
                resolution.found[DirectoryReference(kind: .location, id: location.id)] = name
            }
        }
        return resolution
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
