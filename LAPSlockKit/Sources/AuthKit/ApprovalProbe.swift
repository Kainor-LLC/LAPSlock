import Foundation

// Which registration an organization's writes go through.
//
// An organization approves writes one of two ways: the separate registration for a kind
// of action, or the one registration that holds them all (`AppRegistration.actions`). The
// app has to know which before it asks Microsoft for anything, because finding out by
// asking goes wrong both ways. A technician asked to sign into a registration their
// organization never approved lands on Microsoft's "need admin approval" page with nowhere
// to go, and an administrator on that page can approve it there and then, which is how an
// organization that chose one app ends up with two.
//
// So the app reads the answer: the organization's own record of what it has approved for
// everyone. That takes `Directory.Read.All` through the read registration, which an
// organization grants with Conditional Access or group reads. When it cannot be read the
// answer is "cannot tell", never a guess, and the caller falls back to the separate
// registration, which is the narrower of the two.

public struct ApprovalProbe: Sendable {

    public static let scope = "Directory.Read.All"

    private let graph: GraphClient

    public init(graph: GraphClient) {
        self.graph = graph
    }

    /// The permissions this organization has approved for everyone on each of
    /// `registrations`, lowercased. A registration absent from the organization has an
    /// empty set. Nil when the organization's approvals cannot be read at all.
    public func approvedScopes(for registrations: [AppRegistration]) async -> [AppRegistration: Set<String>]? {
        guard !registrations.isEmpty else { return [:] }
        let ids = registrations.map { "'" + $0.clientId + "'" }.joined(separator: ",")
        let principals = GraphRequest(
            path: "/servicePrincipals",
            query: [URLQueryItem(name: "$filter", value: "appId in (" + ids + ")"),
                    URLQueryItem(name: "$select", value: "id,appId")],
            scopes: [Self.scope])
        guard let found = try? await graph.collection(Principal.self, from: principals, maxPages: 1).items else { return nil }

        var approved: [AppRegistration: Set<String>] = Dictionary(uniqueKeysWithValues: registrations.map { ($0, []) })
        for principal in found {
            guard let registration = registrations.first(where: { $0.clientId.lowercased() == principal.appId?.lowercased() }) else { continue }
            let grants = GraphRequest(
                path: "/servicePrincipals/" + principal.id + "/oauth2PermissionGrants",
                template: "/servicePrincipals/{id}/oauth2PermissionGrants",
                query: [URLQueryItem(name: "$select", value: "consentType,scope")],
                scopes: [Self.scope])
            guard let items = try? await graph.collection(Grant.self, from: grants, maxPages: 2).items else { return nil }
            approved[registration] = Self.organizationWide(items)
        }
        return approved
    }

    /// Only grants made for the whole organization count. A grant one person made for
    /// themselves says nothing about what a colleague's sign-in will be allowed.
    static func organizationWide(_ grants: [Grant]) -> Set<String> {
        var scopes: Set<String> = []
        for grant in grants where (grant.consentType ?? "").caseInsensitiveCompare("AllPrincipals") == .orderedSame {
            for scope in (grant.scope ?? "").split(separator: " ") { scopes.insert(scope.lowercased()) }
        }
        return scopes
    }

    /// The registration to use for one kind of write, from what was approved.
    ///
    /// The separate registration when the organization approved it, because its token is
    /// the narrower. The combined one only when it was approved and the separate one was
    /// not. Nil when neither was, or nothing could be read: the caller cannot tell.
    public static func choose(
        for home: AppRegistration,
        approved: [AppRegistration: Set<String>]?
    ) -> AppRegistration? {
        guard AppRegistration.separateWrites.contains(home), let approved else { return nil }
        let needed = Set(home.scopes.map { $0.lowercased() })
        if let own = approved[home], needed.isSubset(of: own) { return home }
        if let all = approved[.actions], needed.isSubset(of: all) { return .actions }
        return nil
    }

    /// Whether the organization approved, for everyone, every permission `registration`
    /// holds, on Microsoft Graph or on another Microsoft service. False when it holds
    /// none, when it was not approved, and when the approvals could not be read.
    public static func approvedInFull(
        _ registration: AppRegistration,
        approved: [AppRegistration: Set<String>]?
    ) -> Bool {
        guard let own = approved?[registration] else { return false }
        // A grant records a permission by its name alone, without the service in front.
        let needed = Set((registration.scopes + registration.serviceScopes.map(Self.name)).map { $0.lowercased() })
        return !needed.isEmpty && needed.isSubset(of: own)
    }

    static func name(_ qualified: String) -> String {
        qualified.split(separator: "/").last.map(String.init) ?? qualified
    }

    struct Principal: Decodable, Sendable {
        let id: String
        let appId: String?
    }

    struct Grant: Decodable, Sendable, Equatable {
        let consentType: String?
        let scope: String?
    }
}
