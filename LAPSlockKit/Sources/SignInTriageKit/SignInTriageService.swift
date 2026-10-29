import Foundation
import AuthKit

// Sign-in triage over Microsoft Graph, through the shared GraphClient. Read-only.
//
//   GET /auditLogs/signIns?$filter=...&$top=N   AuditLog.Read.All (+ Policy.Read.All for the
//                                               applied policies to be present)
//   GET /users?$filter=startswith(...)          User.ReadBasic.All
//   GET /users?$select=...&$top=999             User.ReadBasic.All, the whole directory
//
// The log is returned newest first by default and $orderby is not supported on it, so the
// order is taken as delivered. Report-only policy results need the unknown-enum header or
// Graph hides them, and a report-only block is exactly what a triage wants to see.
//
// "Failures only" is asked of Graph first (OPTIMIZATION-PLAN.md, step G): each sign-in
// carries every Conditional Access result, so five times the rows filtered on the phone
// is megabytes. A tenant where Graph refuses the clause is filtered here for the session.

public actor SignInTriageService: SignInTriageProviding {

    private let graph: GraphClient
    /// Set when Graph refused "failures only" once; the session then filters on the phone.
    private var failureFilterRefused = false

    public init(graph: GraphClient) {
        self.graph = graph
    }

    public static let signInsPath = "/auditLogs/signIns"
    public static let usersPath = "/users"

    public func searchUsers(prefix: String) async throws -> [DirectoryUser] {
        let trimmed = prefix.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 2 else { return [] }
        let escaped = SignInQuery.escape(trimmed)
        let request = GraphRequest(
            path: Self.usersPath,
            template: Self.usersPath + "?search",
            query: [
                URLQueryItem(name: "$filter", value: "startswith(displayName,'" + escaped + "') or startswith(userPrincipalName,'" + escaped + "')"),
                URLQueryItem(name: "$select", value: "id,displayName,userPrincipalName,mail"),
                URLQueryItem(name: "$top", value: "10")
            ],
            scopes: [SignInTriageScopes.users])
        do {
            let page = try await graph.collection(DirectoryUser.self, from: request, maxPages: 1)
            return page.items.sorted { ($0.displayName ?? "") .localizedCaseInsensitiveCompare($1.displayName ?? "") == .orderedAscending }
        } catch let error as GraphError {
            throw SignInTriageError(error)
        }
    }

    /// Graph's largest page for users, so a 5,000-person directory is six requests.
    public static let directoryPageSize = 999

    public func directoryPage(after next: URL?) async throws -> DirectoryPage {
        let request = GraphRequest(
            path: Self.usersPath,
            template: Self.usersPath + "?directory",
            query: [
                URLQueryItem(name: "$select", value: "id,displayName,userPrincipalName,mail"),
                URLQueryItem(name: "$top", value: String(Self.directoryPageSize))
            ],
            scopes: [SignInTriageScopes.users])
        do {
            let page: GraphCollection<DirectoryUser>
            if let next {
                page = try await graph.collection(DirectoryUser.self, at: next, like: request, maxPages: 1)
            } else {
                page = try await graph.collection(DirectoryUser.self, from: request, maxPages: 1)
            }
            return DirectoryPage(users: page.items, next: page.nextLink)
        } catch let error as GraphError {
            throw SignInTriageError(error)
        }
    }

    public func signIns(_ query: SignInQuery) async throws -> [SignInEvent] {
        do {
            if query.failuresOnly && !failureFilterRefused {
                do {
                    let page = try await graph.collection(
                        SignInEvent.self,
                        from: request(filter: query.serverFilter(), top: query.limit, template: "?user&failures"),
                        maxPages: 1)
                    return query.apply(page.items)
                } catch GraphError.badRequest {
                    failureFilterRefused = true
                }
            }
            let page = try await graph.collection(
                SignInEvent.self, from: request(filter: query.filter(), top: query.fetchCount, template: "?user"), maxPages: 1)
            return query.apply(page.items)
        } catch let error as GraphError {
            throw SignInTriageError(error)
        }
    }

    private func request(filter: String, top: Int, template: String) -> GraphRequest {
        GraphRequest(
            path: Self.signInsPath,
            template: Self.signInsPath + template,
            query: [
                URLQueryItem(name: "$filter", value: filter),
                URLQueryItem(name: "$top", value: String(top))
            ],
            headers: ["Prefer": "include-unknown-enum-members"],
            scopes: [SignInTriageScopes.signIns, SignInTriageScopes.policies])
    }
}
