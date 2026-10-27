import Foundation
import AuthKit

// Security incidents over Microsoft Graph, through the shared GraphClient. Read-only.
//
// One call does the work: the incident list with `$expand=alerts`, which carries each
// alert's evidence on v1.0, so the module runs on the incident scope alone and never asks
// for the alert scope. The list is bounded two ways: a window on `lastUpdateDateTime`,
// because a large tenant's resolved history is thousands of rows and not the phone's job,
// and a page budget. Graph offers no `$orderby` here, so the sort happens on the phone.
//
// The screen's filter, open only and the severity floor, is sent with the request, so a
// tenant's closed and low-severity incidents cannot use up the page budget ahead of an
// open high one. A tenant that refuses the filter gets today's unfiltered read instead,
// remembered for the session, and the screen filters what arrives either way.
//
// `Prefer: include-unknown-enum-members` goes on every call. Without it Graph hides an
// incident whose status is a newer enum value rather than sending it, and a hidden
// incident is worse than one labelled "Unknown".

public actor SecurityService: SecurityProviding {

    private let graph: GraphClient
    private let now: @Sendable () -> Date
    /// Set when Graph refused the filter once; the session then reads unfiltered.
    private var serverFilterRefused = false

    public init(graph: GraphClient, now: @escaping @Sendable () -> Date = { Date() }) {
        self.graph = graph
        self.now = now
    }

    public static let incidentsPath = "/security/incidents"
    /// How far back the list looks, by last update.
    public static let windowDays = 30
    public static let pageSize = 50
    public static let preferHeader = ["Prefer": "include-unknown-enum-members"]

    public func incidents() async throws -> [SecurityIncident] {
        let since = now().addingTimeInterval(-TimeInterval(Self.windowDays) * 86_400)
        let request = GraphRequest(
            path: Self.incidentsPath,
            template: Self.incidentsPath + "?expand=alerts",
            query: [
                URLQueryItem(name: "$expand", value: "alerts"),
                URLQueryItem(name: "$filter", value: "lastUpdateDateTime ge " + Self.stamp(since)),
                URLQueryItem(name: "$top", value: String(Self.pageSize))
            ],
            headers: Self.preferHeader,
            scopes: SecurityScopes.module)
        do {
            let page = try await graph.collection(SecurityIncident.self, from: request, maxPages: 2)
            return page.items.sorted(by: Self.newestFirst)
        } catch let error as GraphError {
            throw SecurityError(error)
        }
    }

    public func incidents(matching filter: SecurityFilter) async throws -> IncidentList {
        let window = "lastUpdateDateTime ge " + Self.stamp(now().addingTimeInterval(-TimeInterval(Self.windowDays) * 86_400))
        if !serverFilterRefused, let clause = Self.serverClause(for: filter) {
            do {
                return try await list(listRequest(filter: window + " and " + clause), filter: filter)
            } catch GraphError.badRequest {
                serverFilterRefused = true
            } catch let error as GraphError {
                throw SecurityError(error)
            }
        }
        do {
            return try await list(listRequest(filter: window), filter: filter)
        } catch let error as GraphError {
            throw SecurityError(error)
        }
    }

    public func moreIncidents(after cursor: URL, matching filter: SecurityFilter) async throws -> IncidentList {
        do {
            let page = try await graph.collection(
                SecurityIncident.self, at: cursor, like: listRequest(filter: ""), maxPages: 2)
            return IncidentList(incidents: filter.apply(page.items).sorted(by: Self.newestFirst), more: page.nextLink)
        } catch let error as GraphError {
            throw SecurityError(error)
        }
    }

    private func list(_ request: GraphRequest, filter: SecurityFilter) async throws -> IncidentList {
        let page = try await graph.collection(SecurityIncident.self, from: request, maxPages: 2)
        return IncidentList(incidents: filter.apply(page.items).sorted(by: Self.newestFirst), more: page.nextLink)
    }

    private func listRequest(filter: String) -> GraphRequest {
        var query = [URLQueryItem(name: "$expand", value: "alerts")]
        if !filter.isEmpty { query.append(URLQueryItem(name: "$filter", value: filter)) }
        query.append(URLQueryItem(name: "$top", value: String(Self.pageSize)))
        return GraphRequest(
            path: Self.incidentsPath,
            template: Self.incidentsPath + "?expand=alerts&filter",
            query: query,
            headers: Self.preferHeader,
            scopes: SecurityScopes.module)
    }

    /// The part of a filter Graph can apply. Open matches `isOpen`: everything but
    /// resolved and redirected, so a status Graph adds later still counts as open.
    static func serverClause(for filter: SecurityFilter) -> String? {
        var clauses: [String] = []
        if filter.openOnly {
            clauses.append("status ne 'resolved' and status ne 'redirected'")
        }
        switch filter.severity {
        case .all:         break
        case .mediumAndUp: clauses.append("(severity eq 'medium' or severity eq 'high')")
        case .highOnly:    clauses.append("severity eq 'high'")
        }
        return clauses.isEmpty ? nil : clauses.joined(separator: " and ")
    }

    public func incident(id: String) async throws -> SecurityIncident {
        // The id goes into the path, so it must be the plain number Graph uses. Anything
        // else is refused here rather than sent.
        guard Self.isIncidentId(id) else { throw SecurityError.transport(status: 400) }
        let request = GraphRequest(
            path: Self.incidentsPath + "/" + id,
            template: Self.incidentsPath + "/{id}?expand=alerts",
            query: [URLQueryItem(name: "$expand", value: "alerts")],
            headers: Self.preferHeader,
            scopes: SecurityScopes.module)
        do {
            return try await graph.decode(SecurityIncident.self, from: request)
        } catch let error as GraphError {
            throw SecurityError(error)
        }
    }

    public func reset() {}

    /// Last activity first; ties and unknowns fall to severity, then title.
    public static func newestFirst(_ a: SecurityIncident, _ b: SecurityIncident) -> Bool {
        switch (a.lastActivity, b.lastActivity) {
        case let (x?, y?) where x != y: return x > y
        case (nil, _?):                 return false
        case (_?, nil):                 return true
        default:
            if a.severity != b.severity { return a.severity > b.severity }
            return a.title.localizedCaseInsensitiveCompare(b.title) == .orderedAscending
        }
    }

    /// Graph incident ids are decimal numbers.
    public static func isIncidentId(_ id: String) -> Bool {
        !id.isEmpty && id.count <= 20 && id.allSatisfy(\.isNumber)
    }

    static func stamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}
