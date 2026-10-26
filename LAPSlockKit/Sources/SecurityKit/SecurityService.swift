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
// `Prefer: include-unknown-enum-members` goes on every call. Without it Graph hides an
// incident whose status is a newer enum value rather than sending it, and a hidden
// incident is worse than one labelled "Unknown".

public actor SecurityService: SecurityProviding {

    private let graph: GraphClient
    private let now: @Sendable () -> Date

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
