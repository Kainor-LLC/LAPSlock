import Foundation
import AuthKit

// The seam between the Security screens and Microsoft Graph, so the screens can be built
// and reviewed against demo data (App Store Review Guideline 2.1) and tested without a
// tenant that has Defender.

public protocol SecurityProviding: Sendable {
    /// Incidents updated in the window, newest first, each with its alerts and their
    /// evidence. Open and closed alike; the screen filters.
    func incidents() async throws -> [SecurityIncident]
    /// Incidents in the window that `filter` lets through, newest first, and whether more
    /// matched than were read. A requirement with a default, so a provider that cannot
    /// filter on the server still answers correctly by filtering what it has.
    func incidents(matching filter: SecurityFilter) async throws -> IncidentList
    /// The same list without alerts or evidence, for a first paint while
    /// `incidents(matching:)` reads them. Nil when the provider has no such read, or Graph
    /// refused it this session; the caller then waits for the full list.
    func incidentSummaries(matching filter: SecurityFilter) async throws -> IncidentList?
    /// The next incidents after a list that said there were more.
    func moreIncidents(after cursor: URL, matching filter: SecurityFilter) async throws -> IncidentList
    /// One incident re-read with its alerts, for the detail's refresh.
    func incident(id: String) async throws -> SecurityIncident
    /// Drops anything cached. Called on sign-out and tenant switch.
    func reset() async
}

public extension SecurityProviding {
    func incidents(matching filter: SecurityFilter) async throws -> IncidentList {
        IncidentList(incidents: filter.apply(try await incidents()), more: nil)
    }

    func moreIncidents(after cursor: URL, matching filter: SecurityFilter) async throws -> IncidentList {
        IncidentList(incidents: [], more: nil)
    }

    func incidentSummaries(matching filter: SecurityFilter) async throws -> IncidentList? { nil }
}

/// One read of the incident list.
public struct IncidentList: Sendable, Equatable {
    public var incidents: [SecurityIncident]
    /// Where the list continues when more incidents matched than were read; nil when
    /// this is all of them. The screen must say so rather than present a partial list as
    /// the whole.
    public var more: URL?

    public init(incidents: [SecurityIncident], more: URL?) {
        self.incidents = incidents
        self.more = more
    }
}
