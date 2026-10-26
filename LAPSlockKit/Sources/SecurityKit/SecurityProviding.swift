import Foundation
import AuthKit

// The seam between the Security screens and Microsoft Graph, so the screens can be built
// and reviewed against demo data (App Store Review Guideline 2.1) and tested without a
// tenant that has Defender.

public protocol SecurityProviding: Sendable {
    /// Incidents updated in the window, newest first, each with its alerts and their
    /// evidence. Open and closed alike; the screen filters.
    func incidents() async throws -> [SecurityIncident]
    /// One incident re-read with its alerts, for the detail's refresh.
    func incident(id: String) async throws -> SecurityIncident
    /// Drops anything cached. Called on sign-out and tenant switch.
    func reset() async
}
