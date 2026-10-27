import XCTest
@testable import SecurityKit

final class DemoSecurityProviderTests: XCTestCase {

    private let now = Date()

    func test_fixturesCoverEverySeverityStatusAndEvidenceKind() async throws {
        let provider = DemoSecurityProvider(latency: .milliseconds(1), now: now)
        let incidents = try await provider.incidents()
        XCTAssertEqual(incidents.count, 5)
        for severity in SecuritySeverity.allCases where severity != .unknown {
            XCTAssertTrue(incidents.contains { $0.severity == severity }, severity.rawValue)
        }
        XCTAssertTrue(incidents.contains { $0.status == .active })
        XCTAssertTrue(incidents.contains { $0.status == .inProgress })
        XCTAssertTrue(incidents.contains { $0.status == .resolved })
        XCTAssertTrue(incidents.contains { $0.status == .awaitingAction })
        XCTAssertTrue(incidents.contains { $0.assignedTo == nil })
        XCTAssertTrue(incidents.contains { $0.assignedTo != nil })
        let titles = Set(incidents.flatMap(\.evidence).map(\.kindTitle))
        XCTAssertEqual(titles, Set(AlertEvidence.Kind.displayOrder.map(\.title)))
        XCTAssertTrue(incidents.flatMap(\.alerts).contains { $0.evidence.isEmpty })
        XCTAssertTrue(incidents.flatMap(\.alerts).contains { $0.recommendedActionLines.count > 2 })
        XCTAssertTrue(incidents.flatMap(\.alerts).contains { !$0.mitreTechniques.isEmpty })
    }

    func test_newestFirstPutsThePhishingIncidentOnTop() async throws {
        let provider = DemoSecurityProvider(latency: .milliseconds(1), now: now)
        let incidents = try await provider.incidents()
        XCTAssertEqual(incidents.first?.id, DemoSecurityProvider.phishingId)
        XCTAssertEqual(incidents.last?.id, DemoSecurityProvider.resolvedId)
    }

    func test_theDefaultFilterHidesTheResolvedOne() async throws {
        let provider = DemoSecurityProvider(latency: .milliseconds(1), now: now)
        let open = SecurityFilter.standard.apply(try await provider.incidents())
        XCTAssertEqual(open.count, 4)
        XCTAssertFalse(open.contains { $0.id == DemoSecurityProvider.resolvedId })
    }

    func test_crossLinksHaveSomethingToPointAt() async throws {
        let provider = DemoSecurityProvider(latency: .milliseconds(1), now: now)
        let incidents = try await provider.incidents()
        let evidence = incidents.flatMap(\.evidence)
        XCTAssertTrue(evidence.contains { $0.userPrincipalName == DemoSecurityProvider.phishedUser })
        XCTAssertTrue(evidence.contains { $0.deviceHostName == "LT-FIELD-207" })
    }

    func test_incidentByIdAndAMissingOne() async throws {
        let provider = DemoSecurityProvider(latency: .milliseconds(1), now: now)
        let found = try await provider.incident(id: DemoSecurityProvider.endpointId)
        XCTAssertEqual(found.alerts.count, 1)
        do {
            _ = try await provider.incident(id: "1")
            XCTFail("expected 404")
        } catch {
            XCTAssertEqual(error as? SecurityError, .transport(status: 404))
        }
    }

    func test_fixtureIdsLookLikeGraphIncidentIds() {
        for incident in DemoSecurityProvider.incidents(now: now) {
            XCTAssertTrue(SecurityService.isIncidentId(incident.id), incident.id)
        }
    }

    func test_fixtureProseHasNoEmDashes() {
        for incident in DemoSecurityProvider.incidents(now: now) {
            XCTAssertFalse((incident.summary ?? "").contains("\u{2014}"), incident.id)
            for alert in incident.alerts {
                XCTAssertFalse((alert.recommendedActions ?? "").contains("\u{2014}"), alert.id)
                XCTAssertFalse((alert.description ?? "").contains("\u{2014}"), alert.id)
            }
        }
    }

    func test_theQuietCustomerHasNoIncidents() async throws {
        let provider = DemoSecurityProvider(latency: .milliseconds(1), now: now, quiet: true)
        let incidents = try await provider.incidents()
        XCTAssertTrue(incidents.isEmpty)
        do {
            _ = try await provider.incident(id: DemoSecurityProvider.phishingId)
            XCTFail("the first customer's incident must not open in the second")
        } catch {}
    }
}
