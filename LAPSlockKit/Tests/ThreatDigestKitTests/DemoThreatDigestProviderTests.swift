import XCTest
@testable import ThreatDigestKit

final class DemoThreatDigestProviderTests: XCTestCase {

    private let now = DigestDates.parse("2026-10-25T12:00:00Z")!

    func test_fixturesExerciseEverySignal() async throws {
        let snapshot = try await DemoThreatDigestProvider(latency: .milliseconds(1), now: now).digest()
        let ranker = DigestRanker(now: now)
        let signals = Set(snapshot.items.flatMap { ranker.rank($0).signals })
        XCTAssertEqual(signals, Set(DigestSignal.allCases), "missing: \(Set(DigestSignal.allCases).subtracting(signals))")
    }

    func test_theMergedCardCarriesBothSourcesAndTheAnnouncementDissolved() async throws {
        let snapshot = try await DemoThreatDigestProvider(latency: .milliseconds(1), now: now).digest()
        let merged = try XCTUnwrap(snapshot.items.first { $0.id == DemoThreatDigestProvider.mergedCVE })
        XCTAssertEqual(merged.sources, [.kev, .msrc, .cisaAlert])
        XCTAssertEqual(merged.links.count, 3)
        XCTAssertFalse(snapshot.items.contains { $0.id == "cisaAlert:/node/90101" })
        XCTAssertTrue(snapshot.items.contains { $0.id == "cisaAlert:/node/90088" })
    }

    func test_cardsAndRestSplitAndTheOtherVendorIsHiddenByTheDefaultFilter() async throws {
        let snapshot = try await DemoThreatDigestProvider(latency: .milliseconds(1), now: now).digest()
        let ranker = DigestRanker(now: now)
        let (cards, rest) = ranker.split(ranker.ranked(snapshot.items))
        XCTAssertFalse(cards.isEmpty)
        XCTAssertFalse(rest.isEmpty)
        XCTAssertEqual(cards.first?.item.id, DemoThreatDigestProvider.ransomwareCVE, "ransomware plus exploited plus overdue outranks everything")
        XCTAssertTrue(cards.contains { $0.item.id == DemoThreatDigestProvider.mergedCVE })
        let microsoftOnly = snapshot.items.filter { $0.kind == .advisory || $0.isMicrosoft }
        XCTAssertFalse(microsoftOnly.contains { $0.id == DemoThreatDigestProvider.otherVendorCVE })
        XCTAssertTrue(snapshot.items.contains { $0.id == DemoThreatDigestProvider.otherVendorCVE })
    }

    func test_unavailableSourceVariant() async throws {
        let snapshot = try await DemoThreatDigestProvider(latency: .milliseconds(1), now: now, msrcUnavailable: true).digest()
        XCTAssertEqual(snapshot.unavailable.map(\.source), [.msrc])
        XCTAssertFalse(snapshot.items.contains { $0.id == DemoThreatDigestProvider.disclosedCVE })
    }

    func test_fixtureProseHasNoEmDashes() async throws {
        let snapshot = try await DemoThreatDigestProvider(latency: .milliseconds(1), now: now).digest()
        for item in snapshot.items {
            XCTAssertFalse(item.summary.contains("\u{2014}"), item.id)
            XCTAssertFalse(item.title.contains("\u{2014}"), item.id)
        }
    }
}
