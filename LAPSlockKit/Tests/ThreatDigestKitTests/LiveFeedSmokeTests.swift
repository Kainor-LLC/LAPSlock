import XCTest
@testable import ThreatDigestKit

// Hits the real feeds. Skipped unless DIGEST_LIVE=1 is in the environment, so the normal
// run stays offline and deterministic. Run it after a feed changes shape, or when a
// parser is edited:
//
//   DIGEST_LIVE=1 swift test --filter LiveFeedSmokeTests
//
final class LiveFeedSmokeTests: XCTestCase {

    func test_everySourceAnswersAndParses() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["DIGEST_LIVE"] == "1", "set DIGEST_LIVE=1 to run against the real feeds")
        let snapshot = try await ThreatDigestService().digest()
        for status in snapshot.statuses {
            switch status.state {
            case .ok(let count):
                XCTAssertGreaterThan(count, 0, status.source.title)
            case .unavailable(let reason):
                XCTFail(status.source.title + ": " + reason)
            }
        }
        XCTAssertFalse(snapshot.items.isEmpty)
        let ranker = DigestRanker(now: snapshot.fetchedAt)
        let (cards, rest) = ranker.split(ranker.ranked(snapshot.items))
        print("live digest:", snapshot.items.count, "items,", cards.count, "cards,", rest.count, "rest")
        for entry in cards {
            print("  ", entry.ranking.score, entry.item.id, "|", entry.item.title.prefix(70), "|", entry.ranking.signals.map(\.rawValue).joined(separator: ","))
        }
        XCTAssertTrue(snapshot.items.contains { $0.sources.contains(.kev) && $0.sources.contains(.msrc) }, "at least one CVE should merge across KEV and MSRC in any given month")
    }
}
