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

    /// Which validators each feed sends, and whether a second read with them is a 304.
    /// Reported rather than asserted: the servers decide, and the digest works either way.
    func test_whatASecondReadOfEachFeedCosts() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["DIGEST_LIVE"] == "1", "set DIGEST_LIVE=1 to run against the real feeds")
        let service = ThreatDigestService()
        let at = Date()
        for source in [DigestSource.kev, .msrc, .cisaAlert, .cisaAdvisory] {
            let url = ThreatDigestService.url(for: source, now: at)
            let first = try await service.exchange(url)
            print("validators:", source.title, "| ETag", first.etag ?? "none", "| Last-Modified", first.lastModified ?? "none", "|", first.data.count, "bytes")
            guard first.etag != nil || first.lastModified != nil else { continue }
            let second = try await service.exchange(url, etag: first.etag, lastModified: first.lastModified)
            print("second read:", source.title, "|", second.notModified ? "304, nothing downloaded" : "downloaded again, " + String(second.data.count) + " bytes")
        }
    }
}
