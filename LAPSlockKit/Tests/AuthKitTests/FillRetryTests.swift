import XCTest
import Foundation
@testable import AuthKit

final class FillRetryTests: XCTestCase {

    func testAPassingFailureWaitsOneThreeAndNineSecondsThenStops() {
        XCTAssertEqual(FillRetry.wait(after: .transient, failures: 1, jitter: 0), 1)
        XCTAssertEqual(FillRetry.wait(after: .transient, failures: 2, jitter: 0), 3)
        XCTAssertEqual(FillRetry.wait(after: .transient, failures: 3, jitter: 0), 9)
        XCTAssertNil(FillRetry.wait(after: .transient, failures: 4, jitter: 0), "four attempts at a page, no more")
    }

    func testJitterOnlyEverLengthensAWait() {
        for failures in 1...3 {
            let short = FillRetry.wait(after: .transient, failures: failures, jitter: 0)!
            let long = FillRetry.wait(after: .transient, failures: failures, jitter: 1)!
            XCTAssertEqual(long, short * 1.25, accuracy: 0.0001)
        }
        // Out-of-range jitter is clamped, so a wait is never negative or shortened.
        XCTAssertEqual(FillRetry.wait(after: .transient, failures: 1, jitter: -5), 1)
        XCTAssertEqual(FillRetry.wait(after: .throttled(retryAfter: 10), failures: 1, jitter: -5), 10)
    }

    /// Asking again before the time Graph named only earns another 429.
    func testAThrottledPageIsNeverAskedForSoonerThanGraphSaid() {
        XCTAssertEqual(FillRetry.wait(after: .throttled(retryAfter: 30), failures: 1, jitter: 0), 30)
        XCTAssertEqual(FillRetry.wait(after: .throttled(retryAfter: 30), failures: 1, jitter: 1), 31)
        XCTAssertEqual(FillRetry.wait(after: .throttled(retryAfter: nil), failures: 1, jitter: 0), FillRetry.defaultThrottleWait)
        XCTAssertEqual(FillRetry.wait(after: .throttled(retryAfter: 60), failures: 3, jitter: 0), 60)
    }

    /// A long Retry-After means Graph wants this tenant left alone, and the fill is a
    /// background job sharing a budget with the person's own taps.
    func testAWaitLongerThanAMinuteStopsInsteadOfBeingCutShort() {
        XCTAssertNil(FillRetry.wait(after: .throttled(retryAfter: 61), failures: 1, jitter: 0))
        XCTAssertNil(FillRetry.wait(after: .throttled(retryAfter: 600), failures: 1, jitter: 0))
        XCTAssertNil(FillRetry.wait(after: .throttled(retryAfter: 5), failures: 4, jitter: 0))
    }
}
