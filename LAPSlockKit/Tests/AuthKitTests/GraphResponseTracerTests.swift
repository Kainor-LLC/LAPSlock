import XCTest
@testable import AuthKit

/// Attribution rules for Graph's `request-id`.
///
/// The stakes are specific: this id goes into a support report that a customer hands to
/// Microsoft, and Microsoft looks it up. An id attributed to the wrong failure sends them
/// to an unrelated request, which is worse than sending nothing — so every rule here
/// refuses rather than guesses.
final class GraphResponseTracerTests: XCTestCase {

    private var tracer: GraphResponseTracer!

    override func setUp() {
        super.setUp()
        // A fresh instance per test rather than `.shared`: these tests must not depend on
        // each other's order, and a global would make them do exactly that.
        tracer = GraphResponseTracer()
    }

    private let guid = "1f2e3d4c-1111-2222-3333-444455556666"

    func test_aRecordedFailureIsAttributedWhenTheStatusAgrees() {
        tracer.recordFailure(requestId: guid, httpStatus: 403)
        XCTAssertEqual(tracer.attributableRequestId(httpStatus: 403), guid)
    }

    func test_aDisagreeingStatusIsADifferentRequest() {
        // The event says 500, the trace says 403. They cannot be the same request, so the
        // id is withheld rather than attached to the wrong one.
        tracer.recordFailure(requestId: guid, httpStatus: 403)
        XCTAssertNil(tracer.attributableRequestId(httpStatus: 500))
    }

    func test_anEventWithNoStatusStillGetsTheId() {
        // A transport failure or a decode failure has no HTTP status of its own, but the
        // response that caused it did. Withholding here would lose the common case.
        tracer.recordFailure(requestId: guid, httpStatus: 429)
        XCTAssertEqual(tracer.attributableRequestId(httpStatus: nil), guid)
    }

    func test_aStaleTraceIsNotAttributed() {
        // A last-seen box cannot prove the id belongs to this event, so age is a hard limit.
        tracer.recordFailure(requestId: guid, httpStatus: 403)
        let muchLater = Date().addingTimeInterval(GraphResponseTracer.attributionWindow + 5)
        XCTAssertNil(tracer.attributableRequestId(httpStatus: 403, now: muchLater))
        // Just inside the window still counts.
        let justInside = Date().addingTimeInterval(GraphResponseTracer.attributionWindow - 1)
        XCTAssertEqual(tracer.attributableRequestId(httpStatus: 403, now: justInside), guid)
    }

    func test_nothingRecordedYieldsNothing() {
        XCTAssertNil(tracer.attributableRequestId(httpStatus: 403))
    }

    func test_aMissingOrBlankHeaderRecordsNothing() {
        // Graph does not always send the header. An empty string must not become a
        // "request id" that support then tries to look up.
        tracer.recordFailure(requestId: nil, httpStatus: 403)
        XCTAssertNil(tracer.attributableRequestId(httpStatus: 403))
        tracer.recordFailure(requestId: "   ", httpStatus: 403)
        XCTAssertNil(tracer.attributableRequestId(httpStatus: 403))
    }

    func test_theLatestFailureWins() {
        let second = "aaaaaaaa-9999-8888-7777-666655554444"
        tracer.recordFailure(requestId: guid, httpStatus: 403)
        tracer.recordFailure(requestId: second, httpStatus: 500)
        XCTAssertEqual(tracer.attributableRequestId(httpStatus: 500), second)
        XCTAssertNil(tracer.attributableRequestId(httpStatus: 403),
                     "the earlier failure is gone, not merely outranked")
    }

    func test_clearRemovesTheTrace() {
        tracer.recordFailure(requestId: guid, httpStatus: 403)
        tracer.clear()
        XCTAssertNil(tracer.attributableRequestId(httpStatus: 403))
    }

    func test_recordingFromAResponseReadsTheRightHeader() throws {
        // `request-id` is Graph's own. `client-request-id` merely echoes what we sent and is
        // useless for finding anything in Microsoft's logs, so it must not be read instead.
        let response = try XCTUnwrap(HTTPURLResponse(
            url: URL(string: "https://graph.microsoft.com/v1.0/me")!,
            statusCode: 403,
            httpVersion: "HTTP/1.1",
            headerFields: ["request-id": guid, "client-request-id": "should-not-be-used"]))
        tracer.recordFailure(response)
        XCTAssertEqual(tracer.attributableRequestId(httpStatus: 403), guid)
    }
}
