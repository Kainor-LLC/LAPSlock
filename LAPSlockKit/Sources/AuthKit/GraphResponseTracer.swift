import Foundation

// Graph's `request-id`, captured so a support case can name it.
//
// WHY THIS MATTERS. When Microsoft Graph fails, `request-id` is the first thing Microsoft
// support asks for — it is how they find the request in their own logs. Without it a support
// case starts with "something failed sometime", and the diagnostics report was carrying a
// `graphRequestId` field that nothing ever populated.
//
// WHY A SIDE CHANNEL AND NOT AN ERROR PAYLOAD. Adding the id to every case of every error
// enum would change `InventoryError` and `CredentialError` — both `Equatable` and both
// compared by value throughout the tests — for a field that is pure diagnostics and never
// affects a decision. The app already uses exactly this pattern for MSAL failures
// (`lastAuthFailure`), so a last-failure box is the established shape here rather than a new
// idea.
//
// WHY IT LIVES IN AuthKit. `isolation-check.sh` caps CredentialKit at Foundation + AuthKit,
// so a credential provider cannot import DiagnosticsKit to report anything. AuthKit is the
// only module every Graph caller — CredentialKit, InventoryKit, PrivilegedAccessKit — is
// permitted to see. The name says Graph rather than auth so nobody mistakes it for part of
// the sign-in flow.

/// The last Graph response worth telling Microsoft about.
public struct GraphResponseTrace: Sendable, Equatable {
    /// Value of the `request-id` header.
    public let requestId: String
    public let httpStatus: Int
    public let observedAt: Date

    public init(requestId: String, httpStatus: Int, observedAt: Date = Date()) {
        self.requestId = requestId
        self.httpStatus = httpStatus
        self.observedAt = observedAt
    }
}

/// Holds the `request-id` of the most recent FAILED Graph response.
///
/// Only failures are recorded. A successful request's id is of no interest to support, and
/// recording every one would mean the id attached to a failure could easily belong to a
/// later success.
///
/// **Lock rather than actor, deliberately.** The write happens inside the synchronous
/// `validate(_:)` helpers that every Graph call already funnels through. An actor would
/// force those to become async or to fire off a detached task, and a detached task can
/// land out of order — which is precisely the failure mode that would attach the wrong id
/// to a report.
public final class GraphResponseTracer: @unchecked Sendable {

    public static let shared = GraphResponseTracer()

    /// How stale a trace may be and still be attributed to an event.
    ///
    /// A last-seen box cannot prove the id belongs to the event being recorded, so the
    /// window is short and the status must agree. The alternative — attaching whatever was
    /// last seen — would put a misleading id in front of Microsoft support, which is worse
    /// than putting none.
    public static let attributionWindow: TimeInterval = 30

    private let lock = NSLock()
    private var trace: GraphResponseTrace?

    public init() {}

    /// Records a failing response. Ignores anything without a usable `request-id`.
    public func recordFailure(requestId: String?, httpStatus: Int) {
        guard let requestId = requestId?.trimmingCharacters(in: .whitespacesAndNewlines),
              !requestId.isEmpty
        else { return }
        lock.lock()
        trace = GraphResponseTrace(requestId: requestId, httpStatus: httpStatus)
        lock.unlock()
    }

    /// Reads a failing HTTP response and records its `request-id`.
    ///
    /// One call at each `validate` site, so the header name is written once. Graph sends
    /// `request-id`; `client-request-id` echoes what the CALLER sent and is therefore
    /// useless for finding anything in Microsoft's logs.
    public func recordFailure(_ response: HTTPURLResponse) {
        recordFailure(
            requestId: response.value(forHTTPHeaderField: "request-id"),
            httpStatus: response.statusCode)
    }

    /// The recent request id, when it can honestly be attributed to this event.
    ///
    /// - Parameter httpStatus: the event's own status. When both the event and the trace
    ///   have one and they disagree, nil is returned — they are different requests.
    public func attributableRequestId(
        httpStatus: Int?,
        now: Date = Date(),
        window: TimeInterval = GraphResponseTracer.attributionWindow
    ) -> String? {
        lock.lock()
        let trace = self.trace
        lock.unlock()

        guard let trace else { return nil }
        guard now.timeIntervalSince(trace.observedAt) <= window else { return nil }
        if let httpStatus, httpStatus != trace.httpStatus { return nil }
        return trace.requestId
    }

    public func clear() {
        lock.lock()
        trace = nil
        lock.unlock()
    }
}
