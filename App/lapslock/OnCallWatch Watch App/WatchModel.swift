import Foundation
import Combine
import WatchConnectivity
import WidgetKit
import WatchBridgeKit

/// The watch's state: the latest glance the phone sent, and the requests it sends back.
/// Nothing is written to the watch's storage; WatchConnectivity keeps the last glance.
@MainActor
final class WatchModel: NSObject, ObservableObject {
    @Published private(set) var glance: WatchGlance? {
        didSet { updateComplications(glance) }
    }
    @Published private(set) var sending = false
    @Published private(set) var lastReply: WatchReply?

    override init() {
        super.init()
        guard WCSession.isSupported() else { return }
        WCSession.default.delegate = self
        WCSession.default.activate()
    }

    var phoneReachable: Bool { WCSession.isSupported() && WCSession.default.isReachable }

    func refresh() async { await send(.refresh) }

    /// Sends a request and waits for the phone's answer. The phone does the Graph call.
    @discardableResult
    func send(_ request: WatchRequest) async -> WatchReply {
        if let problem = request.problem {
            let reply = WatchReply(outcome: .failed, message: problem)
            lastReply = reply
            return reply
        }
        guard phoneReachable, let message = try? WatchBridge.encode(request) else {
            let reply = WatchReply(outcome: .failed, message: "Your iPhone isn't reachable. Keep it nearby with TenantKeep installed.")
            lastReply = reply
            return reply
        }
        sending = true
        defer { sending = false }
        let reply: WatchReply = await withCheckedContinuation { continuation in
            let once = Once(continuation)
            WCSession.default.sendMessage(message, replyHandler: { answer in
                once.resume(WatchBridge.decode(WatchReply.self, from: answer)
                            ?? WatchReply(outcome: .failed, message: "Update TenantKeep on your iPhone."))
            }, errorHandler: { _ in
                once.resume(WatchReply(outcome: .failed, message: "Your iPhone didn't answer. Try again."))
            })
        }
        if let fresh = reply.glance { glance = fresh }
        lastReply = reply
        return reply
    }

    fileprivate func received(_ context: [String: Any]) {
        if let fresh = WatchBridge.decode(WatchGlance.self, from: context), fresh.v == WatchBridge.version {
            glance = fresh
        }
    }

    /// Counts for the watch face, or nothing when signed out, then a complication reload.
    private func updateComplications(_ fresh: WatchGlance?) {
        let defaults = UserDefaults(suiteName: ComplicationSnapshot.appGroup)
        if let fresh, !fresh.tenant.isEmpty {
            ComplicationSnapshot(fresh).save(to: defaults)
        } else {
            ComplicationSnapshot.clear(in: defaults)
        }
        WidgetCenter.shared.reloadAllTimelines()
    }
}

/// Resumes a continuation exactly once, whichever of WatchConnectivity's handlers fires.
nonisolated private final class Once: @unchecked Sendable {
    private var continuation: CheckedContinuation<WatchReply, Never>?
    private let lock = NSLock()
    init(_ continuation: CheckedContinuation<WatchReply, Never>) { self.continuation = continuation }
    func resume(_ value: WatchReply) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }
}

extension WatchModel: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        let context = session.receivedApplicationContext
        let box = ContextBox(context)
        Task { @MainActor in self.received(box.value) }
    }

    nonisolated func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        let box = ContextBox(applicationContext)
        Task { @MainActor in self.received(box.value) }
    }
}

nonisolated private final class ContextBox: @unchecked Sendable {
    let value: [String: Any]
    init(_ value: [String: Any]) { self.value = value }
}
