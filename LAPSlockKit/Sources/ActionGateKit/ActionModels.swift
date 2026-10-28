import Foundation
import AuthKit
import PrivilegedAccessKit

// The gate every write goes through. Spec section 4, CLAUDE.md "write actions are gated".
//
// A write is data: the request to send, the tier that says how much confirmation it needs,
// the roles that are known to be required, and the words for the log. No module calls a
// write endpoint itself; it hands one of these to the runner, and the runner is the only
// code in the app that sends a POST to Microsoft Graph outside of PIM activation.
//
// This target imports Foundation, AuthKit and PrivilegedAccessKit. It must never be able
// to see a credential, and the isolation guard keeps CredentialKit out of its link graph
// in both directions.

/// How much the person has to do before the call fires. Spec section 4, tiered
/// confirmation.
public enum ActionTier: String, Sendable, Codable, Equatable {
    /// Sync: fires on the tap.
    case none
    /// Restart, lock, locate, rotate keys, revoke sessions: a confirmation sheet.
    case confirm
    /// Retire, wipe, remove authentication methods: the target's name typed back, the app
    /// lock re-prompted, and a ten-second window to change your mind before the call.
    case destructive

    /// The tier after an organization's strict confirmation policy: every tier moves one
    /// step up, and destructive stays destructive.
    public func effective(strict: Bool) -> ActionTier {
        guard strict else { return self }
        switch self {
        case .none:        return .confirm
        case .confirm:     return .destructive
        case .destructive: return .destructive
        }
    }

    /// What the screen has to collect, in order.
    public var requirements: [ConfirmationRequirement] {
        switch self {
        case .none:        return []
        case .confirm:     return [.confirmSheet]
        case .destructive: return [.typedName, .appLockReprompt, .undoWindow(seconds: UndoWindow.standardSeconds)]
        }
    }
}

public enum ConfirmationRequirement: Sendable, Equatable {
    case confirmSheet
    case typedName
    case appLockReprompt
    case undoWindow(seconds: Int)
}

/// What the action is done to, in words the log and the sheet can show.
public struct ActionTarget: Sendable, Codable, Equatable {
    /// "LT-FIELD-207", "jane.okafor@demo.example".
    public let label: String
    /// The Graph identifier, for the log.
    public let id: String
    public init(label: String, id: String) {
        self.label = label
        self.id = id
    }
}

/// One write, ready to run.
public struct WriteAction: Sendable, Equatable {
    /// A stable name for the log and diagnostics: "device.restart".
    public let id: String
    /// "Restart", for the sheet and the log.
    public let title: String
    public let tier: ActionTier
    public let target: ActionTarget
    /// The POST to send. The runner refuses anything that is not a POST.
    public let request: GraphRequest
    /// Role template ids known to allow this action. Empty means "let Graph decide": the
    /// gate still catches a 403 and offers activation then.
    public let requiredRoleTemplateIds: [String]
    /// What the screen says on success. Always "requested", never "done": Intune queues
    /// device actions and the device performs them at its next check-in.
    public let successCopy: String

    public init(
        id: String,
        title: String,
        tier: ActionTier,
        target: ActionTarget,
        request: GraphRequest,
        requiredRoleTemplateIds: [String] = [],
        successCopy: String
    ) {
        self.id = id
        self.title = title
        self.tier = tier
        self.target = target
        self.request = request
        self.requiredRoleTemplateIds = requiredRoleTemplateIds
        self.successCopy = successCopy
    }
}

/// Where a run ended up. Every case is something the screen can act on.
public enum ActionOutcome: Sendable, Equatable {
    /// Graph accepted the request. The id is Microsoft's `request-id`, for a ticket.
    case requested(requestId: String?)
    /// Before any call: a required role is eligible but not active. Offer activation.
    case needsActivation(eligible: [EligibleAccess])
    /// Graph answered 403. The eligible access, if any, so the screen can offer activation
    /// instead of a bare error.
    case notAuthorized(eligible: [EligibleAccess])
    /// Graph wants another sign-in step (MFA, an authentication context). The person taps
    /// to continue; the runner never does this on its own.
    case challenged(ClaimsChallenge)
    case failed(ActionFailure)

    public var isRequested: Bool {
        if case .requested = self { return true }
        return false
    }
}

public enum ActionFailure: Sendable, Equatable {
    case consentRequired
    case notFound
    case badRequest(code: String?)
    /// Never retried: a write is sent once.
    case throttled(retryAfter: TimeInterval?)
    case serviceUnavailable(status: Int)
    case transport(status: Int)
    case cancelled
    /// The action was not a POST, or was otherwise refused before sending.
    case refused(reason: String)

    public var description: String {
        switch self {
        case .consentRequired:            return "This organization hasn't granted TenantKeep permission for this action yet."
        case .notFound:                   return "Microsoft no longer has this object."
        case .badRequest(let code):       return code.map { "Microsoft rejected the request (\($0))." } ?? "Microsoft rejected the request."
        case .throttled(let retryAfter):
            if let retryAfter { return "Microsoft Graph is rate limiting this tenant. Try again in about \(Int(retryAfter)) seconds." }
            return "Microsoft Graph is rate limiting this tenant. Try again shortly."
        case .serviceUnavailable:         return "Microsoft Graph is unavailable right now. Nothing was sent."
        case .transport:                  return "The request did not get through. Nothing was done."
        case .cancelled:                  return "Cancelled."
        case .refused(let reason):        return reason
        }
    }
}

/// The ten seconds between "confirm" and the call, during which a tap undoes it.
public actor UndoWindow {
    public static let standardSeconds = 10

    private var cancelled = false
    private var started = false
    private var sendNow = false

    public init() {}

    /// Waits the window out. Returns true when the time passed with no cancel, false when
    /// somebody changed their mind. Calling it twice is a programming error and returns
    /// false, so a second tap can never fire a second write. `tick` hears the whole seconds
    /// left, from the full count down to 1, each time that changes.
    public func wait(seconds: Int = UndoWindow.standardSeconds,
                     sleep: @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) },
                     tick: @Sendable (Int) async -> Void = { _ in }) async -> Bool {
        guard !started else { return false }
        started = true
        let step: TimeInterval = 0.25
        var elapsed: TimeInterval = 0
        var shown = seconds
        await tick(shown)
        while elapsed < TimeInterval(seconds) {
            if cancelled { return false }
            if sendNow { return true }
            do { try await sleep(step) } catch { return false }
            elapsed += step
            let left = seconds - Int(elapsed)
            if left != shown, left > 0 {
                shown = left
                await tick(left)
            }
        }
        return !cancelled
    }

    public func cancel() {
        cancelled = true
    }

    /// The person is sure: end the wait and send. A cancel that already landed wins.
    public func proceedNow() {
        guard !cancelled else { return }
        sendNow = true
    }

    public var isCancelled: Bool { cancelled }
}

/// Every countdown running right now, by the id of what it acts on. A screen that goes
/// away cancels through here rather than through its own view state, which a redraw or a
/// teardown can lose: an action is sent only while its Undo is on screen.
public actor PendingActions {
    public static let shared = PendingActions()

    private var windows: [String: UndoWindow] = [:]

    public init() {}

    public func register(_ window: UndoWindow, for targetId: String) {
        windows[targetId] = window
    }

    public func finished(_ targetId: String) {
        windows[targetId] = nil
    }

    /// Cancels the countdown for one target, if there is one. Returns whether there was.
    @discardableResult
    public func cancel(_ targetId: String) async -> Bool {
        guard let window = windows.removeValue(forKey: targetId) else { return false }
        await window.cancel()
        return true
    }

    public func cancelAll() async {
        let all = windows
        windows = [:]
        for window in all.values { await window.cancel() }
    }

    public var count: Int { windows.count }
}

/// One write's undo countdown from start to finish. It is registered with PendingActions
/// for the whole wait, so a screen that goes away or an app that leaves the foreground
/// cancels it, and it is removed when it ends either way. Never shorter than ten seconds.
public final class UndoCountdown: Sendable {
    public let key: String
    public let seconds: Int
    private let window = UndoWindow()
    private let pending: PendingActions

    public init(key: String, seconds: Int = UndoWindow.standardSeconds, pending: PendingActions = .shared) {
        self.key = key
        self.seconds = max(UndoWindow.standardSeconds, seconds)
        self.pending = pending
    }

    /// Runs the countdown. Returns true to send, false when it was undone or cancelled.
    public func run(sleep: @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) },
                    tick: @Sendable (Int) async -> Void) async -> Bool {
        await pending.register(window, for: key)
        let proceed = await window.wait(seconds: seconds, sleep: sleep, tick: tick)
        await pending.finished(key)
        return proceed
    }

    public func undo() async {
        await window.cancel()
    }

    /// Ends the wait and sends. An undo that already landed wins.
    public func sendNow() async {
        await window.proceedNow()
    }
}
