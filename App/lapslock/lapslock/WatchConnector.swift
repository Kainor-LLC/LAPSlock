import Foundation
import UserNotifications
import WatchConnectivity
import WatchBridgeKit
import AuthKit
import ActionGateKit
import ApprovalsKit
import PrivilegedAccessKit
import TenantPulseKit
import SecurityKit

// The phone's side of the Apple Watch companion, phase 4 step B, spec 3.13.
//
// The watch is a remote for the phone: it never holds a token, so every Graph call it asks
// for happens here, with the phone's own session and the same services the phone's screens
// use, through the same gate. What goes back is a WatchGlance or a WatchReply from
// WatchBridgeKit, which by construction cannot carry a credential.
//
// The glance goes out as application context: the latest state, which the watch reads when
// it next looks, so the phone does not need the watch to be awake. Requests come in as
// messages, which wake the phone in the background when the watch asks.

@MainActor
final class WatchConnector: NSObject {
    static let shared = WatchConnector()

    struct Handlers {
        var glance: @MainActor () async -> WatchGlance
        var decide: @MainActor (String, Bool, String) async -> WatchReply
        var activate: @MainActor (String, String, Int) async -> WatchReply
    }

    private var handlers: Handlers?
    private var session: WCSession? { WCSession.isSupported() ? WCSession.default : nil }

    func start() {
        guard let session, session.delegate == nil else { return }
        session.delegate = self
        session.activate()
    }

    /// Set when the mode changes: demo, live, or signed out (nil).
    func configure(_ handlers: Handlers?) {
        self.handlers = handlers
        Task { await push() }
    }

    /// Sends the latest glance, if a watch with the app is paired. Signed out sends an empty
    /// glance, so the wrist never shows a previous session's tenant.
    func push() async {
        guard let session, session.activationState == .activated, session.isPaired, session.isWatchAppInstalled else { return }
        let glance: WatchGlance
        if let handlers {
            glance = await handlers.glance().fitted()
        } else {
            glance = WatchGlance(updatedAt: Date(), tenant: "", isDemo: false, problem: "Sign in on your iPhone.")
        }
        if let context = try? WatchBridge.encode(glance) {
            try? session.updateApplicationContext(context)
        }
    }

    fileprivate func handle(_ request: WatchRequest) async -> WatchReply {
        guard let handlers else {
            return WatchReply(outcome: .failed, message: "Sign in on your iPhone first.")
        }
        if let problem = request.problem { return WatchReply(outcome: .failed, message: problem) }
        let reply: WatchReply
        switch request {
        case .refresh:
            return WatchReply(outcome: .done, message: "Updated.", glance: await handlers.glance().fitted())
        case .decide(let id, let approve, let reason):
            reply = await handlers.decide(id, approve, reason)
        case .activate(let id, let reason, let hours):
            reply = await handlers.activate(id, reason, hours)
        }
        var withGlance = reply
        withGlance.glance = await handlers.glance().fitted()
        return withGlance
    }

    /// For a step the wrist cannot do, such as a fresh MFA prompt: the phone says so where
    /// the admin will see it.
    static func notifyFinishOnPhone(_ body: String) async {
        let content = UNMutableNotificationContent()
        content.title = "Finish on your iPhone"
        content.body = body
        content.userInfo = ["module": "privilegedAccess", "tab": "approvals"]
        let request = UNNotificationRequest(identifier: "watch-finish-" + UUID().uuidString, content: content, trigger: nil)
        try? await UNUserNotificationCenter.current().add(request)
    }
}

/// Carries WatchConnectivity's reply handler across to the main actor. It is called once.
private final class ReplyBox: @unchecked Sendable {
    let send: ([String: Any]) -> Void
    init(_ send: @escaping ([String: Any]) -> Void) { self.send = send }
}

extension WatchConnector: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        Task { @MainActor in await self.push() }
    }

    nonisolated func sessionDidBecomeInactive(_ session: WCSession) {}

    /// Switching to another watch: reactivate so the new one gets the glance.
    nonisolated func sessionDidDeactivate(_ session: WCSession) {
        session.activate()
    }

    nonisolated func sessionWatchStateDidChange(_ session: WCSession) {
        Task { @MainActor in await self.push() }
    }

    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
        let box = ReplyBox(replyHandler)
        let request = WatchBridge.decode(WatchRequest.self, from: message)
        Task { @MainActor in
            let reply: WatchReply
            if let request {
                reply = await self.handle(request)
            } else {
                reply = WatchReply(outcome: .failed, message: "Update TenantKeep on your iPhone and your watch to the same version.")
            }
            box.send((try? WatchBridge.encode(reply)) ?? [:])
        }
    }
}

// MARK: - building the handlers

enum WatchHandlers {
    /// Fixed for the session, so the demo role's countdown counts down across refreshes.
    @MainActor static let demoRoleEnds = Date().addingTimeInterval(2 * 3600 + 14 * 60)

    /// Demo: the demo approvals provider, fixed counts, and no activation.
    @MainActor
    static func demo(approvals: any ApprovalsProviding) -> WatchConnector.Handlers {
        WatchConnector.Handlers(
            glance: {
                let pending = (try? await approvals.pending()) ?? []
                return WatchGlance(
                    updatedAt: Date(), tenant: "Demo tenant", isDemo: true,
                    health: .init(degradedServices: 1, openIncidents: 2, expiringSoon: 3, secureScorePercent: 61),
                    activeRoles: [.init(name: "Intune Administrator", endsAt: demoRoleEnds)],
                    eligible: [.init(id: "demo-gr", name: "Global Reader", isGroup: false),
                               .init(id: "demo-ops", name: "Ops On-Call (PIM)", isGroup: true)],
                    approvals: pending.map(summary))
            },
            decide: { id, approve, reason in
                await decide(approvals, id: id, approve: approve, reason: reason)
            },
            activate: { _, _, _ in
                WatchReply(outcome: .failed, message: "Demo data has no roles to activate. Sign in on your iPhone to use this.")
            })
    }

    /// Live: the session's services, every read silent, every write through the gate.
    @MainActor
    static func live(graph: GraphClient, auth: any AuthManaging, tenant: String, approvals: any ApprovalsProviding,
                     tenantPulse: TenantPulseService, security: SecurityService, activationEnabled: Bool) -> WatchConnector.Handlers {
        let privileged = PrivilegedAccessService(auth: auth)
        let gate = GraphRoleGate(graph: graph, privileged: privileged)
        return WatchConnector.Handlers(
            glance: {
                async let health = try? tenantPulse.health()
                async let expiring = try? tenantPulse.expiringItems()
                async let score = try? tenantPulse.secureScore()
                async let incidents = try? security.incidents()
                async let pending = try? approvals.pending()
                async let roles = try? gate.activeRoles()
                async let eligible = activationEnabled ? (try? privileged.eligibleAccess()) : nil
                let horizon = Date().addingTimeInterval(30 * 86_400)
                let latest = await score?.latest
                let percent = latest.flatMap { s -> Int? in
                    guard let current = s.currentScore, let max = s.maxScore, max > 0 else { return nil }
                    return Int((current / max * 100).rounded())
                }
                let pendingList = await pending
                return WatchGlance(
                    updatedAt: Date(), tenant: tenant, isDemo: false,
                    health: .init(degradedServices: await health?.degraded.count,
                                  openIncidents: await incidents?.filter(\.isOpen).count,
                                  expiringSoon: await expiring?.filter { $0.expiresAt <= horizon }.count,
                                  secureScorePercent: percent),
                    activeRoles: (await roles ?? []).map { .init(name: $0.name, endsAt: $0.endsAt) },
                    eligible: (await eligible ?? []).map { access in
                        var isGroup = false
                        if case .group = access.kind { isGroup = true }
                        return .init(id: access.id, name: access.displayName ?? "Eligible access", isGroup: isGroup)
                    },
                    approvals: (pendingList ?? []).map(summary),
                    problem: pendingList == nil ? "Couldn't read PIM approvals." : nil)
            },
            decide: { id, approve, reason in
                await decide(approvals, id: id, approve: approve, reason: reason)
            },
            activate: { id, reason, hours in
                guard activationEnabled else {
                    return WatchReply(outcome: .failed, message: "Turn on role activation in Settings on your iPhone first.")
                }
                guard let access = (try? await privileged.eligibleAccess())?.first(where: { $0.id == id }) else {
                    return WatchReply(outcome: .failed, message: "That access is no longer eligible.")
                }
                let name = access.displayName ?? "the role"
                do {
                    let outcome = try await privileged.activate(access, justification: reason, ticketNumber: nil, duration: "PT" + String(hours) + "H")
                    switch outcome {
                    case .activated:              return WatchReply(outcome: .done, message: name + " is active.")
                    case .provisioning:           return WatchReply(outcome: .done, message: name + " is being applied. It becomes active on its own.")
                    case .pendingApproval:        return WatchReply(outcome: .done, message: "Sent for approval. " + name + " activates when an approver agrees.")
                    case .requested(_, let status): return WatchReply(outcome: .done, message: "Requested. PIM says " + status + ".")
                    case .refused(let status):    return WatchReply(outcome: .failed, message: "PIM refused: " + status + ".")
                    }
                } catch PrivilegedAccessError.claimsChallenge {
                    await WatchConnector.notifyFinishOnPhone("Activating " + name + " needs a fresh sign-in step. Open TenantKeep to finish.")
                    return WatchReply(outcome: .finishOnPhone, message: "Microsoft wants a fresh sign-in. Finish on your iPhone.")
                } catch {
                    return WatchReply(outcome: .failed, message: "Couldn't activate " + name + ". Your policy may need a ticket number; use your iPhone.")
                }
            })
    }

    static func summary(_ approval: PendingApproval) -> WatchGlance.Approval {
        WatchGlance.Approval(id: approval.id, requester: approval.requester, target: approval.targetLabel,
                             duration: approval.durationText, reason: approval.justification, askedAt: approval.requested)
    }

    static func decide(_ approvals: any ApprovalsProviding, id: String, approve: Bool, reason: String) async -> WatchReply {
        guard let approval = (try? await approvals.pending())?.first(where: { $0.id == id }) else {
            return WatchReply(outcome: .failed, message: ApprovalsError.nothingToDecide.message)
        }
        switch await approvals.decide(approval, approve ? .approve : .deny, justification: reason) {
        case .requested:
            return WatchReply(outcome: .done, message: (approve ? "Approved " : "Denied ") + approval.requester + ".")
        case .challenged:
            await WatchConnector.notifyFinishOnPhone("Deciding " + approval.requester + "'s request needs a fresh sign-in step.")
            return WatchReply(outcome: .finishOnPhone, message: "Microsoft wants a fresh sign-in. Finish on your iPhone.")
        case .needsActivation, .notAuthorized:
            return WatchReply(outcome: .failed, message: "Microsoft refused: you are not an approver for this request.")
        case .failed(let failure):
            if case .refused(let reason) = failure { return WatchReply(outcome: .failed, message: reason) }
            return WatchReply(outcome: .failed, message: failure.description)
        }
    }
}
