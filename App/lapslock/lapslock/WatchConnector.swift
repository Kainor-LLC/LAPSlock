import Foundation
import UIKit
import UserNotifications
import WatchConnectivity
import WatchBridgeKit
import AuthKit
import ActionGateKit
import ApprovalsKit
import PrivilegedAccessKit
import TenantPulseKit
import SecurityKit
import AuthKitMSAL
import ManagedConfigKit

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
    /// For a request that woke the app in the background before any screen said which
    /// mode it is in. Dropped as soon as the screens configure.
    private var headless: Handlers?
    /// The connections a headless request's session opened, closed when the screens take over.
    private var headlessSession: URLSession?
    /// False until the app's screens have said which mode it is in. A background launch for
    /// the notification check builds no screens, and must not tell the watch "signed out".
    private var configured = false
    private var session: WCSession? { WCSession.isSupported() ? WCSession.default : nil }

    /// The one push running, and whether another was asked for while it ran
    /// (OPTIMIZATION-PLAN.md, step F). Pushes used to start on every activation, each Face ID
    /// prompt included, several at once at launch, each reading seven services.
    private var pushTask: Task<Void, Never>?
    private var pushAgain = false
    /// Moves on every configure, so a glance built for the previous tenant is never sent.
    private var generation = 0
    private var lastPushed: Date?
    /// The counts the watch face last had, so it is woken only when they change.
    private var lastComplication: ComplicationSnapshot?
    /// Unforced pushes, at most this often. The wrist can ask for Update now at any time.
    static let minimumInterval: TimeInterval = 10 * 60

    func start() {
        guard let session, session.delegate == nil else { return }
        session.delegate = self
        session.activate()
    }

    /// Set when the mode changes: demo, live, or signed out (nil).
    func configure(_ handlers: Handlers?) {
        self.handlers = handlers
        headless = nil
        headlessSession?.finishTasksAndInvalidate()
        headlessSession = nil
        configured = true
        generation += 1
        requestPush(force: true)
    }

    /// Asks for the glance to be sent. Forced for a tenant or mode change, a newly reachable
    /// watch and a write from the wrist; otherwise only when the last push is more than
    /// `minimumInterval` old. One runs at a time; a request while it runs runs it once more.
    func requestPush(force: Bool = false) {
        if !force, let lastPushed, Date().timeIntervalSince(lastPushed) < Self.minimumInterval { return }
        if pushTask != nil {
            pushAgain = true
            return
        }
        pushTask = Task { [weak self] in await self?.runPushes() }
    }

    /// For the background check: a push if one is due, finished before the check returns.
    func pushIfDue() async {
        requestPush()
        await pushTask?.value
    }

    private func runPushes() async {
        repeat {
            pushAgain = false
            await pushOnce()
        } while pushAgain
        pushTask = nil
    }

    /// Sends the latest glance, if a watch with the app is paired. Signed out sends an empty
    /// glance, so the wrist never shows a previous session's tenant.
    private func pushOnce() async {
        guard configured, let session, session.activationState == .activated, session.isPaired, session.isWatchAppInstalled else { return }
        let built = generation
        let glance: WatchGlance
        if let handlers {
            glance = await handlers.glance().fitted()
        } else {
            glance = WatchGlance(updatedAt: Date(), tenant: "", isDemo: false, problem: "Sign in on your iPhone.")
        }
        // Built for a tenant the app has since left: the push the switch asked for follows.
        guard built == generation else { return }
        send(glance, over: session)
    }

    /// The glance as application context, and the face's counts over the complication
    /// channel when they changed: that one wakes the watch, from a budget of about fifty a day.
    private func send(_ glance: WatchGlance, over session: WCSession) {
        lastPushed = Date()
        PerfProbe.mark("watchPush", "approvals=" + String(glance.approvals.count))
        if let context = try? WatchBridge.encode(glance) {
            try? session.updateApplicationContext(context)
        }
        guard !glance.tenant.isEmpty else { return }
        let snapshot = ComplicationSnapshot(glance)
        guard !snapshot.shows(sameAs: lastComplication), session.isComplicationEnabled,
              session.remainingComplicationUserInfoTransfers > 0 else { return }
        session.transferCurrentComplicationUserInfo(snapshot.userInfo)
        lastComplication = snapshot
    }

    fileprivate func handle(_ request: WatchRequest) async -> WatchReply {
        var active = handlers
        if active == nil, !configured { active = await headlessHandlers() }
        guard let handlers = active else {
            return WatchReply(outcome: .failed, message: "Sign in on your iPhone first.")
        }
        if let problem = request.problem { return WatchReply(outcome: .failed, message: problem) }
        let reply: WatchReply
        switch request {
        case .refresh:
            let glance = await handlers.glance().fitted()
            if configured, let session { send(glance, over: session) }
            return WatchReply(outcome: .done, message: "Updated.", glance: glance)
        case .decide(let id, let approve, let reason):
            reply = await handlers.decide(id, approve, reason)
        case .activate(let id, let reason, let hours):
            reply = await handlers.activate(id, reason, hours)
        }
        // Answered as soon as the write returns. The fresh glance follows as application
        // context, rather than holding the wrist's spinner through a re-read of the tenant,
        // long enough on a weak link for the watch to give up on an approval that went through.
        requestPush(force: true)
        return reply
    }

    /// A request from the wrist can launch the app in the background, once iOS has put it
    /// away overnight, with no screen built to configure the watch. Answering "sign in
    /// first" then made Approve and Activate on the wrist useless until the phone app was
    /// opened. So the live session is restored the way the background check restores it:
    /// silently, the organization's tenant pin honoured, the live providers only, and
    /// nothing at all when nobody is signed in.
    private func headlessHandlers() async -> Handlers? {
        if let headless { return headless }
        guard let manager = await SessionAuth.shared.restoredManager(),
              let account = await manager.currentAccount else { return nil }
        if let pin = ManagedConfigStore.read().tenantPin, account.tenantId.lowercased() != pin { return nil }
        let tenant = await manager.operatingTenantId ?? account.tenantId
        let session = AppRootModel.LiveSession(auth: manager, tenantId: tenant)
        headlessSession = session.urlSession
        let domain = account.username.split(separator: "@").last.map(String.init)
        let built = WatchHandlers.live(
            graph: session.graph, privileged: session.privileged, tenant: domain ?? "Your tenant",
            approvals: session.approvals, tenantPulse: session.tenantPulse, security: session.security,
            activationEnabled: AppSettings.shared.privilegedActivationEnabled)
        headless = built
        return built
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
        Task { @MainActor in self.requestPush(force: true) }
    }

    nonisolated func sessionDidBecomeInactive(_ session: WCSession) {}

    /// Switching to another watch: reactivate so the new one gets the glance.
    nonisolated func sessionDidDeactivate(_ session: WCSession) {
        session.activate()
    }

    nonisolated func sessionWatchStateDidChange(_ session: WCSession) {
        Task { @MainActor in self.requestPush(force: true) }
    }

    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
        let box = ReplyBox(replyHandler)
        let request = WatchBridge.decode(WatchRequest.self, from: message)
        Task { @MainActor in
            // A request can arrive with the app in the background; ask for the time to
            // finish the Graph work and answer.
            let background = UIApplication.shared.beginBackgroundTask(withName: "watch-request")
            defer { UIApplication.shared.endBackgroundTask(background) }
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

    /// Demo: the demo approvals provider, fixed counts, and no activation. Quiet is the
    /// second sample customer, whose counts are all zero, so the wrist follows a switch.
    @MainActor
    static func demo(approvals: any ApprovalsProviding, quiet: Bool = false) -> WatchConnector.Handlers {
        WatchConnector.Handlers(
            glance: {
                let pending = (try? await approvals.pending()) ?? []
                return WatchGlance(
                    updatedAt: Date(), tenant: quiet ? "fabrikam.example (sample)" : "Demo tenant", isDemo: true,
                    health: quiet
                        ? .init(degradedServices: 0, openIncidents: 0, expiringSoon: 0, secureScorePercent: 72)
                        : .init(degradedServices: 1, openIncidents: 2, expiringSoon: 3, secureScorePercent: 61),
                    activeRoles: quiet ? [] : [.init(name: "Intune Administrator", endsAt: demoRoleEnds)],
                    eligible: [.init(id: "demo-gr", name: "Global Reader", isGroup: false),
                               .init(id: "demo-ops", name: "Ops On-Call (PIM)", isGroup: true)],
                    approvals: pending.map(summary))
            },
            decide: { id, approve, reason in
                await decide(approvals, id: id, approve: approve, reason: reason, known: [])
            },
            activate: { _, _, _ in
                WatchReply(outcome: .failed, message: "Demo data has no roles to activate. Sign in on your iPhone to use this.")
            })
    }

    /// What the live handlers keep between pushes, for one tenant's session.
    @MainActor
    final class Memory {
        /// Expiring items change by the day, and reading them walks every app registration.
        static let expiringLife: TimeInterval = 6 * 3_600
        private var expiring: (items: [ExpiringItem], at: Date)?
        /// The last approvals and eligible access read, so a decision or an activation from
        /// the wrist does not read the list again first.
        var pending: [PendingApproval] = []
        var eligible: [EligibleAccess] = []

        func expiringItems(_ read: () async throws -> [ExpiringItem]) async -> [ExpiringItem]? {
            if let expiring, Date().timeIntervalSince(expiring.at) < Self.expiringLife { return expiring.items }
            guard let items = try? await read() else { return expiring?.items }
            expiring = (items, Date())
            return items
        }
    }

    /// Live: the session's services, every read silent, every write through the gate.
    ///
    /// The glance reads what it shows and no more (OPTIMIZATION-PLAN.md, step F): the
    /// service statuses without the issues and their posts, the latest Secure Score rather
    /// than a month, incident statuses without their alerts and evidence, and expiring
    /// items from memory for six hours.
    @MainActor
    static func live(graph: GraphClient, privileged: PrivilegedAccessService, tenant: String, approvals: any ApprovalsProviding,
                     tenantPulse: TenantPulseService, security: SecurityService, activationEnabled: Bool) -> WatchConnector.Handlers {
        let gate = GraphRoleGate(graph: graph, privileged: privileged)
        let memory = Memory()
        return WatchConnector.Handlers(
            glance: {
                async let overviews = try? tenantPulse.healthOverviews()
                async let expiring = memory.expiringItems { try await tenantPulse.expiringItems() }
                async let score = try? tenantPulse.secureScore(snapshots: 1)
                async let incidents = try? security.incidentStatuses(highOnly: false)
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
                if let pendingList { memory.pending = pendingList }
                let eligibleList = await eligible
                if let eligibleList { memory.eligible = eligibleList }
                return WatchGlance(
                    updatedAt: Date(), tenant: tenant, isDemo: false,
                    health: .init(degradedServices: await overviews?.filter { !$0.isOperational }.count,
                                  openIncidents: await incidents?.filter(\.isOpen).count,
                                  expiringSoon: await expiring?.filter { $0.expiresAt <= horizon }.count,
                                  secureScorePercent: percent),
                    activeRoles: (await roles ?? []).map { .init(name: $0.name, endsAt: $0.endsAt) },
                    eligible: (eligibleList ?? []).map { access in
                        var isGroup = false
                        if case .group = access.kind { isGroup = true }
                        return .init(id: access.id, name: access.displayName ?? "Eligible access", isGroup: isGroup)
                    },
                    approvals: (pendingList ?? []).map(summary),
                    problem: pendingList == nil ? "Couldn't read PIM approvals." : nil)
            },
            decide: { id, approve, reason in
                let reply = await decide(approvals, id: id, approve: approve, reason: reason, known: memory.pending)
                if reply.outcome == .done { memory.pending.removeAll { $0.id == id } }
                return reply
            },
            activate: { id, reason, hours in
                guard activationEnabled else {
                    return WatchReply(outcome: .failed, message: "Turn on role activation in Settings on your iPhone first.")
                }
                var known = memory.eligible.first(where: { $0.id == id })
                if known == nil { known = (try? await privileged.eligibleAccess())?.first(where: { $0.id == id }) }
                guard let access = known else {
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

    /// The request is looked up among those the last glance read, and read again only when
    /// it is not there. Graph refuses a request somebody else already decided, so a
    /// remembered one cannot be decided twice.
    static func decide(_ approvals: any ApprovalsProviding, id: String, approve: Bool, reason: String,
                       known: [PendingApproval]) async -> WatchReply {
        var found = known.first(where: { $0.id == id })
        if found == nil { found = (try? await approvals.pending())?.first(where: { $0.id == id }) }
        guard let approval = found else {
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
