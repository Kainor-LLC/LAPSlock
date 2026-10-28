import Foundation
import UserNotifications
import BackgroundTasks
import AuthKit
import AuthKitMSAL
import NotificationsKit
import TenantPulseKit
import ConditionalAccessKit
import SignInTriageKit
import ApprovalsKit
import SecurityKit
import ManagedConfigKit
import RelayKit

// The background run. Spec section 3.11.
//
// iOS decides when this runs, typically minutes to tens of minutes apart and never in Low
// Power Mode. Each run: for every enabled tenant, a silent token for that tenant only,
// through an auth adapter that cannot prompt and cannot move the foreground's operating
// tenant; each enabled kind read with the module that owns it and reduced to opaque keys;
// the planner decides what is new; one local notification per tenant per kind. A tenant
// whose silent sign-in fails gets one "sign in again" line and is paused until the admin
// next signs in with the app open. Nothing is retried in a loop.

enum AlertsRunner {

    static let taskIdentifier = "com.kainor.lapslock.notifications.refresh"
    /// The earliest iOS may run the next check. It will usually be later.
    static let interval: TimeInterval = 15 * 60

    static var preferencesStore: any NotificationPreferencesStoring = KeychainNotificationPreferencesStore()
    private static let defaultsStore = UserDefaultsLastSeenStore()
    static var lastSeen: any LastSeenStoring = defaultsStore
    /// When each tenant and kind was last read, and where the last run stopped.
    static var checkLog: any AlertCheckLogging = defaultsStore

    // MARK: - scheduling

    /// Called when the app goes to the background and after every run. Asks for nothing
    /// when nothing is switched on.
    static func scheduleIfNeeded() {
        guard let prefs = try? preferencesStore.load(), prefs.anythingToCheck else {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: taskIdentifier)
            return
        }
        let request = BGAppRefreshTaskRequest(identifier: taskIdentifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: interval)
        try? BGTaskScheduler.shared.submit(request)
    }

    // MARK: - the run

    /// The whole run. Returns how many notifications it posted, for the DEBUG path.
    ///
    /// iOS gives a run about thirty seconds (OPTIMIZATION-PLAN.md, step F). So, in order:
    /// break-glass sign-ins for every tenant, four tenants at a time, because that is the
    /// one alert that cannot wait; then the other kinds tenant by tenant, starting after the
    /// tenant the last run finished with, the kinds due for each read together, and no new
    /// tenant started after `AlertSchedule.budget`. Kinds that change about once a day are
    /// read about that often. Nothing waits to retry: a throttled read is next run's.
    @discardableResult
    static func run(auth suppliedAuth: (any AuthManaging)? = nil) async -> Int {
        defer { scheduleIfNeeded() }
        let deadline = Date().addingTimeInterval(AlertSchedule.budget)
        let managed = ManagedConfigStore.read()
        guard !managed.isDisabled("notifications") else { return 0 }
        guard var prefs = try? preferencesStore.load(), prefs.anythingToCheck else { return 0 }
        let resolved: (any AuthManaging)?
        if let suppliedAuth { resolved = suppliedAuth } else { resolved = await SessionAuth.shared.restoredAuth() }
        guard let auth = resolved else { return 0 }

        // The organization's break-glass accounts apply to its own tenant: the pinned one,
        // or the signed-in account's home tenant when nothing is pinned.
        let homeTenant = await auth.currentAccount?.tenantId.lowercased()
        let managedTenant = managed.tenantPin ?? homeTenant
        if !managed.breakGlassUPNs.isEmpty, let managedTenant, var own = prefs.tenant(managedTenant) {
            own.breakGlassUPNs = TenantAlertPreferences.cleanUPNs(own.breakGlassUPNs + managed.breakGlassUPNs)
            prefs.upsert(own)
        }
        let tenants = prefs.tenants.filter { tenant in
            !tenant.activeKinds.isEmpty && (managed.tenantPin == nil || tenant.tenantId == managed.tenantPin)
        }

        // One connection pool for the run, shared by every tenant's Graph client: each
        // still has its own auth for its tenant, and the token goes with each request. A
        // shorter wait per request than the foreground's, and no retries.
        let urlSession = GraphClient.makeSession(timeout: 15)
        defer { urlSession.finishTasksAndInvalidate() }
        func sources(for tenant: TenantAlertPreferences) -> AlertSources {
            let scoped = TenantScopedAuth(base: auth, tenantId: tenant.tenantId)
            return AlertSources(graph: GraphClient(auth: scoped, session: urlSession, retryPolicy: .none),
                                breakGlassUPNs: tenant.breakGlassUPNs)
        }

        var posted = 0
        // Whether each tenant answered its probe this run, so a tenant is probed once.
        var signedIn: [String: Bool] = [:]

        // Break-glass first, for every tenant, from the same starting point as the rest so
        // the same tenants are not always last.
        let watched = AlertSchedule.rotated(tenants, after: checkLog.lastTenant)
            .filter { $0.activeKinds.contains(.breakGlassSignIn) }
        for group in stride(from: 0, to: watched.count, by: 4).map({ Array(watched[$0 ..< min($0 + 4, watched.count)]) }) {
            if Task.isCancelled || Date() >= deadline { break }
            let results = await withTaskGroup(of: (String, Probe, Set<String>?).self) { tasks in
                for tenant in group {
                    let reader = sources(for: tenant)
                    tasks.addTask {
                        let probe = await Self.probe(tenant, auth: auth)
                        guard probe == .signedIn else { return (tenant.tenantId, probe, nil) }
                        return (tenant.tenantId, probe, await reader.keys(for: .breakGlassSignIn))
                    }
                }
                var collected: [(String, Probe, Set<String>?)] = []
                for await result in tasks { collected.append(result) }
                return collected
            }
            for (tenantId, probe, keys) in results {
                guard let tenant = tenants.first(where: { $0.tenantId == tenantId }) else { continue }
                switch probe {
                case .cancelled:
                    continue
                case .needsSignIn:
                    signedIn[tenantId] = false
                    posted += await pause(tenant, in: &prefs)
                case .signedIn:
                    signedIn[tenantId] = true
                    if let keys {
                        posted += await plan(tenant, [AlertObservation(kind: .breakGlassSignIn, keys: keys)])
                    }
                }
            }
        }

        // Then everything else, tenant by tenant, from where the last run stopped.
        for tenant in AlertSchedule.rotated(tenants, after: checkLog.lastTenant) {
            if Task.isCancelled || Date() >= deadline { break }
            if signedIn[tenant.tenantId] == nil {
                switch await probe(tenant, auth: auth) {
                case .cancelled:
                    return posted
                case .needsSignIn:
                    signedIn[tenant.tenantId] = false
                    posted += await pause(tenant, in: &prefs)
                    continue
                case .signedIn:
                    signedIn[tenant.tenantId] = true
                }
            }
            guard signedIn[tenant.tenantId] == true else { continue }

            let started = Date()
            let due = AlertSchedule.due(
                tenant.activeKinds.filter { $0 != .breakGlassSignIn },
                lastChecked: { checkLog.lastChecked(tenantId: tenant.tenantId, kind: $0) },
                now: started)
            let observations = await read(due, from: sources(for: tenant))
            // A kind read is a kind checked, whatever it found; a failed read is retried
            // next run, whatever its schedule.
            for observation in observations {
                checkLog.setChecked(started, tenantId: tenant.tenantId, kind: observation.kind)
            }
            posted += await plan(tenant, observations)
            if Task.isCancelled { break }
            checkLog.setFinished(started, tenantId: tenant.tenantId)
            checkLog.setLastTenant(tenant.tenantId)
        }

        // The watch's glance and complications are as fresh as this run, when the app's
        // screens exist to say which mode it is in; a cold background launch skips it. Within
        // the run's own time, rather than after iOS has suspended the app.
        if !Task.isCancelled, Date() < deadline {
            await WatchConnector.shared.pushIfDue()
        }
        return posted
    }

    enum Probe: Sendable, Equatable { case signedIn, needsSignIn, cancelled }

    /// A scope consented at sign-in, asked for silently. If even this fails, the tenant
    /// needs a foreground sign-in, and asking for every kind would fail the same way. A run
    /// cut short by iOS is not a failed sign-in.
    private static func probe(_ tenant: TenantAlertPreferences, auth: any AuthManaging) async -> Probe {
        let scoped = TenantScopedAuth(base: auth, tenantId: tenant.tenantId)
        do {
            _ = try await scoped.token(scopes: ["DeviceManagementManagedDevices.Read.All"], allowInteractive: false)
            return .signedIn
        } catch {
            if error is CancellationError || Task.isCancelled { return .cancelled }
            return .needsSignIn
        }
    }

    /// Pauses a tenant until the admin next signs in with the app open, and says so once.
    private static func pause(_ tenant: TenantAlertPreferences, in prefs: inout NotificationPreferences) async -> Int {
        var paused = tenant
        paused.paused = true
        prefs.upsert(paused)
        try? preferencesStore.save(prefs)
        await post(AlertCopy.needsSignIn(tenantId: tenant.tenantId, label: tenant.label))
        return 1
    }

    /// The kinds read together, three at a time. A kind whose module was never consented in
    /// this tenant fails here and is skipped quietly; the others still count.
    private static func read(_ kinds: [AlertKind], from sources: AlertSources) async -> [AlertObservation] {
        await withTaskGroup(of: AlertObservation?.self) { group in
            var waiting = kinds[...]
            func start() {
                guard let kind = waiting.popFirst() else { return }
                group.addTask { await sources.keys(for: kind).map { AlertObservation(kind: kind, keys: $0) } }
            }
            for _ in 0 ..< 3 { start() }
            var observations: [AlertObservation] = []
            for await observation in group {
                if let observation { observations.append(observation) }
                start()
            }
            return observations
        }
    }

    /// Decides what is new for one tenant, remembers what was seen, and posts.
    private static func plan(_ tenant: TenantAlertPreferences, _ observations: [AlertObservation]) async -> Int {
        guard !observations.isEmpty else { return 0 }
        let result = AlertPlanner().plan(
            tenantId: tenant.tenantId,
            label: tenant.label,
            observations: observations,
            lastSeen: { lastSeen.keys(tenantId: tenant.tenantId, kind: $0) })
        for (kind, keys) in result.remembered {
            lastSeen.setKeys(keys, tenantId: tenant.tenantId, kind: kind)
        }
        for alert in result.alerts {
            await post(alert)
        }
        return result.alerts.count
    }

    // MARK: - posting

    static func post(_ alert: PlannedAlert) async {
        let content = UNMutableNotificationContent()
        content.title = alert.title
        content.body = alert.body
        content.threadIdentifier = alert.threadIdentifier
        content.userInfo = alert.userInfo
        if let category = alert.categoryIdentifier { content.categoryIdentifier = category }
        // Ordinary kinds: a banner, no sound. Passive was tried first and never shows a
        // banner at all, which reads as "nothing happened". Break-glass: sound, and
        // time-sensitive so it can come through Focus; that level needs its own
        // entitlement, without which iOS delivers it as ordinary (on the checklist).
        content.sound = alert.timeSensitive ? .default : nil
        content.interruptionLevel = alert.timeSensitive ? .timeSensitive : .active
        // The thread id as the request id, so a newer count replaces the older one.
        let request = UNNotificationRequest(identifier: alert.threadIdentifier, content: content, trigger: nil)
        try? await UNUserNotificationCenter.current().add(request)
    }

    /// Asks once, at the moment the admin turns the first switch on. Returns whether
    /// notifications may be shown.
    /// The one action category: Review, on a PIM approval. Registered at launch.
    static func registerCategories() {
        let review = UNNotificationAction(identifier: PlannedAlert.reviewAction, title: "Review", options: [.foreground])
        let category = UNNotificationCategory(identifier: PlannedAlert.reviewCategory, actions: [review], intentIdentifiers: [])
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    static func requestAuthorization() async -> Bool {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        switch settings.authorizationStatus {
        case .authorized, .provisional, .ephemeral:
            return true
        case .denied:
            return false
        default:
            return (try? await center.requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        }
    }

    /// A sample from demo data, for the Settings button: shows what a notification looks
    /// like without waiting for iOS to run the check.
    static func postPreview(label: String) async {
        await post(AlertCopy.alert(tenantId: "preview", label: label, kind: .serviceIncident, count: 2))
    }

    /// After a foreground sign-in, every paused tenant gets another chance.
    static func unpauseAll() {
        guard var prefs = try? preferencesStore.load(), !prefs.paused.isEmpty else { return }
        for var tenant in prefs.paused {
            tenant.paused = false
            prefs.upsert(tenant)
        }
        try? preferencesStore.save(prefs)
    }

    /// When Pro lapses, the switches turn off rather than the run silently doing nothing.
    static func disableAll() {
        guard var prefs = try? preferencesStore.load(), prefs.tenants.contains(where: \.enabled) else { return }
        for var tenant in prefs.tenants where tenant.enabled {
            tenant.enabled = false
            prefs.upsert(tenant)
        }
        try? preferencesStore.save(prefs)
        scheduleIfNeeded()
    }
}

/// Each kind, read with the module that owns it and reduced to keys. Nil when the read
/// failed, which the run treats as "not this time".
struct AlertSources {
    let graph: GraphClient
    let breakGlassUPNs: [String]
    var now: Date = Date()

    func keys(for kind: AlertKind) async -> Set<String>? {
        do {
            switch kind {
            // The keys below are exactly what they were when each kind read the screen's full
            // payload, so a tenant's first run after the lean reads arrived alerts on nothing
            // it had already seen (OPTIMIZATION-PLAN.md, step F).
            case .serviceIncident:
                let issues = try await TenantPulseService(graph: graph).activeIssueStamps()
                return Set(issues.filter(\.isIncident).map { issue in
                    issue.id + "|" + String(Int(issue.lastModifiedDateTime?.timeIntervalSince1970 ?? 0))
                })
            case .messageDeadline:
                let horizon = now.addingTimeInterval(14 * 86_400)
                let messages = try await TenantPulseService(graph: graph).messageDeadlines(from: now, through: horizon)
                return Set(messages.compactMap { message in
                    guard let due = message.actionRequiredByDateTime, due > now, due <= horizon else { return nil }
                    return message.id
                })
            case .expiringCredential:
                let horizon = now.addingTimeInterval(30 * 86_400)
                let items = try await TenantPulseService(graph: graph).expiringItems()
                return Set(items.filter { $0.expiresAt <= horizon && $0.expiresAt > now.addingTimeInterval(-86_400) }.map(\.id))
            case .secureScoreDrop:
                // Yesterday's change needs today's snapshot and yesterday's, not a month.
                guard let summary = try await TenantPulseService(graph: graph).secureScore(snapshots: 2) else { return [] }
                if let change = summary.change(overDays: 1), change < 0 { return [summary.latest.id] }
                return []
            case .conditionalAccessChange:
                let policies = try await ConditionalAccessService(graph: graph).policyStamps()
                return Set(policies.map { $0.id + "|" + String(Int($0.lastChanged?.timeIntervalSince1970 ?? 0)) })
            case .pimApproval:
                return try await ApprovalsService(readingWith: graph).pendingIds()
            case .securityIncident:
                let incidents = try await SecurityService(graph: graph).incidentStatuses(highOnly: true)
                return Set(incidents.filter { $0.isOpen && $0.severity == .high }.map(\.id))
            case .breakGlassSignIn:
                // Every account at once rather than one after another; any failure is the
                // kind failing, as before.
                let triage = SignInTriageService(graph: graph)
                return try await withThrowingTaskGroup(of: [String].self) { group in
                    for upn in breakGlassUPNs {
                        group.addTask {
                            let events = try await triage.signIns(SignInQuery(userPrincipalName: upn, last24Hours: true, limit: 20))
                            return events.map { OpaqueKey.make($0.id, upn) }
                        }
                    }
                    var keys = Set<String>()
                    for try await part in group { keys.formUnion(part) }
                    return keys
                }
            }
        } catch {
            return nil
        }
    }
}

/// The one auth manager the app built, for the background run to reuse. When iOS launches
/// the app only to run the check, there is none yet, and the run restores one silently.
@MainActor
final class SessionAuth {
    static let shared = SessionAuth()
    weak var auth: MSALAuthManager?
    private var restored: MSALAuthManager?

    nonisolated func restoredAuth() async -> (any AuthManaging)? {
        await restoredManager()
    }

    /// The manager itself, for a caller that builds a whole live session on it.
    nonisolated func restoredManager() async -> MSALAuthManager? {
        if let existing = await MainActor.run(body: { self.auth ?? self.restored }) {
            return existing
        }
        return await restoreFresh()
    }

    nonisolated private func restoreFresh() async -> MSALAuthManager? {
        guard let manager = try? MSALAuthManager(config: .vendorDefault),
              await manager.restoreSession() != nil else { return nil }
        await MainActor.run { self.restored = manager }
        return manager
    }
}

extension Notification.Name {
    /// Posted when a notification is tapped, with an `AlertRoute` as the object. The root
    /// switches to the alert's organization if it has to, then the shell opens the module.
    static let openModuleFromAlert = Notification.Name("tenantkeep.openModuleFromAlert")
}

/// A tapped alert: the module to open, an optional tab or person, and the organization it
/// is about. Built from a local alert's `module`, or from a relayed alert's `tenantkeep://`
/// link (RELAY-API.md), whose host names the module.
struct AlertRoute: Equatable {
    let module: AppModule
    var tab: String?
    var upn: String?
    /// Lowercase. Nil when the alert does not say, which opens it where the admin is.
    var tenantId: String?

    /// The last tap not yet handled by the root.
    @MainActor static var pending: AlertRoute?

    init?(_ fields: [String: String]) {
        if let raw = fields["module"], let module = AppModule(rawValue: raw) {
            self.module = module
            tab = fields["tab"]
        } else if let link = fields["link"], let url = URL(string: link), url.scheme?.lowercased() == "tenantkeep",
                  let host = url.host()?.lowercased(),
                  let module = AppModule.allCases.first(where: { $0.rawValue.lowercased() == host }) {
            self.module = module
            upn = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first { $0.name == "upn" }?.value
        } else {
            return nil
        }
        tenantId = fields["tenantId"]?.lowercased()
    }
}

/// Shows alerts while the app is open, and routes a tap to its module.
final class AlertsNotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = AlertsNotificationDelegate()

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list]
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let info = response.notification.request.content.userInfo
        var fields: [String: String] = [:]
        for key in ["module", "tab", "link", "tenantId"] {
            if let value = info[key] as? String { fields[key] = value }
        }
        // A relayed alert that arrived before the phone was unlocked after a restart: the
        // extension kept the envelope. Now that the phone is unlocked it can be opened,
        // shown with its real content, and routed like any other.
        if fields.isEmpty, let envelope = info["e"] as? [String: Any],
           let enc = envelope["enc"] as? String, let ct = envelope["ct"] as? String,
           let alert = await RelayCoordinator.shared.openDeferred(enc: enc, ct: ct) {
            fields["tenantId"] = alert.tenant
            if let link = alert.link { fields["link"] = link }
        }
        await MainActor.run {
            guard let route = AlertRoute(fields) else { return }
            // Kept as well as posted: a tap that launches the app can arrive before the
            // root view is listening, and the root reads this when it appears.
            AlertRoute.pending = route
            NotificationCenter.default.post(name: .openModuleFromAlert, object: route)
        }
    }
}
