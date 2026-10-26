import Foundation
import UserNotifications
import BackgroundTasks
import AuthKit
import AuthKitMSAL
import NotificationsKit
import TenantPulseKit
import ConditionalAccessKit
import SignInTriageKit
import SecurityKit

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
    static var lastSeen: any LastSeenStoring = UserDefaultsLastSeenStore()

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
    @discardableResult
    static func run(auth suppliedAuth: (any AuthManaging)? = nil) async -> Int {
        defer { scheduleIfNeeded() }
        guard var prefs = try? preferencesStore.load(), prefs.anythingToCheck else { return 0 }
        let resolved: (any AuthManaging)?
        if let suppliedAuth { resolved = suppliedAuth } else { resolved = await SessionAuth.shared.restoredAuth() }
        guard let auth = resolved else { return 0 }

        var posted = 0
        for tenant in prefs.tenants where !tenant.activeKinds.isEmpty {
            if Task.isCancelled { break }
            let scoped = TenantScopedAuth(base: auth, tenantId: tenant.tenantId)
            // The probe: a scope consented at sign-in. If even this fails silently, the
            // tenant needs a foreground sign-in, and asking for every kind would fail the
            // same way.
            do {
                _ = try await scoped.token(scopes: ["DeviceManagementManagedDevices.Read.All"], allowInteractive: false)
            } catch {
                var paused = tenant
                paused.paused = true
                prefs.upsert(paused)
                try? preferencesStore.save(prefs)
                await post(AlertCopy.needsSignIn(tenantId: tenant.tenantId, label: tenant.label))
                posted += 1
                continue
            }

            let graph = GraphClient(auth: scoped)
            let sources = AlertSources(graph: graph, breakGlassUPNs: tenant.breakGlassUPNs)
            var observations: [Observation] = []
            for kind in tenant.activeKinds {
                if Task.isCancelled { break }
                // A kind whose module was never consented in this tenant fails here and is
                // skipped quietly; the others still run.
                if let keys = await sources.keys(for: kind) {
                    observations.append(Observation(kind: kind, keys: keys))
                }
            }
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
                posted += 1
            }
        }
        return posted
    }

    // MARK: - posting

    static func post(_ alert: PlannedAlert) async {
        let content = UNMutableNotificationContent()
        content.title = alert.title
        content.body = alert.body
        content.threadIdentifier = alert.threadIdentifier
        content.userInfo = alert.userInfo
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
            case .serviceIncident:
                let report = try await TenantPulseService(graph: graph).health()
                return Set(report.activeIssues.filter(\.isIncident).map { issue in
                    issue.id + "|" + String(Int(issue.lastModifiedDateTime?.timeIntervalSince1970 ?? 0))
                })
            case .messageDeadline:
                let horizon = now.addingTimeInterval(14 * 86_400)
                let messages = try await TenantPulseService(graph: graph).messages()
                return Set(messages.compactMap { message in
                    guard let due = message.actionRequiredByDateTime, due > now, due <= horizon else { return nil }
                    return message.id
                })
            case .expiringCredential:
                let horizon = now.addingTimeInterval(30 * 86_400)
                let items = try await TenantPulseService(graph: graph).expiringItems()
                return Set(items.filter { $0.expiresAt <= horizon && $0.expiresAt > now.addingTimeInterval(-86_400) }.map(\.id))
            case .secureScoreDrop:
                guard let summary = try await TenantPulseService(graph: graph).secureScore() else { return [] }
                if let change = summary.change(overDays: 1), change < 0 { return [summary.latest.id] }
                return []
            case .conditionalAccessChange:
                let policies = try await ConditionalAccessService(graph: graph).policies()
                return Set(policies.map { $0.id + "|" + String(Int($0.lastChanged?.timeIntervalSince1970 ?? 0)) })
            case .securityIncident:
                let incidents = try await SecurityService(graph: graph).incidents()
                return Set(incidents.filter { $0.isOpen && $0.severity == .high }.map(\.id))
            case .breakGlassSignIn:
                let triage = SignInTriageService(graph: graph)
                var keys = Set<String>()
                for upn in breakGlassUPNs {
                    let events = try await triage.signIns(SignInQuery(userPrincipalName: upn, last24Hours: true, limit: 20))
                    for event in events { keys.insert(OpaqueKey.make(event.id, upn)) }
                }
                return keys
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
        if let existing = await MainActor.run(body: { self.auth ?? self.restored }) {
            return existing
        }
        return await restoreFresh()
    }

    nonisolated private func restoreFresh() async -> (any AuthManaging)? {
        guard let manager = try? MSALAuthManager(config: .vendorDefault),
              await manager.restoreSession() != nil else { return nil }
        await MainActor.run { self.restored = manager }
        return manager
    }
}

extension Notification.Name {
    /// Posted when a notification is tapped; the shell opens the module it names.
    static let openModuleFromAlert = Notification.Name("tenantkeep.openModuleFromAlert")
}

/// Shows alerts while the app is open, and routes a tap to its module.
final class AlertsNotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = AlertsNotificationDelegate()

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list]
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        guard let module = response.notification.request.content.userInfo["module"] as? String else { return }
        await MainActor.run {
            NotificationCenter.default.post(name: .openModuleFromAlert, object: nil, userInfo: ["module": module])
        }
    }
}
