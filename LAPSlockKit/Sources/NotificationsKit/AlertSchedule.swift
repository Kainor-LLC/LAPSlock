import Foundation

// When the background run checks what (OPTIMIZATION-PLAN.md, step F).
//
// iOS gives a run about thirty seconds. Checked in stored order, every kind every time, an
// MSP's first few customers used them all and the rest were never reached, break-glass sign-
// ins included. So: break-glass for every tenant first, then the other kinds tenant by tenant
// from where the last run stopped, and the kinds that change once a day checked about that
// often. Skipping a kind leaves its last-seen keys as they are, so a skip never re-alerts.

public enum AlertSchedule {

    /// No new tenant is started after this many seconds of a run.
    public static let budget: TimeInterval = 22

    /// How often a kind is worth reading. Nil is every run.
    public static func interval(for kind: AlertKind) -> TimeInterval? {
        switch kind {
        case .secureScoreDrop: return 24 * 3_600
        case .expiringCredential: return 12 * 3_600
        case .messageDeadline: return 5 * 3_600
        case .serviceIncident, .breakGlassSignIn, .conditionalAccessChange, .securityIncident, .pimApproval: return nil
        }
    }

    /// The kinds due now, given when each was last read. A kind never read is due.
    public static func due(_ kinds: [AlertKind], lastChecked: (AlertKind) -> Date?, now: Date) -> [AlertKind] {
        kinds.filter { kind in
            guard let interval = interval(for: kind), let last = lastChecked(kind) else { return true }
            return now.timeIntervalSince(last) >= interval
        }
    }

    /// The tenants in the order a run takes them: starting after the one the last run
    /// finished with, and round to the start, so every customer is reached within a few runs.
    public static func rotated(_ tenants: [TenantAlertPreferences], after lastId: String?) -> [TenantAlertPreferences] {
        guard let lastId, let index = tenants.firstIndex(where: { $0.tenantId == lastId.lowercased() }) else { return tenants }
        return Array(tenants[(index + 1)...] + tenants[...index])
    }
}

/// When each tenant and kind was last read, and where the last run stopped.
public protocol AlertCheckLogging: Sendable {
    func lastChecked(tenantId: String, kind: AlertKind) -> Date?
    func setChecked(_ date: Date, tenantId: String, kind: AlertKind)
    /// The last time a run finished every due kind of this tenant, for Settings.
    func lastFinished(tenantId: String) -> Date?
    func setFinished(_ date: Date, tenantId: String)
    /// The tenant the last run finished with, for the next run to start after.
    var lastTenant: String? { get }
    func setLastTenant(_ tenantId: String?)
}

extension UserDefaultsLastSeenStore: AlertCheckLogging {
    private func checkedKey(_ tenantId: String, _ kind: AlertKind) -> String {
        "notifications.checked." + tenantId.lowercased() + "." + kind.rawValue
    }

    private func finishedKey(_ tenantId: String) -> String {
        "notifications.finished." + tenantId.lowercased()
    }

    private static let lastTenantKey = "notifications.lastTenant"

    public func lastChecked(tenantId: String, kind: AlertKind) -> Date? {
        defaults.object(forKey: checkedKey(tenantId, kind)) as? Date
    }

    public func setChecked(_ date: Date, tenantId: String, kind: AlertKind) {
        defaults.set(date, forKey: checkedKey(tenantId, kind))
    }

    public func lastFinished(tenantId: String) -> Date? {
        defaults.object(forKey: finishedKey(tenantId)) as? Date
    }

    public func setFinished(_ date: Date, tenantId: String) {
        defaults.set(date, forKey: finishedKey(tenantId))
    }

    public var lastTenant: String? { defaults.string(forKey: Self.lastTenantKey) }

    public func setLastTenant(_ tenantId: String?) {
        defaults.set(tenantId?.lowercased(), forKey: Self.lastTenantKey)
    }

    /// The schedule's timestamps for one tenant, cleared with its last-seen keys.
    func clearChecks(tenantId: String) {
        for kind in AlertKind.allCases {
            defaults.removeObject(forKey: checkedKey(tenantId, kind))
        }
        defaults.removeObject(forKey: finishedKey(tenantId))
        if lastTenant == tenantId.lowercased() { setLastTenant(nil) }
    }
}
