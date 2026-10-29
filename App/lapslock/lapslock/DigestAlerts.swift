import SwiftUI
import UserNotifications
import ThreatDigestKit
import os

// Notifications from the Threat Digest (DIGEST-AND-PEOPLE-PLAN.md, step K): a new exploited
// vulnerability or CISA alert or advisory in the categories the admin chose. The feeds are
// public, so this is one check for the device, not one per organization, and it needs no
// sign-in. Pro, like every notification: when Pro lapses it turns off with the rest. The
// choices are not secrets and live in the defaults; so do the ids already seen.

enum DigestAlerts {
    static let enabledKey = "settings.digestAlertsEnabled"
    static let categoriesKey = "settings.digestAlertCategories"
    static let seenKey = "digestAlerts.seenIds"
    static let defaultCategories: Set<DigestCategory> = [.microsoft, .advisories]
    /// News never alerts, so it is not offered.
    static let offeredCategories = DigestCategory.allCases.filter { $0 != .news }

    static var isOn: Bool {
        get { UserDefaults.standard.bool(forKey: enabledKey) }
        set { UserDefaults.standard.set(newValue, forKey: enabledKey) }
    }

    static var categories: Set<DigestCategory> {
        get {
            guard let raw = UserDefaults.standard.array(forKey: categoriesKey) as? [String] else { return defaultCategories }
            return Set(raw.compactMap(DigestCategory.init(rawValue:)))
        }
        set { UserDefaults.standard.set(newValue.map(\.rawValue).sorted(), forKey: categoriesKey) }
    }

    /// One check: read the digest, announce what is new in the chosen categories, remember
    /// everything seen. Returns how many notifications it posted.
    static func check(provider: any ThreatDigestProviding = ThreatDigestService.shared) async -> Int {
        guard isOn else { return 0 }
        guard let snapshot = try? await provider.digest(),
              snapshot.statuses.contains(where: \.isAvailable) else { return 0 }
        let seen = UserDefaults.standard.array(forKey: seenKey) as? [String]
        let result = DigestAlertPlanner.plan(items: snapshot.items, seen: seen, categories: categories)
        UserDefaults.standard.set(result.remember, forKey: seenKey)
        guard let copy = DigestAlertPlanner.copy(for: result.announce) else { return 0 }
        let content = UNMutableNotificationContent()
        content.title = copy.title
        content.body = copy.body
        content.threadIdentifier = "digest"
        content.userInfo = ["module": AppModule.security.rawValue, "tab": "digest"]
        // One request id, so a newer one replaces the older rather than stacking.
        let request = UNNotificationRequest(identifier: "digest", content: content, trigger: nil)
        try? await UNUserNotificationCenter.current().add(request)
        return 1
    }

    #if DEBUG
    /// `-LAPSlockDigestAlertCheck`: one check at launch, logged under the perf category, so the
    /// simulator can show the baseline and a real notification without waiting for iOS.
    static func checkNowIfAsked() async {
        guard ProcessInfo.processInfo.arguments.contains("-LAPSlockDigestAlertCheck") else { return }
        let seenBefore = (UserDefaults.standard.array(forKey: seenKey) as? [String])?.count
        let posted = await check()
        let remembered = (UserDefaults.standard.array(forKey: seenKey) as? [String])?.count ?? 0
        Logger(subsystem: "com.kainor.lapslock", category: "perf")
            .info("digestAlerts on=\(isOn) seenBefore=\(seenBefore.map(String.init) ?? "none") posted=\(posted) remembered=\(remembered)")
    }
    #endif
}

/// Settings, Notifications: the digest's switch and its categories.
struct DigestAlertsSection: View {
    let isPro: Bool
    let isDemo: Bool
    @State private var isOn = DigestAlerts.isOn
    @State private var categories = DigestAlerts.categories
    @State private var notificationsDenied = false

    var body: some View {
        Section {
            Toggle(isOn: Binding(get: { isOn }, set: { on in Task { await turn(on) } })) {
                Text("New threats in the digest")
                Text("Exploited vulnerabilities, and CISA alerts and advisories")
            }
            .disabled(!isAvailable)
            if isOn {
                ForEach(DigestAlerts.offeredCategories) { category in
                    Toggle(isOn: Binding(get: { categories.contains(category) }, set: { on in choose(category, on) })) {
                        Text(category.title)
                        Text(category.detail)
                    }
                    .disabled(!isAvailable)
                }
            }
            if notificationsDenied {
                Text("Notifications are off for TenantKeep in iOS Settings, so nothing can be shown.")
                    .font(.footnote)
                    .foregroundStyle(.orange)
            }
        } header: {
            Text("Threat Digest")
        } footer: {
            Text(footer)
        }
    }

    private var isAvailable: Bool { isPro && !isDemo }

    private var footer: String {
        if isDemo { return "Not in demo mode." }
        if !isPro { return "Part of Pro, with the other notifications." }
        return "Checked in the background with the other notifications, when iOS allows. The same public feeds as the digest; nothing about your organization goes with the request. The first check only notes what is there, so it never announces the backlog."
    }

    private func turn(_ on: Bool) async {
        if on, !(await AlertsRunner.requestAuthorization()) {
            notificationsDenied = true
            return
        }
        notificationsDenied = false
        isOn = on
        DigestAlerts.isOn = on
        AlertsRunner.scheduleIfNeeded()
    }

    private func choose(_ category: DigestCategory, _ on: Bool) {
        if on { categories.insert(category) } else { categories.remove(category) }
        DigestAlerts.categories = categories
    }
}
