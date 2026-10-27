import Foundation

// The large demo tenant's Message Center and expiring items (optimization plan step C).

extension DemoTenantPulseProvider {

    public static func largeMessages(now: Date, count: Int = 200) -> [ServiceMessage] {
        let categories = ["planForChange", "stayInformed", "preventOrFixIssue"]
        let services = ["Exchange Online", "Microsoft Teams", "SharePoint Online", "Microsoft Intune", "Microsoft Entra"]
        return (0..<max(0, count)).map { i in
            ServiceMessage(
                id: "MC" + String(900_000 + i),
                title: services[i % services.count] + ": change " + String(i),
                category: categories[i % categories.count],
                isMajorChange: i % 11 == 0,
                actionRequiredByDateTime: i % 5 == 0 ? days(Double(3 + i % 40), from: now) : nil,
                lastModifiedDateTime: days(-Double(i % 60), from: now),
                services: [services[i % services.count]])
        }
    }

    public static func largeExpiringItems(now: Date, count: Int = 600) -> [ExpiringItem] {
        let kinds: [ExpiringItem.Kind] = [.appSecret, .appSecret, .appCertificate, .samlCertificate]
        return (0..<max(0, count)).map { i in
            ExpiringItem(
                id: "large-expiring-" + String(i),
                kind: kinds[i % kinds.count],
                owner: "App " + String(i / 2),
                detail: i % 3 == 0 ? nil : "Credential " + String(i),
                expiresAt: days(Double(i % 120) - 10, from: now))
        }
    }
}
