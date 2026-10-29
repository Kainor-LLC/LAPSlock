import SwiftUI
import NotificationsKit

/// The app's own alerts, the Threat Digest's, and alerts relayed from the organization's
/// automation.
struct SettingsNotificationsPage: View {
    /// The organizations offered a switch, and where the choices are kept.
    let notificationTenants: [NotificationTenant]
    let notificationsStore: (any NotificationPreferencesStoring)?
    let isPro: Bool
    let isDemo: Bool

    var body: some View {
        Form {
            if let notificationsStore, !notificationTenants.isEmpty {
                NotificationsSettingsSection(
                    model: NotificationsSettingsModel(tenants: notificationTenants, store: notificationsStore),
                    isPro: isPro,
                    isDemo: isDemo)
            }
            DigestAlertsSection(isPro: isPro, isDemo: isDemo)
            RelaySettingsSection(isPro: isPro, isDemo: isDemo)
        }
        .navigationTitle("Notifications")
    }
}
