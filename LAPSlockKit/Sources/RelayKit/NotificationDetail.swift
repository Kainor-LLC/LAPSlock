import Foundation

// How much a notification may show.
//
// An organization that protects the app with Microsoft Intune can say that notifications
// must not carry its data, or must not appear at all. The app learns that from Microsoft's
// Intune App SDK. The notification extension, which shows a relayed alert while the app is
// not running, does not link that SDK, so the app writes the answer where the extension
// can read it: the settings the two share. It holds no secret, only one of three words.
//
// This lives in RelayKit because the extension links RelayKit and nothing else.

public enum NotificationDetail: String, Sendable, CaseIterable {
    /// No policy, or the policy allows notifications as they are.
    case full
    /// "Block organization data": that something happened, and nothing about it.
    case withoutDetails
    /// "Block": no notifications.
    case none

    public static let defaultsKey = "appProtection.notificationDetail"
    public static let appGroup = "group.com.kainor.lapslock"

    /// What every notification says in place of its details.
    public static let withheldTitle = "TenantKeep"
    public static let withheldBody = "You have an alert. Open TenantKeep to read it."

    /// What is in force. Nothing stored is `full`: no policy has said otherwise. Something
    /// stored that is not one of the three words is read as the stricter `withoutDetails`,
    /// so a damaged value never shows more than the organization allowed.
    public static func current(in defaults: UserDefaults? = UserDefaults(suiteName: appGroup)) -> NotificationDetail {
        guard let stored = defaults?.string(forKey: defaultsKey) else { return .full }
        return NotificationDetail(rawValue: stored) ?? .withoutDetails
    }

    /// Records it for the extension. `full` removes the entry, which is how an install with
    /// no policy looks.
    public func store(in defaults: UserDefaults? = UserDefaults(suiteName: appGroup)) {
        if self == .full {
            defaults?.removeObject(forKey: Self.defaultsKey)
        } else {
            defaults?.set(rawValue, forKey: Self.defaultsKey)
        }
    }

    /// The title and body to show for a notification that would have said `title` and
    /// `body`. Nil when nothing may be shown.
    public func shown(title: String, body: String) -> (title: String, body: String)? {
        switch self {
        case .full:           return (title, body)
        case .withoutDetails: return (Self.withheldTitle, Self.withheldBody)
        case .none:           return nil
        }
    }
}
