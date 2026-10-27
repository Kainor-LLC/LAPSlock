import UserNotifications
import RelayKit

// Decrypts a relayed TenantKeep Watch alert before iOS shows it. docs/RELAY-API.md, section 10.
//
// The relay sends a neutral placeholder with `mutable-content` and the encrypted envelope
// under `e`. This opens it with the phone's Secure Enclave key and the sender pinned for the
// tenant, and rewrites the notification. Anything that fails (wrong sender, wrong phone,
// tampering, a key rotated since, a repeat) is shown as a notice with no content, until
// Apple grants the filtering entitlement that lets it be dropped. Nothing decrypted is
// written anywhere except a day of alert ids.

final class NotificationService: UNNotificationServiceExtension {
    private var handler: ((UNNotificationContent) -> Void)?
    private var content: UNMutableNotificationContent?

    override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        handler = contentHandler
        let content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
        self.content = content
        guard let envelope = request.content.userInfo["e"] as? [String: Any],
              let enc = envelope["enc"] as? String, let ct = envelope["ct"] as? String else {
            contentHandler(content)
            return
        }
        let prefix = (Bundle.main.object(forInfoDictionaryKey: "TKAppIdentifierPrefix") as? String).flatMap { $0.isEmpty || $0.contains("$(") ? nil : $0 }
        let phone = RelayPhone(store: KeychainRelayStateStore(teamPrefix: prefix))
        let seenURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.kainor.lapslock")?.appendingPathComponent("relay-seen.json")
        do {
            let alert = try phone.open(enc: enc, ct: ct, seen: RelaySeenStore(url: seenURL))
            content.title = alert.title
            content.body = alert.body
            content.threadIdentifier = "relay-" + alert.tenant
            var info: [String: Any] = ["tenantId": alert.tenant, "relayKind": alert.kind]
            if let link = alert.link { info["link"] = link }
            content.userInfo = info
        } catch {
            Self.discard(content)
        }
        contentHandler(content)
    }

    override func serviceExtensionTimeWillExpire() {
        if let handler, let content {
            Self.discard(content)
            handler(content)
        }
    }

    static func discard(_ content: UNMutableNotificationContent) {
        content.title = "TenantKeep"
        content.body = "An alert could not be verified and was discarded."
        content.userInfo = [:]
    }
}
