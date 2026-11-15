import Foundation

// Instant alerts, hosted by Kainor (HOSTED-WATCH-PLAN.md, H4): what the phone sends the
// watcher to register, and what each answer means. Pure data: the request itself, with its
// bearer token, is made by the app, so this kit stays out of reach of any token.

/// The body of POST /api/v1/devices: where to reach this phone and the key to encrypt to.
public struct InstantAlertsRegistration: Codable, Sendable, Equatable {
    public var deviceToken: String
    public var environment: String
    public var publicKey: String
    /// The accounts to watch as break-glass accounts. Applied only from an administrator who
    /// may configure; ignored otherwise.
    public var breakGlass: [String]?

    public init(code: PairingCode, breakGlass: [String]?) {
        self.deviceToken = code.deviceToken
        self.environment = code.environment
        self.publicKey = code.publicKey
        self.breakGlass = breakGlass
    }
}

/// What the watcher answered.
public enum InstantAlertsAnswer: Sendable, Equatable {
    /// Registered. Pin `senderKey` for `tenantId`.
    case registered(tenantId: String, label: String, senderKey: Data, breakGlassAccounts: Int, canConfigure: Bool)
    /// The organization has not approved TenantKeep Watch yet; an administrator opens this.
    case needsApproval(URL)
    /// The account lacks an active role that may register.
    case notPermitted
    /// A break-glass account was not found in the organization.
    case accountNotFound
    /// Anything else, with the HTTP status (0 for no answer).
    case failed(Int)

    public static func parse(status: Int, body: Data) -> InstantAlertsAnswer {
        let json = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
        switch status {
        case 200:
            guard let tenant = json["tenantId"] as? String,
                  let key = (json["senderKey"] as? String).flatMap(Base64URL.decode),
                  key.count == 65 else { return .failed(status) }
            return .registered(
                tenantId: tenant.lowercased(),
                label: json["label"] as? String ?? "Your organization",
                senderKey: key,
                breakGlassAccounts: json["breakGlassAccounts"] as? Int ?? 0,
                canConfigure: json["canConfigure"] as? Bool ?? false)
        case 409:
            guard let text = json["approvalUrl"] as? String, let url = URL(string: text),
                  url.scheme == "https", url.host == "login.microsoftonline.com" else { return .failed(status) }
            return .needsApproval(url)
        case 403:
            return .notPermitted
        case 400 where json["error"] as? String == "account":
            return .accountNotFound
        default:
            return .failed(status)
        }
    }
}
