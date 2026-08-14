import Foundation

// Build Spec §4, §8 — consent onboarding.
//
// THE PROBLEM THIS SOLVES
// All four Graph scopes PitLAPS requests are admin-restricted. That produces a
// predictable and nasty onboarding failure:
//
//   An admin signs in, approves the consent prompt, but does NOT tick "Consent on
//   behalf of your organization." Entra records a per-user grant (consentType:
//   Principal) instead of a tenant-wide one (AllPrincipals). The app then works
//   perfectly for that admin and fails for every other person in the tenant — and
//   because the scopes are admin-restricted, a helpdesk tech cannot self-approve.
//
// The person who tested it sees success; the team sees AADSTS65001. Left unhandled,
// that reads as "this app is broken" rather than "one checkbox was missed".
//
// So consent state is treated as a first-class product concern: explained before
// sign-in, and recoverable with a shareable link after failure.

/// Builds the URLs used to grant tenant-wide admin consent.
public enum AdminConsentLink {

    /// The v2 admin consent endpoint. Sending an admin here grants for the whole
    /// organization — there is no per-user option on this flow, which is precisely why
    /// it is the reliable remedy for a missed checkbox.
    ///
    /// - Parameters:
    ///   - clientId: the app registration's client ID.
    ///   - tenant: a tenant ID (GUID) or verified domain. `nil` uses `organizations`,
    ///     which lets the admin sign in and have their own tenant resolved.
    ///   - redirectUri: where Entra returns after consent. Optional; when omitted,
    ///     Entra uses the app's configured reply URL.
    public static func url(clientId: String, tenant: String? = nil, redirectUri: String? = nil) -> URL? {
        let authority = (tenant?.isEmpty == false ? tenant! : "organizations")
        var comps = URLComponents(string: "https://login.microsoftonline.com/\(authority)/v2.0/adminconsent")
        var items = [URLQueryItem(name: "client_id", value: clientId)]
        if let redirectUri, !redirectUri.isEmpty {
            items.append(URLQueryItem(name: "redirect_uri", value: redirectUri))
        }
        // `scope` is required on the v2 endpoint. .default requests every delegated
        // permission configured on the registration, which is what tenant-wide consent
        // means here.
        items.append(URLQueryItem(name: "scope", value: "https://graph.microsoft.com/.default"))
        comps?.queryItems = items
        return comps?.url
    }

    /// Message an admin can forward to whoever holds Global Administrator or Privileged
    /// Role Administrator. Written to be pasted into Teams or email as-is.
    public static func requestMessage(appName: String = "PitLAPS", consentURL: URL?) -> String {
        var lines = [
            "\(appName) needs one-time approval from a Microsoft Entra administrator before our team can use it.",
            "",
            "It reads device inventory from Intune and local administrator passwords from Entra ID. It uses delegated access only, so each person still needs their own directory role to see a password, and every retrieval is recorded in our audit log.",
            ""
        ]
        if let consentURL {
            lines.append("Approval link: \(consentURL.absoluteString)")
            lines.append("")
        }
        lines.append("Approving from that link grants access for the whole organization. Approving from inside the app without selecting \"Consent on behalf of your organization\" only enables it for your own account.")
        return lines.joined(separator: "\n")
    }
}

/// Why the app can't currently reach Graph, expressed in product terms rather than
/// error codes. Drives which recovery UI is shown (§8).
public enum ConsentState: Sendable, Equatable {
    /// Consent is in place; nothing to show.
    case granted
    /// Nobody has consented for this tenant yet, and the signed-in user may not be
    /// able to. Show the "ask an administrator" path with a shareable link.
    case organizationApprovalRequired
    /// The signed-in user personally consented, but the organization hasn't — so this
    /// account works while others fail. Worth surfacing even though nothing looks
    /// broken for the current user.
    case grantedForThisUserOnly
    /// Consent exists but the user lacks the directory role to read passwords.
    /// A different problem with a different fix (§6: role, not consent).
    case roleMissing

    public var title: String {
        switch self {
        case .granted:
            return "Connected"
        case .organizationApprovalRequired:
            return "Approval needed from an administrator"
        case .grantedForThisUserOnly:
            return "Approved for your account only"
        case .roleMissing:
            return "Your account can't read passwords yet"
        }
    }

    public var explanation: String {
        switch self {
        case .granted:
            return "PitLAPS is connected to your organization."
        case .organizationApprovalRequired:
            return "Your organization hasn't approved PitLAPS yet. Reading local administrator passwords requires an administrator to approve it once for everyone."
        case .grantedForThisUserOnly:
            return "PitLAPS works for you, but nobody else in your organization can sign in yet. A tenant-wide approval fixes that in one step."
        case .roleMissing:
            return "You're signed in, but your account doesn't hold a directory role that can read local administrator passwords. Cloud Device Administrator is the least-privileged role that can, and it can be activated just-in-time through Privileged Identity Management."
        }
    }

    /// The single next action, phrased as a button label.
    public var actionLabel: String? {
        switch self {
        case .granted: return nil
        case .organizationApprovalRequired, .grantedForThisUserOnly: return "Get the approval link"
        case .roleMissing: return "How to fix this"
        }
    }
}

/// Classifies Entra error payloads into a `ConsentState`.
/// Kept pure so the mapping is unit-tested rather than discovered in production.
public enum ConsentDiagnostics {

    /// Entra error codes that mean "consent is missing for this caller".
    /// AADSTS65001 — user or admin has not consented.
    /// AADSTS900971 / AADSTS90094 — admin consent required for the requested scopes.
    static let consentCodes = ["AADSTS65001", "AADSTS90094", "AADSTS900971"]

    /// Inspects an error message for a consent-related Entra code.
    public static func state(fromErrorDescription description: String?) -> ConsentState? {
        guard let description, !description.isEmpty else { return nil }
        let upper = description.uppercased()
        if consentCodes.contains(where: { upper.contains($0) }) {
            return .organizationApprovalRequired
        }
        // Graph returns 403 with this shape when consent exists but the role does not.
        if upper.contains("AUTHORIZATION_REQUESTDENIED") || upper.contains("INSUFFICIENT PRIVILEGES") {
            return .roleMissing
        }
        return nil
    }

    /// Maps an `AuthError` onto a consent state where one applies.
    public static func state(from error: AuthError) -> ConsentState? {
        switch error {
        case .consentRequired:
            return .organizationApprovalRequired
        case .underlying(let message):
            return state(fromErrorDescription: message)
        default:
            return nil
        }
    }
}
