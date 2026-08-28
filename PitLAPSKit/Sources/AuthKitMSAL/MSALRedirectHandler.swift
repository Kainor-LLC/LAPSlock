import Foundation
import MSAL

/// Hands a broker redirect back to MSAL.
///
/// Why this exists: when Microsoft Authenticator (or Company Portal) is installed, MSAL
/// stops using an in-app web view and delegates authentication to that app instead. The
/// result comes back as a URL open on `msauth.<bundle id>://auth`, which means the app has
/// to be listening for it. Without this, the interactive request never completes and the
/// failure surfaces as a generic "sign-in didn't complete" error, because nothing about it
/// looks like a consent problem or a cancellation.
///
/// This never appears in the simulator: no broker is installed there, so MSAL keeps the
/// whole flow in-process and no URL is ever handed back. It is a device-only code path.
///
/// Lives in AuthKitMSAL because that is the only module allowed to import MSAL. The app
/// target calls `MSALRedirect.handle(_:sourceApplication:)` and stays MSAL-free.
public enum MSALRedirect {

    /// Forwards a redirect URL to MSAL.
    ///
    /// - Parameters:
    ///   - url: the URL the app was opened with.
    ///   - sourceApplication: bundle identifier of the app that performed the open, taken
    ///     from `UIApplication.OpenURLOptionsKey.sourceApplication`. MSAL uses it to verify
    ///     the response actually came from a broker it trusts, so passing the real value
    ///     matters. Nil is accepted but weakens that check.
    /// - Returns: true if MSAL recognised and consumed the URL.
    @discardableResult
    public static func handle(_ url: URL, sourceApplication: String?) -> Bool {
        MSALPublicClientApplication.handleMSALResponse(url, sourceApplication: sourceApplication)
    }
}
