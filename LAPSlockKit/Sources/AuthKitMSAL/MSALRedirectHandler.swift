// MSAL's broker response handling is iOS-only, so this file is too.
// On the macOS test host it compiles to nothing, which is intended and matches
// MSALAuthManager.swift. macOS exists here only to host fast tests; the shipping
// product is an iOS app.
//
// The guard sits ABOVE the imports for the same reason it does in MSALAuthManager:
// the symbols below do not all exist on macOS. MSAL itself does build for macOS, but
// MSALPublicClientApplication.handleMSALResponse(_:sourceApplication:) does not exist
// there, so an unguarded file fails the macOS build with a missing member error while
// the iOS build stays perfectly healthy. That is a nasty shape of bug: the app runs on
// device, and only `swift test` tells you anything is wrong.
#if os(iOS)

import Foundation
import MSAL

/// Hands a broker redirect back to MSAL.
///
/// Why this exists: when Microsoft Authenticator (or Company Portal) is installed, MSAL
/// stops using an in-app web view and delegates authentication to that app instead. The
/// result comes back as a URL open on `msauth.<bundle id>://auth`, which means the app has
/// to be listening for it. Without this, the interactive request never completes and MSAL
/// reports "application did not receive response from broker" (MSALErrorDomain -50000),
/// which the app surfaces as a generic "sign-in didn't complete" error, because nothing
/// about it looks like a consent problem or a cancellation.
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
    ///   - sourceApplication: bundle identifier of the app that performed the open, where
    ///     the caller has it. SwiftUI's `.onOpenURL` does not expose it, so the app passes
    ///     nil; MSAL validates broker responses with a nonce (V2-broker-nonce) rather than
    ///     relying on this value, which is what makes nil acceptable rather than merely
    ///     tolerated. An app delegate path that does have the value should pass it.
    /// - Returns: true if MSAL recognised and consumed the URL.
    @discardableResult
    public static func handle(_ url: URL, sourceApplication: String?) -> Bool {
        MSALPublicClientApplication.handleMSALResponse(url, sourceApplication: sourceApplication)
    }
}

#endif // os(iOS)
