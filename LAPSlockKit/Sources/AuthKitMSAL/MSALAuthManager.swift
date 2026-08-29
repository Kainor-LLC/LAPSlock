// MSAL's interactive flow is UIKit-based, so this implementation is iOS-only.
// On the macOS test host this target compiles to nothing, which is intended:
// the shipping product is an iOS app, and macOS exists only to host fast tests.
// The guard must sit ABOVE the imports: UIKit does not exist on macOS.
#if os(iOS)

import Foundation
import UIKit
import MSAL
import AuthKit

// Build Spec §4, §2.1, §3.3, §9. The ONLY file that imports MSAL.
//
// Responsibilities:
//   * interactive account-selection sign-in on /common (§2.1)
//   * per-account tenant-specific authority for silent acquisition (§2.1)
//   * tenant pinning: the token's tid MUST match the account's tenant (§3.3 guard)
//   * ThisDeviceOnly, non-synced keychain for the MSAL token cache (§4)
//   * config injection for BYO registration (§9)
//
// CONCURRENCY NOTE — read this before changing anything in here.
//
// It is not enough to build MSALWebviewParameters on the main actor. MSAL dereferences
// the presenting view controller AGAIN inside acquireToken, on whatever thread you called
// acquireToken from. This actor's methods run on the cooperative thread pool, so calling
// acquireToken directly from actor context reads UIViewController.view and UIView.window
// off the main thread. Main Thread Checker flags it, and on a real device with Microsoft
// Authenticator installed the broker return path then fails: the broker screen appears,
// the user authenticates, and the completion never delivers a usable result.
//
// This was invisible in the simulator. Without a broker installed MSAL keeps the whole
// flow in-process, so the fragile part never ran.
//
// Therefore: every MSAL call that can present UI (acquireToken, signout) is dispatched to
// the main thread before it is made. Silent acquisition presents nothing and stays here.
// If you add another MSAL entry point that can show a screen, dispatch it too.

/// Configuration for the app registration. `.vendorDefault` ships with the app;
/// `.custom` is supplied by an enterprise using their own registration (§9 BYO).
public struct AuthConfiguration: Sendable {
    public let clientId: String
    public let redirectUri: String
    /// nil → use /common for account selection, then pin to the account's tenant.
    /// Set to a specific tenant GUID only for single-tenant BYO deployments.
    public let authorityTenant: String?

    public init(clientId: String, redirectUri: String, authorityTenant: String? = nil) {
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.authorityTenant = authorityTenant
    }

    /// Vendor multi-tenant default (§9).
    ///
    /// This client ID points at the "LAPSlock" app registration in the Kainor LLC tenant.
    /// It is NOT a secret — it appears in every authorization request and is public by
    /// design for a PKCE public client. What it is, however, is load-bearing: every
    /// shipped build references it, and every customer tenant's consent creates a service
    /// principal pointing at this object. Changing or deleting it breaks every install.
    ///
    /// Registration facts (created 2026-08-14):
    ///   * Audience: AzureADMultipleOrgs (any work/school tenant, no personal accounts)
    ///   * Public client, allow public client flows = Yes, no client secret
    ///   * Delegated Graph scopes only: DeviceManagementManagedDevices.Read.All,
    ///     Device.Read.All, DeviceLocalCredential.ReadBasic.All,
    ///     DeviceLocalCredential.Read.All
    ///
    /// The bundle identifier of the app target MUST be com.kainor.lapslock, because the
    /// redirect URI below is derived from it. A mismatch produces an MSAL redirect error.
    public static let vendorDefault = AuthConfiguration(
        clientId: "50c9aa83-4f5c-4203-a3c0-adab54a2ba3a",
        redirectUri: "msauth.com.kainor.lapslock://auth",
        authorityTenant: nil    // multi-tenant: /common for selection, then pin per account
    )
}

public actor MSALAuthManager: AuthManaging {
    private let config: AuthConfiguration
    private let application: MSALPublicClientApplication
    private var pinnedAccount: AdminAccount?

    public init(config: AuthConfiguration) throws {
        self.config = config

        #if DEBUG
        _ = Self.debugLoggingInstalled
        #endif

        let authorityURL = URL(string: "https://login.microsoftonline.com/\(config.authorityTenant ?? "common")")!
        let authority = try MSALAADAuthority(url: authorityURL)
        let pcaConfig = MSALPublicClientApplicationConfig(
            clientId: config.clientId,
            redirectUri: config.redirectUri,
            authority: authority
        )
        // Keep tokens on this device only; never sync to iCloud Keychain (§4).
        pcaConfig.cacheConfig.keychainSharingGroup = Bundle.main.bundleIdentifier ?? "com.kainor.lapslock"
        self.application = try MSALPublicClientApplication(configuration: pcaConfig)
    }

    public var currentAccount: AdminAccount? {
        get async { pinnedAccount }
    }

    // MARK: - sign in

    @discardableResult
    public func signIn() async throws -> AdminAccount {
        let webParams = try await MainActorUI.webviewParameters()
        let params = MSALInteractiveTokenParameters(scopes: Self.baseScopes, webviewParameters: webParams)
        params.promptType = .selectAccount

        let result = try await acquireInteractive(params)
        let account = try Self.account(from: result)
        self.pinnedAccount = account
        return account
    }

    // MARK: - token acquisition

    public func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        guard let account = pinnedAccount else { throw AuthError.noAccount }

        // Pin silent acquisition to the account's own tenant authority (§2.1).
        let authorityURL = URL(string: "https://login.microsoftonline.com/\(account.tenantId)")!
        let tenantAuthority = try MSALAADAuthority(url: authorityURL)

        // account(forIdentifier:) returns a NON-optional MSALAccount and throws if the
        // account isn't in the cache, so no conditional binding here.
        let msalAccount = try application.account(forIdentifier: account.id)

        let silent = MSALSilentTokenParameters(scopes: scopes, account: msalAccount)
        silent.authority = tenantAuthority

        do {
            let result = try await acquireSilent(silent)
            try Self.assertTenant(result, matches: account)   // §3.3 guard
            return result.accessToken
        } catch let error as AuthError {
            switch error {
            case .interactionRequired, .consentRequired:
                guard allowInteractive else { throw AuthError.interactionRequired }
                return try await interactiveToken(scopes: scopes, account: account, authority: tenantAuthority)
            default:
                throw error
            }
        }
    }

    public func signOut(account: AdminAccount) async throws {
        // A throw here means nothing is cached for this account, which is
        // indistinguishable from "already signed out" — so absorb it.
        let msalAccount: MSALAccount
        do {
            msalAccount = try application.account(forIdentifier: account.id)
        } catch {
            if pinnedAccount?.id == account.id { pinnedAccount = nil }
            return
        }
        let webParams = try await MainActorUI.webviewParameters()
        let params = MSALSignoutParameters(webviewParameters: webParams)

        try await performSignout(msalAccount, params)
        if pinnedAccount?.id == account.id { pinnedAccount = nil }
    }

    // MARK: - interactive fallback (incremental consent, §4)

    private func interactiveToken(
        scopes: [String],
        account: AdminAccount,
        authority: MSALAuthority
    ) async throws -> String {
        let webParams = try await MainActorUI.webviewParameters()
        let params = MSALInteractiveTokenParameters(scopes: scopes, webviewParameters: webParams)
        params.authority = authority
        params.loginHint = account.username

        let result = try await acquireInteractive(params)
        try Self.assertTenant(result, matches: account)
        return result.accessToken
    }

    // MARK: - continuation wrappers

    /// Interactive acquisition. Dispatched to the main thread because MSAL touches UIKit
    /// inside this call, not only while building the parameters. See the concurrency note
    /// at the top of the file before changing this.
    private func acquireInteractive(_ params: MSALInteractiveTokenParameters) async throws -> MSALResult {
        let app = application
        return try await withCheckedThrowingContinuation { cont in
            DispatchQueue.main.async {
                app.acquireToken(with: params) { result, error in
                    if let result { cont.resume(returning: result) }
                    else { cont.resume(throwing: Self.map(error)) }
                }
            }
        }
    }

    /// Sign-out can present a web view, so it gets the same treatment as acquireToken.
    private func performSignout(
        _ account: MSALAccount,
        _ params: MSALSignoutParameters
    ) async throws {
        let app = application
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            DispatchQueue.main.async {
                app.signout(with: account, signoutParameters: params) { _, error in
                    if let error { cont.resume(throwing: Self.map(error)) } else { cont.resume(returning: ()) }
                }
            }
        }
    }

    /// Silent acquisition presents nothing, so it does not need the main thread.
    private func acquireSilent(_ params: MSALSilentTokenParameters) async throws -> MSALResult {
        try await withCheckedThrowingContinuation { cont in
            application.acquireTokenSilent(with: params) { result, error in
                if let result { cont.resume(returning: result) }
                else { cont.resume(throwing: Self.map(error)) }
            }
        }
    }

    // MARK: - debug logging

    #if DEBUG
    /// MSAL's own log stream, development builds only.
    ///
    /// Two guarantees, both deliberate. `piiEnabled` stays false, and any message MSAL
    /// flags as containing PII is dropped rather than printed, so tokens, account
    /// identifiers, and authorization codes never reach the console. And the whole block
    /// is compiled out of Release, so a shipping build has no MSAL log sink at all.
    ///
    /// This exists because a broker failure on a real device is otherwise diagnosable only
    /// by reading Main Thread Checker stack traces, which is how the off-main bug above
    /// was eventually found. A static let makes the callback install exactly once; MSAL
    /// raises if it is set twice.
    private static let debugLoggingInstalled: Void = {
        MSALGlobalConfig.loggerConfig.logLevel = .verbose
        MSALGlobalConfig.loggerConfig.piiEnabled = false
        MSALGlobalConfig.loggerConfig.setLogCallback { _, message, containsPII in
            guard !containsPII, let message else { return }
            print("[MSAL] \(message)")
        }
    }()
    #endif

    // MARK: - helpers

    /// Browse/metadata scopes granted at sign-in (§4).
    /// The reveal scope (DeviceLocalCredential.Read.All) is requested later, on demand.
    ///
    /// NOTE: these mirror CredentialKit's `LapsCredentialScopes.signInBaseline`. They are
    /// duplicated rather than imported on purpose — AuthKitMSAL must not depend on
    /// CredentialKit, or the credential module would end up in MSAL's link graph and
    /// break the §3.1 isolation boundary. If you change one, change both.
    private static let baseScopes = [
        "DeviceManagementManagedDevices.Read.All",
        "Device.Read.All",
        "DeviceLocalCredential.ReadBasic.All"
    ]

    private static func account(from result: MSALResult) throws -> AdminAccount {
        let tid = result.tenantProfile.tenantId
            ?? (result.account.accountClaims?["tid"] as? String)
        guard let tenantId = tid else {
            throw AuthError.underlying("missing tenant id in token")
        }
        return AdminAccount(
            id: result.account.identifier ?? "",
            tenantId: tenantId,
            username: result.account.username ?? ""
        )
    }

    /// §3.3 cross-tenant guard: reject any token whose tid differs from the pinned account.
    private static func assertTenant(_ result: MSALResult, matches account: AdminAccount) throws {
        let tid = result.tenantProfile.tenantId
            ?? (result.account.accountClaims?["tid"] as? String)
        guard tid == account.tenantId else { throw AuthError.tenantMismatch }
    }

    /// Maps MSAL errors onto AuthError. Never includes secret material in the message.
    private static func map(_ error: Error?) -> AuthError {
        guard let error = error as NSError? else { return .underlying("unknown") }

        if error.domain == MSALErrorDomain {
            if error.code == MSALError.interactionRequired.rawValue {
                return .interactionRequired
            }
            if error.code == MSALError.userCanceled.rawValue {
                return .userCancelled
            }
            // Some tenants surface consent as a server error with a sub-error.
            // The sub-error key constant name varies across MSAL versions, so match
            // defensively over userInfo rather than referencing a specific symbol.
            let subErrorText = error.userInfo
                .filter { $0.key.lowercased().contains("suberror") }
                .compactMap { $0.value as? String }
                .joined(separator: " ")
                .lowercased()
            if subErrorText.contains("consent") {
                return .consentRequired
            }
            return .underlying("MSAL error \(error.code)")   // no secret material
        }
        return .underlying(error.localizedDescription)
    }
}

// MARK: - main-actor UIKit access

/// All UIKit touching happens here, on the main actor. The MSALAuthManager actor
/// reaches these with `await`, which is what keeps the concurrency checker happy.
///
/// Note that this is necessary but not sufficient: MSAL also dereferences the presenting
/// controller inside acquireToken. See the concurrency note at the top of the file.
@MainActor
private enum MainActorUI {

    static func webviewParameters() throws -> MSALWebviewParameters {
        MSALWebviewParameters(authPresentationViewController: try topViewController())
    }

    static func topViewController() throws -> UIViewController {
        let activeScene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }

        guard
            let scene = activeScene ?? UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first,
            let root = (scene.keyWindow ?? scene.windows.first)?.rootViewController
        else {
            throw AuthError.underlying("no presenting view controller")
        }

        var top = root
        while let presented = top.presentedViewController { top = presented }
        return top
    }
}

#endif // os(iOS)
