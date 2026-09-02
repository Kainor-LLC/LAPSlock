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

    /// The most recent MSAL failure, reduced to the allowlisted shape in `AuthFailureDetail`.
    ///
    /// Kept here rather than pushed into DiagnosticsKit because this module must not grow a
    /// dependency (the app layer records diagnostics from typed data; see Diagnostics.swift).
    /// The app reads this after a failed sign-in, and the support report reads it at export
    /// time, which covers silent token failures during browsing without wiring every call.
    private var lastFailure: AuthFailureDetail?
    public var lastAuthFailure: AuthFailureDetail? { lastFailure }

    /// The customer tenant an MSP has switched into. Nil means "the signed-in account's own
    /// tenant", which is the only state a single-organization administrator is ever in.
    ///
    /// Deliberately NOT persisted here. A switch is a decision for one session; reopening the
    /// app puts you back in your own tenant, which is the safe default for a tool that
    /// reveals administrator passwords. Somebody handed an unlocked phone should not find it
    /// already pointed at a customer's directory.
    private var activeTenant: TenantPin?

    /// The tenant this manager will request tokens for, and will refuse tokens from any
    /// other. §3.3.
    private var operatingPin: TenantPin? {
        activeTenant ?? pinnedAccount.flatMap { TenantPin(expected: $0.tenantId) }
    }

    /// The tenant currently being operated in, for the UI. Nil when signed out.
    public var operatingTenantId: String? { operatingPin?.expected }

    /// True when operating somewhere other than the account's home tenant.
    public var isOperatingInAnotherTenant: Bool {
        guard let active = activeTenant, let home = pinnedAccount?.tenantId else { return false }
        return active.expected != home.lowercased()
    }

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

        let result = try await recording(.signIn) { try await acquireInteractive(params) }
        let account = try Self.account(from: result)
        self.pinnedAccount = account
        // A new account starts in its own tenant. Carrying a previous session's customer
        // tenant across a sign-in would be both confusing and wrong.
        self.activeTenant = nil
        return account
    }

    /// Runs an MSAL call, and on failure reduces the raw error to `AuthFailureDetail`
    /// before mapping it to the public `AuthError`. The raw error never leaves this actor.
    private func recording<T>(_ step: AuthStep, _ body: () async throws -> T) async throws -> T {
        do {
            return try await body()
        } catch let failure as MSALFailure {
            lastFailure = Self.detail(from: failure.error, step: step)
            throw Self.map(failure.error)
        }
    }

    // MARK: - token acquisition

    public func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        guard let account = pinnedAccount else { throw AuthError.noAccount }
        guard let pin = operatingPin else { throw AuthError.noAccount }

        // Pin acquisition to the tenant we are deliberately operating in (§2.1, §3.3). For a
        // single-organization admin that is their own tenant; for an MSP who has switched, it
        // is the customer's. Either way the authority we ASK and the tenant we ACCEPT are the
        // same value, which is the property that makes the guard below meaningful.
        let tenantAuthority = try MSALAADAuthority(url: pin.authorityURL)

        // account(forIdentifier:) returns a NON-optional MSALAccount and throws if the
        // account isn't in the cache, so no conditional binding here.
        let msalAccount = try application.account(forIdentifier: account.id)

        let silent = MSALSilentTokenParameters(scopes: scopes, account: msalAccount)
        silent.authority = tenantAuthority

        do {
            let result = try await recording(.tokenSilent) { try await acquireSilent(silent) }
            try pin.validate(returnedTenantId: Self.tenantId(of: result))   // §3.3 guard
            return result.accessToken
        } catch let error as AuthError {
            switch error {
            case .interactionRequired, .consentRequired:
                guard allowInteractive else { throw AuthError.interactionRequired }
                return try await interactiveToken(scopes: scopes, account: account, pin: pin)
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
            if pinnedAccount?.id == account.id { pinnedAccount = nil; activeTenant = nil }
            return
        }
        let webParams = try await MainActorUI.webviewParameters()
        let params = MSALSignoutParameters(webviewParameters: webParams)

        try await performSignout(msalAccount, params)
        if pinnedAccount?.id == account.id { pinnedAccount = nil; activeTenant = nil }
    }

    // MARK: - interactive fallback (incremental consent, §4)

    private func interactiveToken(
        scopes: [String],
        account: AdminAccount,
        pin: TenantPin
    ) async throws -> String {
        let webParams = try await MainActorUI.webviewParameters()
        let params = MSALInteractiveTokenParameters(scopes: scopes, webviewParameters: webParams)
        params.authority = try MSALAADAuthority(url: pin.authorityURL)
        params.loginHint = account.username

        let result = try await recording(.tokenInteractive) { try await acquireInteractive(params) }
        try pin.validate(returnedTenantId: Self.tenantId(of: result))
        return result.accessToken
    }

    /// Acquires a token while satisfying a claims challenge. See the default implementation
    /// in AuthKit for why this exists.
    ///
    /// A challenge always forces INTERACTIVE acquisition. That is the point: the challenge
    /// exists because the cached token does not meet the bar, so a silent retry would return
    /// the same inadequate token and the caller would loop. `allowInteractive: false` with a
    /// challenge present is therefore a failure rather than a silent attempt.
    public func token(scopes: [String], claims: String?, allowInteractive: Bool) async throws -> String {
        guard let claims, !claims.isEmpty else {
            return try await token(scopes: scopes, allowInteractive: allowInteractive)
        }
        guard allowInteractive else { throw AuthError.interactionRequired }

        guard let account = pinnedAccount else { throw AuthError.noAccount }
        guard let pin = operatingPin else { throw AuthError.noAccount }
        // MSALClaimsRequest reports parse failure through the NSError out-parameter rather
        // than by returning nil, so the error has to be inspected explicitly. A guard on the
        // return value compiles to nothing useful here — the initializer is non-optional.
        var claimsError: NSError?
        let claimsRequest = MSALClaimsRequest(jsonString: claims, error: &claimsError)
        if let claimsError {
            // Not something to retry differently. ClaimsChallenge validates the shape before
            // it ever reaches here, so this means the two disagree, which is a bug rather
            // than a user-facing condition.
            throw AuthError.underlying("malformed claims request (\(claimsError.code))")
        }

        let webParams = try await MainActorUI.webviewParameters()
        let params = MSALInteractiveTokenParameters(scopes: scopes, webviewParameters: webParams)
        params.authority = try MSALAADAuthority(url: pin.authorityURL)
        params.loginHint = account.username
        params.claimsRequest = claimsRequest

        let result = try await recording(.tokenInteractive) { try await acquireInteractive(params) }
        try pin.validate(returnedTenantId: Self.tenantId(of: result))
        return result.accessToken
    }

    // MARK: - tenant switching (MSP tiers)

    /// Switches the tenant this manager operates in, or returns to the account's own tenant
    /// when `tenantId` is nil.
    ///
    /// The switch is VALIDATED before it is committed: a token is acquired for the target
    /// tenant first, and `activeTenant` only moves if that succeeds. Committing optimistically
    /// would leave the app pointed at a directory the user cannot read, turning one clear
    /// failure here into a confusing failure on every subsequent screen.
    ///
    /// Expect `consentRequired` for a customer tenant whose administrator has not yet
    /// approved LAPSlock. That is not a bug and not something an MSP can self-serve: app
    /// consent is per-tenant, so the customer's admin has to grant it. `AdminConsentLink`
    /// already builds the right URL for a given tenant.
    public func setActiveTenant(_ tenantId: String?) async throws {
        guard let account = pinnedAccount else { throw AuthError.noAccount }

        guard let tenantId else {
            activeTenant = nil
            return
        }

        guard let pin = TenantPin(expected: tenantId) else {
            throw AuthError.underlying("not a tenant id")
        }

        // Already there. Do not spend a token acquisition confirming it.
        if pin.expected == operatingPin?.expected { return }

        let previous = activeTenant
        activeTenant = pin
        do {
            _ = try await token(scopes: Self.baseScopes, allowInteractive: true)
        } catch {
            activeTenant = previous
            throw error
        }
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
                    else { cont.resume(throwing: MSALFailure(error: error)) }
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
                else { cont.resume(throwing: MSALFailure(error: error)) }
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
            username: result.account.username ?? "",
            // The oid claim, which is the DIRECTORY object id. Deliberately read from the
            // claims rather than split out of `identifier`: the identifier's `{oid}.{utid}`
            // shape is an MSAL implementation detail, and anything that needs a principal id
            // should not depend on it holding.
            objectId: result.account.accountClaims?["oid"] as? String
        )
    }

    /// §3.3 cross-tenant guard: reject any token whose tid differs from the pinned account.
    /// The tenant a token actually came back for. The comparison against what we asked for
    /// lives in `TenantPin.validate`, where it is unit tested — MSALResult cannot be
    /// constructed on macOS, so a comparison written here could not be.
    private static func tenantId(of result: MSALResult) -> String? {
        result.tenantProfile.tenantId ?? (result.account.accountClaims?["tid"] as? String)
    }

    /// Reduces an MSAL error to the allowlisted support-report shape. Reads only fixed
    /// userInfo keys. The description is consulted for an `AADSTS` code by regex and then
    /// discarded — it can contain the failing URL, and a broker redirect URL can contain an
    /// authorization code, which is why no field here is a description.
    private static func detail(from error: Error?, step: AuthStep) -> AuthFailureDetail {
        guard let error = error as NSError?, error.domain == MSALErrorDomain else {
            return AuthFailureDetail(step: step)
        }
        let info = error.userInfo
        return AuthFailureDetail(
            step: step,
            msalErrorCode: error.code,
            aadErrorCode: AuthFailureDetail.extractAADCode(from: info[MSALErrorDescriptionKey] as? String),
            oauthError: info[MSALOAuthErrorKey] as? String,
            correlationId: info[MSALCorrelationIDKey] as? String,
            httpStatus: (info[MSALHTTPResponseCodeKey] as? NSNumber)?.intValue,
            // MSAL sets the broker version key only when the Authenticator broker handled
            // the request. Its presence is the broker-path flag; its value is not kept.
            brokerInvolved: info[MSALBrokerVersionKey] != nil
        )
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

/// Carries the raw MSAL error from a completion closure back onto the actor, where it is
/// reduced and mapped. Private so a raw error cannot escape this file.
private struct MSALFailure: Error {
    let error: Error?
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
