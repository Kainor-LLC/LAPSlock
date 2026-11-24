// iOS and, since phase 4 step C, macOS for the native Mac app. The only difference is how
// the presenting view controller is found (MainActorUI at the bottom). Since this compiles
// on macOS, `swift test` on the Mac now compiles this file for real, which closes the gap
// CLAUDE.md warns about; building the iOS app is still required, for the UIKit half.
// The guard must sit ABOVE the imports.
#if os(iOS) || os(macOS)

import Foundation
#if os(iOS)
import UIKit
#else
import AppKit
#endif
import MSAL
import AuthKit

// Build Spec §4, §2.1, §3.3, §9. The only file that imports MSAL.
//
// Responsibilities:
//   * interactive account-selection sign-in on /common (§2.1)
//   * per-account tenant-specific authority for silent acquisition (§2.1)
//   * tenant pinning: the token's tid must match the account's tenant (§3.3)
//   * ThisDeviceOnly, non-synced keychain for the MSAL token cache (§4)
//   * one MSAL client per app registration (AuthKit's AppRegistration), chosen from the
//     scopes a request names, so a read never travels through a registration that can
//     write, and every client is the same person in the same tenant
//
// Concurrency: MSAL dereferences the presenting view controller inside acquireToken, on
// the calling thread. This actor runs on the cooperative pool, so calling acquireToken
// from actor context touches UIKit off the main thread; with Microsoft Authenticator
// installed the broker return path then fails silently. The simulator never showed it,
// because without a broker the whole flow stays in-process. Every MSAL call that can
// present UI (acquireToken, signout) is therefore dispatched to the main thread first.
// Silent acquisition presents nothing and stays here. Any new MSAL entry point that can
// show a screen must be dispatched the same way.

/// What differs between the apps that sign in: where Microsoft returns to. The client IDs
/// are not here; they come from `AppRegistration`, one per registration.
public struct AuthConfiguration: Sendable {
    /// `msauth.{bundle id}://auth`, which every registration this app signs into must list.
    public let redirectUri: String
    /// nil → use /common for account selection, then pin to the account's tenant.
    public let authorityTenant: String?

    public init(redirectUri: String, authorityTenant: String? = nil) {
        self.redirectUri = redirectUri
        self.authorityTenant = authorityTenant
    }

    /// The iPhone and iPad app.
    ///
    /// The bundle identifier of the app target MUST be com.kainor.lapslock, because the
    /// redirect URI below is derived from it. A mismatch produces an MSAL redirect error.
    ///
    /// The registrations themselves are multi-tenant public clients with no secret and
    /// delegated permissions only. Their client IDs are load-bearing: every shipped build
    /// references them, and every customer tenant's consent creates a service principal
    /// pointing at them. Changing or deleting one breaks every install.
    public static let vendorDefault = AuthConfiguration(
        redirectUri: "msauth.com.kainor.lapslock://auth",
        authorityTenant: nil    // multi-tenant: /common for selection, then pin per account
    )
}

public actor MSALAuthManager: AuthManaging {
    private let config: AuthConfiguration
    /// One MSAL client per registration, built the first time it is needed. They share one
    /// keychain cache and nothing else: an account one client signed in is invisible to
    /// the others (verified on a phone), so each registration's first token is interactive.
    private var applications: [AppRegistration: MSALPublicClientApplication] = [:]
    private var pinnedAccount: AdminAccount?

    /// True when this install signed in before the split and the person's own organization
    /// has not moved to the read registration: the session itself lives on the original
    /// registration, and every organization's reads go through it, as they always did,
    /// until `moveReadsToReadRegistration()` succeeds.
    private var sessionOnOriginal = false

    /// After the person's own organization has moved: the customers that have not, which
    /// keep reading through the original registration until each approves the read one.
    /// The rules are in `ReadRoutes.swift`. Read from the store every time, never from a
    /// copy, because the background check builds its own manager.
    private let readRoutes: ReadRouteStore
    /// Customers the person was asked about through the read registration this session
    /// with no token coming back, and customers a silent request has already tried to move.
    private var askedRead: Set<String> = []
    private var probedRead: Set<String> = []

    /// Per tenant, the kinds of write that go through the combined registration because
    /// the organization approved that one and not the separate one. Decided by the app
    /// from what the organization approved; empty means every write uses its own.
    private var combinedWrites: [String: Set<AppRegistration>] = [:]

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

    public init(config: AuthConfiguration, readRoutes: ReadRouteStore = .standard) throws {
        self.config = config
        self.readRoutes = readRoutes

        #if DEBUG
        _ = Self.debugLoggingInstalled
        #endif

        // Built now so a bad configuration fails here, at launch, and not at first sign-in.
        self.applications = [.read: try Self.makeApplication(.read, config: config)]
    }

    private static func makeApplication(_ registration: AppRegistration, config: AuthConfiguration) throws -> MSALPublicClientApplication {
        let authorityURL = URL(string: "https://login.microsoftonline.com/\(config.authorityTenant ?? "common")")!
        let authority = try MSALAADAuthority(url: authorityURL)
        let pcaConfig = MSALPublicClientApplicationConfig(
            clientId: registration.clientId,
            redirectUri: config.redirectUri,
            authority: authority
        )
        // Keep tokens on this device only; never sync to iCloud Keychain (§4).
        pcaConfig.cacheConfig.keychainSharingGroup = Bundle.main.bundleIdentifier ?? "com.kainor.lapslock"
        return try MSALPublicClientApplication(configuration: pcaConfig)
    }

    private func application(for registration: AppRegistration) throws -> MSALPublicClientApplication {
        if let existing = applications[registration] { return existing }
        let made = try Self.makeApplication(registration, config: config)
        applications[registration] = made
        return made
    }

    /// The registration the session lives on: the read one, or the original one for an
    /// install from before the split whose own organization has not moved. Sign-out talks
    /// to Microsoft through this one.
    private var primaryRegistration: AppRegistration { sessionOnOriginal ? .actions : .read }

    /// Whether `tenant`'s reads go through the original registration: every organization's
    /// while the session lives there, and afterwards a customer that has not moved.
    private func readsThroughOriginal(in tenant: String) -> Bool {
        sessionOnOriginal || waits(tenant)
    }

    /// A customer recorded as not having moved, for the person signed in.
    private func waits(_ tenant: String) -> Bool {
        guard !sessionOnOriginal, let home = pinnedAccount?.tenantId else { return false }
        return readRoutes.waits(tenant, home: home)
    }

    // MARK: - which registration

    /// How requests reach the registrations in the tenant being operated in.
    public var registrationRoute: RegistrationRoute {
        let tenant = operatingPin?.expected ?? ""
        return RegistrationRoute(combined: combinedWrites[tenant] ?? [],
                                 readsThroughOriginal: readsThroughOriginal(in: tenant))
    }

    /// Records which kinds of write `tenantId` sends through the combined registration.
    /// An empty set means each uses its own. The app decides this from what the
    /// organization approved; nothing here guesses.
    public func setCombinedWrites(_ registrations: Set<AppRegistration>, inTenant tenantId: String) {
        combinedWrites[tenantId.lowercased()] = registrations.intersection(AppRegistration.separateWrites)
    }

    /// The registration and client a request for `scopes` in `tenant` goes through.
    private func client(for scopes: [String], tenant: String) throws -> MSALPublicClientApplication {
        let home: AppRegistration
        do {
            home = try ScopeRouter.registration(for: scopes)
        } catch ScopeRouter.RoutingError.unknownScope(let scope) {
            throw AuthError.underlying("no app registration holds " + scope)
        } catch ScopeRouter.RoutingError.mixedRegistrations {
            throw AuthError.underlying("the scopes belong to more than one app registration")
        } catch {
            throw AuthError.underlying("no scopes to ask for")
        }
        let route = RegistrationRoute(combined: combinedWrites[tenant.lowercased()] ?? [],
                                      readsThroughOriginal: readsThroughOriginal(in: tenant))
        return try application(for: route.client(for: home))
    }

    public var currentAccount: AdminAccount? {
        get async { pinnedAccount }
    }

    /// The user's object id in `tenantId`, from MSAL's profile of the account in that tenant,
    /// which it records from that tenant's ID token. A guest in a customer tenant is a
    /// different object there than at home. Falls back to the home id when MSAL has no
    /// profile for the tenant, which is what was always sent before.
    public func objectId(inTenant tenantId: String) async -> String? {
        guard let account = pinnedAccount else { return nil }
        let wanted = tenantId.lowercased()
        guard wanted != account.tenantId.lowercased(),
              // The registration that organization reads through is the one that has its profile.
              let app = try? application(for: readsThroughOriginal(in: wanted) ? .actions : .read),
              let msalAccount = try? app.account(forIdentifier: account.id),
              let profile = msalAccount.tenantProfiles?.first(where: { $0.tenantId?.lowercased() == wanted })
        else { return account.objectId }
        return (profile.claims?["oid"] as? String) ?? profile.identifier ?? account.objectId
    }

    // MARK: - sign in

    @discardableResult
    public func signIn() async throws -> AdminAccount {
        // Always the read registration. A person who signs in today has no session on the
        // original one to fall back to, and should not acquire one.
        let app = try application(for: .read)
        let webParams = try await MainActorUI.webviewParameters()
        let params = MSALInteractiveTokenParameters(scopes: Self.baseScopes, webviewParameters: webParams)
        params.promptType = .selectAccount

        let result = try await recording(.signIn) { try await acquireInteractive(app, params) }
        let account = try Self.account(from: result)
        self.pinnedAccount = account
        self.sessionOnOriginal = false
        // The customers still waiting to move stay with the person who began the list, so
        // a sign-in the session needed (a sign-in frequency policy, a changed password, a
        // revoke) does not undo the move. Anyone else starts with none. Until the second
        // review (R2-1, 2026-11-24) every sign-in cleared it here.
        readRoutes.keep(onlyFor: account.tenantId, person: account.id)
        askedRead = []
        probedRead = []
        // A new account starts in its own tenant. Carrying a previous session's customer
        // tenant across a sign-in would be both confusing and wrong.
        self.activeTenant = nil
        // Nor does anyone else's session on another registration survive it.
        removeAccounts(except: account.id, keepingPrimary: false)
        return account
    }

    /// Removes cached accounts from the registrations: everyone but `identifier`, or with
    /// `identifier` nil, everyone. The primary registration is skipped when the caller
    /// signs it out itself, with Microsoft's own sign-out.
    private func removeAccounts(except identifier: String?, keepingPrimary: Bool) {
        for registration in AppRegistration.allCases {
            if keepingPrimary, registration == primaryRegistration { continue }
            guard let app = try? application(for: registration),
                  let accounts = try? app.allAccounts() else { continue }
            for other in accounts where identifier == nil || other.identifier != identifier {
                try? app.remove(other)
            }
        }
    }

    /// Restores a previous session without prompting, or returns nil.
    ///
    /// **Why this exists.** MSAL already holds the account and a refresh token in its
    /// keychain-backed cache, and nothing was asking for them, so every launch showed the
    /// sign-in screen and made the user tap a button that then succeeded silently. That is
    /// friction with no security value: the tokens were already on the device.
    ///
    /// **Entra still decides.** This only ever acquires silently. If the refresh token has
    /// expired, been revoked, or Conditional Access now demands reauthentication, the silent
    /// attempt fails and nil comes back, and the sign-in screen appears, which is exactly
    /// right. The app deliberately does NOT impose a session lifetime of its own: that is the
    /// tenant's policy to set, and second-guessing it would contradict the whole delegated
    /// model.
    ///
    /// **A token is acquired to prove it, not merely assumed.** Restoring on the presence of
    /// a cached account alone would show the device list and then fail on the first Graph
    /// call, which is worse than showing the sign-in screen.
    public func restoreSession() async -> AdminAccount? {
        // `SessionRestore` holds the decision and its reasons. In short: an install from
        // before the split has its session on the original registration and none on the
        // read one, and carries on reading through the original until the person signs
        // into the read registration once (`moveReadsToReadRegistration`). Any other
        // install restores through the read registration or not at all, and a cache that
        // holds more than one person is emptied instead of guessed at.
        switch SessionRestore.plan(readAccounts: cachedAccounts(.read), originalAccounts: cachedAccounts(.actions)) {
        case .through(let registration):
            guard let account = await restore(through: registration) else { return nil }
            // Nobody else's session stays cached beside the one restored.
            removeAccounts(except: account.id, keepingPrimary: false)
            return account
        case .clearThenSignIn:
            removeAccounts(except: nil, keepingPrimary: false)
            return nil
        case .signIn:
            return nil
        }
    }

    private func cachedAccounts(_ registration: AppRegistration) -> Int {
        guard let app = try? application(for: registration), let accounts = try? app.allAccounts() else { return 0 }
        return accounts.count
    }

    private func restore(through registration: AppRegistration) async -> AdminAccount? {
        guard let app = try? application(for: registration),
              let msalAccount = (try? app.allAccounts())?.first,
              let account = Self.account(from: msalAccount)
        else { return nil }

        pinnedAccount = account
        sessionOnOriginal = (registration == .actions)
        readRoutes.keep(onlyFor: account.tenantId, person: account.id)
        // A restored session starts in the account's own tenant. An MSP's customer selection
        // is deliberately not carried across a launch, operating in someone else's tenant
        // should be a decision made now, not one inherited from last week.
        activeTenant = nil

        // Microsoft is asked first whether the session still stands, with the cached token
        // skipped. A session it has ended must not come back on a token cached before the
        // end, which lasts up to an hour and a half. With no answer (no network) the cached
        // token decides, as before. CAE-PLAN.md, decisions 2 and 3.
        if await checkSession().endsTheSession {
            dropSession()
            return nil
        }

        do {
            _ = try await token(scopes: Self.baseScopes, allowInteractive: false)
            return account
        } catch {
            pinnedAccount = nil
            activeTenant = nil
            sessionOnOriginal = false
            return nil
        }
    }

    /// What is still waiting to move to the read registration, for the organization
    /// being worked in: everything, this customer, or nothing.
    public var pendingReadUpdate: ReadUpdate? {
        if sessionOnOriginal { return .ownOrganization }
        if let tenant = operatingPin?.expected, waits(tenant) { return .thisCustomer }
        return nil
    }

    /// The customers still reading through the original registration, for the screens
    /// that list organizations. Empty until the person's own organization has moved.
    public var customersWaitingToMove: Set<String> {
        guard !sessionOnOriginal, let home = pinnedAccount?.tenantId else { return [] }
        return readRoutes.waiting(home: home)
    }

    /// Signs the same person into the read registration and moves reads onto it, for
    /// whatever `pendingReadUpdate` says is waiting. One interactive sign-in. Throws
    /// `consentRequired` or `userCancelled` when the organization has not approved the
    /// read registration, and reads then stay where they were, so nothing stops working.
    ///
    /// The person's own organization moves first, whichever organization is on screen:
    /// the session itself moves with it, and a customer cannot move before the session
    /// has. `customers` are the organizations saved on the device at that moment. They are
    /// recorded as waiting, so each keeps reading through the original registration until
    /// it has approved the read one. That is the only time the list is added to.
    ///
    /// Afterwards, in a waiting customer, this moves that customer alone.
    public func moveReadsToReadRegistration(customers: [String] = []) async throws {
        guard let account = pinnedAccount else { throw AuthError.noAccount }
        guard let home = TenantPin(expected: account.tenantId) else { throw AuthError.tenantMismatch }
        let read = try application(for: .read)

        if sessionOnOriginal {
            _ = try await interactiveToken(read, scopes: Self.baseScopes, account: account, pin: home, claims: nil)
            var waiting = Set(customers.compactMap { TenantPin(expected: $0)?.expected })
            // The customer on screen was reading through the original a moment ago,
            // saved or not, and what is on screen must not stop.
            if let active = activeTenant { waiting.insert(active.expected) }
            sessionOnOriginal = false
            readRoutes.begin(home: home.expected, person: account.id, waiting: waiting)
            // It may have approved the read registration already.
            if let active = activeTenant, waits(active.expected),
               await probe(.read, pin: active, account: account).probe == .token {
                markMoved(active.expected)
            }
            return
        }

        guard let pin = operatingPin, waits(pin.expected) else { return }
        _ = try await interactiveToken(read, scopes: Self.baseScopes, account: account, pin: pin, claims: nil)
        markMoved(pin.expected)
    }

    /// A customer removed from the device leaves the list with its other data. If it is
    /// added again it reads through the read registration, like any customer added now.
    public func forgetReadRoute(for tenantId: String) {
        guard let home = pinnedAccount?.tenantId else { return }
        readRoutes.remove(tenantId, home: home)
    }

    private func markMoved(_ tenant: String) {
        guard let home = pinnedAccount?.tenantId else { return }
        readRoutes.remove(tenant, home: home)
        askedRead.remove(tenant)
    }

    private func forgetReadRoutes() {
        readRoutes.clear()
        askedRead = []
        probedRead = []
    }

    private struct ProbeAnswer {
        let probe: RouteProbe
        var error: AuthError?
        var detail: AuthFailureDetail?
    }

    /// One silent request for the sign-in scopes through `registration`, in `pin`'s
    /// organization, reduced to what it means for the route. Never a prompt.
    private func probe(_ registration: AppRegistration, pin: TenantPin, account: AdminAccount) async -> ProbeAnswer {
        guard let app = try? application(for: registration) else {
            return ProbeAnswer(probe: .failed, error: .underlying("no client for the registration"))
        }
        guard let msalAccount = try? app.account(forIdentifier: account.id) else {
            // No session on this registration. For the original that settles it: a person
            // with no session there does not acquire one to read through. For the read
            // registration it means asking.
            return ProbeAnswer(probe: registration == .actions ? .notApproved : .needsPrompt, error: .interactionRequired)
        }
        do {
            let silent = MSALSilentTokenParameters(scopes: Self.baseScopes, account: msalAccount)
            silent.authority = try MSALAADAuthority(url: pin.authorityURL)
            let result = try await acquireSilent(app, silent)
            try pin.validate(returnedTenantId: Self.tenantId(of: result))   // §3.3 guard
            return ProbeAnswer(probe: .token)
        } catch let failure as MSALFailure {
            return ProbeAnswer(probe: Self.routeProbe(from: failure.error), error: Self.map(failure.error),
                               detail: Self.detail(from: failure.error, step: .tokenSilent))
        } catch let error as AuthError {
            return ProbeAnswer(probe: .failed, error: error)
        } catch {
            return ProbeAnswer(probe: .failed, error: .underlying("the request did not finish"))
        }
    }

    /// For a customer that has not moved, before it is entered: finds out whether it can
    /// move now, and otherwise proves the original registration still answers there.
    /// The read registration first, always. Throws with nothing changed.
    private func settleReadRoute(for pin: TenantPin, account: AdminAccount) async throws {
        let read = await probe(.read, pin: pin, account: account)
        if read.probe == .token { return markMoved(pin.expected) }
        let original = await probe(.actions, pin: pin, account: account)

        switch ReadRoutes.settle(read: read.probe, original: original.probe, askedReadBefore: askedRead.contains(pin.expected)) {
        case .read:
            markMoved(pin.expected)
        case .original:
            return
        case .ask(let registration):
            if registration == .read { askedRead.insert(pin.expected) }
            _ = try await interactiveToken(try application(for: registration), scopes: Self.baseScopes,
                                           account: account, pin: pin, claims: nil)
            if registration == .read { markMoved(pin.expected) }
        case .notApproved:
            lastFailure = read.detail
            throw AuthError.consentRequired
        case .fail:
            lastFailure = read.detail ?? original.detail
            throw read.error ?? original.error ?? AuthError.underlying("no answer from Microsoft")
        }
    }

    /// Builds an `AdminAccount` from a cached MSAL account.
    ///
    /// Separate from the `MSALResult` version because a restore has no result to read, only
    /// what the cache kept. Returns nil rather than throwing: a cache entry too incomplete to
    /// use is a reason to show the sign-in screen, not an error to surface.
    private static func account(from msalAccount: MSALAccount) -> AdminAccount? {
        let claims = msalAccount.accountClaims
        guard let tenantId = (claims?["tid"] as? String) ?? msalAccount.homeAccountId?.tenantId,
              let identifier = msalAccount.identifier, !identifier.isEmpty
        else { return nil }
        return AdminAccount(
            id: identifier,
            tenantId: tenantId,
            username: msalAccount.username ?? "",
            objectId: claims?["oid"] as? String)
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
        let app = try client(for: scopes, tenant: pin.expected)

        // A registration this person has not signed into on this device has nothing
        // cached, so there is nothing to try silently: its first token is interactive.
        guard let msalAccount = try? app.account(forIdentifier: account.id) else {
            guard allowInteractive else { throw AuthError.interactionRequired }
            return try await interactiveToken(app, scopes: scopes, account: account, pin: pin, claims: nil)
        }

        // Pin acquisition to the tenant we are deliberately operating in (§2.1, §3.3). For a
        // single-organization admin that is their own tenant; for an MSP who has switched, it
        // is the customer's. Either way the authority we ASK and the tenant we ACCEPT are the
        // same value, which is the property that makes the guard below meaningful.
        let silent = MSALSilentTokenParameters(scopes: scopes, account: msalAccount)
        silent.authority = try MSALAADAuthority(url: pin.authorityURL)

        do {
            let result = try await recording(.tokenSilent) { try await acquireSilent(app, silent) }
            try pin.validate(returnedTenantId: Self.tenantId(of: result))   // §3.3 guard
            return result.accessToken
        } catch let error as AuthError {
            switch error {
            case .interactionRequired, .consentRequired:
                guard allowInteractive else { throw AuthError.interactionRequired }
                return try await interactiveToken(app, scopes: scopes, account: account, pin: pin, claims: nil)
            default:
                throw error
            }
        }
    }

    /// Silent acquisition for one named tenant, leaving `activeTenant` exactly where it
    /// was. The same §3.3 guard applies: the tenant asked for is the tenant accepted. A
    /// token that needs interaction is a failure here, never a prompt.
    public func silentToken(scopes: [String], tenantId: String) async throws -> String {
        guard let account = pinnedAccount else { throw AuthError.noAccount }
        guard let pin = TenantPin(expected: tenantId) else { throw AuthError.tenantMismatch }
        // A customer that has not moved is tried on the read registration once a launch,
        // so it moves as soon as it has approved it, without waiting to be switched into.
        if waits(pin.expected), probedRead.insert(pin.expected).inserted,
           await probe(.read, pin: pin, account: account).probe == .token {
            markMoved(pin.expected)
        }
        let app = try client(for: scopes, tenant: pin.expected)
        guard let msalAccount = try? app.account(forIdentifier: account.id) else { throw AuthError.interactionRequired }
        let silent = MSALSilentTokenParameters(scopes: scopes, account: msalAccount)
        silent.authority = try MSALAADAuthority(url: pin.authorityURL)
        let result = try await recording(.tokenSilent) { try await acquireSilent(app, silent) }
        try pin.validate(returnedTenantId: Self.tenantId(of: result))
        return result.accessToken
    }

    // MARK: - the session check (CAE-PLAN.md, decisions 2 and 3)

    /// What the last session check said, at a restore or in the app's own check. The app
    /// reads it after a restore comes back empty, to say why.
    public private(set) var lastSessionStanding: SessionStanding?

    /// Asks Microsoft whether the session still stands: one silent request for the sign-in
    /// permissions in the person's own organization, through the registration the session
    /// lives on, with the cached token skipped, so Entra has to accept the refresh token
    /// now. Never a prompt, and the token that comes back is not used. What the answer
    /// means is `SessionStanding.from`, in AuthKit, where it is tested.
    public func checkSession() async -> SessionStanding {
        guard let account = pinnedAccount,
              let home = TenantPin(expected: account.tenantId),
              let app = try? application(for: primaryRegistration),
              let msalAccount = try? app.account(forIdentifier: account.id)
        else { return .unknown }
        let silent = MSALSilentTokenParameters(scopes: Self.baseScopes, account: msalAccount)
        silent.forceRefresh = true
        let standing: SessionStanding
        do {
            silent.authority = try MSALAADAuthority(url: home.authorityURL)
            let result = try await acquireSilent(app, silent)
            try home.validate(returnedTenantId: Self.tenantId(of: result))
            standing = .current
        } catch let failure as MSALFailure {
            standing = SessionStanding.from(aadCode: Self.detail(from: failure.error, step: .tokenSilent).aadErrorCode)
        } catch {
            standing = .unknown
        }
        lastSessionStanding = standing
        return standing
    }

    /// Stops acting as the person and removes nothing, which is what a sign-in that has
    /// expired leaves behind: the next sign-in by the same person picks up where they
    /// were. For Microsoft's own end of a session. Sign-out is `signOut`, and an erase is
    /// `forgetEveryone`.
    public func dropSession() {
        pinnedAccount = nil
        activeTenant = nil
        sessionOnOriginal = false
        combinedWrites = [:]
        askedRead = []
        probedRead = []
    }

    public func signOut(account: AdminAccount) async throws {
        // Whatever happens below, this object stops acting as the person, and no
        // registration keeps anybody cached: not the person signing out, and not anyone
        // 1.0 left cached beside them, whom the next launch would otherwise restore. Both
        // run even when Microsoft's sign-out throws, so a failure there cannot leave a
        // live session behind a sign-in screen. (Deferred blocks run last declared first:
        // the caches are emptied, then the session is cleared.)
        defer { if pinnedAccount?.id == account.id { clearSession() } }
        defer { removeAccounts(except: nil, keepingPrimary: false) }

        // Every other registration first. Local removal only: the primary registration's
        // sign-out below is the one that talks to Microsoft.
        removeAccounts(except: nil, keepingPrimary: true)

        // Nothing cached for this account is indistinguishable from "already signed out".
        let app = try application(for: primaryRegistration)
        guard let msalAccount = try? app.account(forIdentifier: account.id) else { return }
        let webParams = try await MainActorUI.webviewParameters()
        let params = MSALSignoutParameters(webviewParameters: webParams)
        try await performSignout(app, msalAccount, params)
    }

    /// Removes every cached sign-in on every registration and stops acting as anyone,
    /// without Microsoft's sign-out page. For an organization's order to remove its data
    /// from the app, which must not wait on a person or on a network.
    public func forgetEveryone() {
        removeAccounts(except: nil, keepingPrimary: false)
        emptyCacheGroup()
        clearSession()
    }

    /// Deletes everything left in the Keychain group the sign-in cache has to itself.
    ///
    /// MSAL's own removal takes the tokens and leaves its record of who was signed in: a
    /// name and a sign-in address, no credential. Seen on a phone after an organization's
    /// wipe, 2026-11-24. Nothing of the person is to stay, so the group is emptied. Nothing
    /// else lives there: the app's other items and Microsoft's Intune App SDK's are in
    /// other groups.
    private func emptyCacheGroup() {
        let own = "." + (Bundle.main.bundleIdentifier ?? "com.kainor.lapslock")
        let everything: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true
        ]
        var found: CFTypeRef?
        guard SecItemCopyMatching(everything as CFDictionary, &found) == errSecSuccess,
              let items = found as? [[String: Any]] else { return }
        // The group's full name carries the team's prefix, which is read off an item in it.
        let groups = Set(items.compactMap { $0[kSecAttrAccessGroup as String] as? String }.filter { $0.hasSuffix(own) })
        for group in groups {
            SecItemDelete([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccessGroup as String: group
            ] as CFDictionary)
        }
    }

    private func clearSession() {
        pinnedAccount = nil
        activeTenant = nil
        sessionOnOriginal = false
        forgetReadRoutes()
        combinedWrites = [:]
    }

    // MARK: - interactive fallback (incremental consent, §4)

    /// One interactive request through `app`, for the person already signed in.
    ///
    /// **The account that comes back must be that person.** Microsoft's screen lets
    /// somebody else sign in instead, which is what happens when an administrator approves
    /// a permission on a technician's phone. The approval, if it was for the organization,
    /// is recorded at Microsoft and stands. The administrator's session is removed from
    /// this device and the request fails with `differentAccount`: reads and writes are
    /// always sent as the one person who signed in, in the one tenant they chose.
    private func interactiveToken(
        _ app: MSALPublicClientApplication,
        scopes: [String],
        account: AdminAccount,
        pin: TenantPin,
        claims: MSALClaimsRequest?
    ) async throws -> String {
        let webParams = try await MainActorUI.webviewParameters()
        let params = MSALInteractiveTokenParameters(scopes: scopes, webviewParameters: webParams)
        params.authority = try MSALAADAuthority(url: pin.authorityURL)
        params.loginHint = account.username
        if let claims { params.claimsRequest = claims }

        let result = try await recording(.tokenInteractive) { try await acquireInteractive(app, params) }
        guard result.account.identifier == account.id else {
            // The other person's session must not stay cached: a later launch could
            // restore it. If the one removal fails, the sweep still takes it.
            try? app.remove(result.account)
            removeAccounts(except: account.id, keepingPrimary: false)
            throw AuthError.differentAccount
        }
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
        // return value compiles to nothing useful here, the initializer is non-optional.
        var claimsError: NSError?
        let claimsRequest = MSALClaimsRequest(jsonString: claims, error: &claimsError)
        if let claimsError {
            // Not something to retry differently. ClaimsChallenge validates the shape before
            // it ever reaches here, so this means the two disagree, which is a bug rather
            // than a user-facing condition.
            throw AuthError.underlying("malformed claims request (\(claimsError.code))")
        }

        let app = try client(for: scopes, tenant: pin.expected)
        return try await interactiveToken(app, scopes: scopes, account: account, pin: pin, claims: claimsRequest)
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

        // A customer that has not moved to the read registration is settled first, with
        // both registrations named outright, and committed only once one of them answers.
        if waits(pin.expected) {
            try await settleReadRoute(for: pin, account: account)
            // Settling waits on Microsoft, and the person can have signed out meanwhile.
            guard pinnedAccount?.id == account.id else { throw AuthError.noAccount }
            activeTenant = pin
            return
        }

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
    private func acquireInteractive(_ app: MSALPublicClientApplication, _ params: MSALInteractiveTokenParameters) async throws -> MSALResult {
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
        _ app: MSALPublicClientApplication,
        _ account: MSALAccount,
        _ params: MSALSignoutParameters
    ) async throws {
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            DispatchQueue.main.async {
                app.signout(with: account, signoutParameters: params) { _, error in
                    if let error { cont.resume(throwing: Self.map(error)) } else { cont.resume(returning: ()) }
                }
            }
        }
    }

    /// Silent acquisition presents nothing, so it does not need the main thread.
    ///
    /// Cancellable: a cancelled caller gets `CancellationError` at once instead of waiting
    /// for MSAL's own network timeout, so the cross-tenant run's budget and the background
    /// check's deadline hold while a token refresh hangs on a weak connection. MSAL's
    /// answer, if it comes later, is dropped; the token it fetched stays in MSAL's cache.
    private func acquireSilent(_ app: MSALPublicClientApplication, _ params: MSALSilentTokenParameters) async throws -> MSALResult {
        let once = SilentResume()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { cont in
                guard once.begin(cont) else { return }
                app.acquireTokenSilent(with: params) { result, error in
                    if let result { once.finish(.success(result)) }
                    else { once.finish(.failure(MSALFailure(error: error))) }
                }
            }
        } onCancel: {
            once.cancel()
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
    /// duplicated rather than imported on purpose, AuthKitMSAL must not depend on
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
    /// lives in `TenantPin.validate`, where it is unit tested, MSALResult cannot be
    /// constructed on macOS, so a comparison written here could not be.
    private static func tenantId(of result: MSALResult) -> String? {
        result.tenantProfile.tenantId ?? (result.account.accountClaims?["tid"] as? String)
    }

    /// Reduces an MSAL error to the allowlisted support-report shape. Reads only fixed
    /// userInfo keys. The description is consulted for an `AADSTS` code by regex and then
    /// discarded, it can contain the failing URL, and a broker redirect URL can contain an
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

    /// What a failed silent request says about a registration in one organization. Reads
    /// the same fixed keys `detail(from:)` does, and keeps nothing.
    private static func routeProbe(from error: Error?) -> RouteProbe {
        guard let error = error as NSError?, error.domain == MSALErrorDomain else { return .failed }
        let subError = error.userInfo
            .filter { $0.key.lowercased().contains("suberror") }
            .compactMap { $0.value as? String }
            .joined(separator: " ")
        return RouteProbe.failure(
            aadCode: AuthFailureDetail.extractAADCode(from: error.userInfo[MSALErrorDescriptionKey] as? String),
            subError: subError,
            interactionRequired: error.code == MSALError.interactionRequired.rawValue)
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

// MARK: - main-actor UI access

/// All UIKit and AppKit touching happens here, on the main actor. The MSALAuthManager actor
/// reaches these with `await`, which is what keeps the concurrency checker happy.
///
/// Note that this is necessary but not sufficient: MSAL also dereferences the presenting
/// controller inside acquireToken. See the concurrency note at the top of the file.
@MainActor
private enum MainActorUI {

    static func webviewParameters() throws -> MSALWebviewParameters {
        MSALWebviewParameters(authPresentationViewController: try topViewController())
    }

    #if os(macOS)
    /// The key window's controller, or any visible window's. A menu bar app may have no
    /// window open; then a small transparent one hosts the sign-in sheet and is closed with
    /// the app. MSAL presents ASWebAuthenticationSession on macOS, which needs an anchor.
    static func topViewController() throws -> NSViewController {
        if let controller = NSApplication.shared.keyWindow?.contentViewController
            ?? NSApplication.shared.windows.first(where: { $0.isVisible })?.contentViewController {
            return controller
        }
        let controller = NSViewController()
        controller.view = NSView(frame: NSRect(x: 0, y: 0, width: 1, height: 1))
        let window = NSWindow(contentViewController: controller)
        window.styleMask = [.borderless]
        window.isReleasedWhenClosed = false
        window.setFrame(NSRect(x: 0, y: 0, width: 1, height: 1), display: false)
        window.orderFront(nil)
        anchors.append(window)
        return controller
    }

    private static var anchors: [NSWindow] = []
    #else

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
    #endif
}

#endif // os(iOS) || os(macOS)

#if os(iOS) || os(macOS)
/// Resumes a silent token request exactly once, whichever comes first: MSAL's answer or the
/// caller's cancellation.
final class SilentResume: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<MSALResult, Error>?
    private var cancelled = false

    /// Holds the continuation, unless the caller was cancelled before MSAL was asked: then
    /// it is resumed with the cancellation here, and false says not to ask MSAL at all.
    func begin(_ continuation: CheckedContinuation<MSALResult, Error>) -> Bool {
        lock.lock()
        if cancelled {
            lock.unlock()
            continuation.resume(throwing: CancellationError())
            return false
        }
        self.continuation = continuation
        lock.unlock()
        return true
    }

    func finish(_ result: Result<MSALResult, Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(throwing: CancellationError())
    }
}
#endif
