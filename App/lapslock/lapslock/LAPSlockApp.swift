import SwiftUI
import UIKit
import Combine
import AuthKit
import AuthKitMSAL
import CredentialKit
import DiagnosticsKit
import InventoryKit
import LicensingKit
import PrivilegedAccessKit
import SubscriptionKit

// App root. Owns the one decision the rest of the app depends on: which data source
// is in play — a live tenant, or demo mode.
//
// Demo mode exists for three reasons (§ App Store Review Guideline 2.1):
//   1. App Store reviewers cannot sign into a customer's Entra tenant.
//   2. UI can be developed and demonstrated without touching a real tenant.
//   3. Sales conversations can show the product without borrowing someone's devices.
// It is never silent: DemoBanner is pinned to every screen while it's on.
//
// The demo types are reachable from exactly one place: the `.demo` branch of
// AppRootView.content. The `.live` branch cannot construct one, because every service
// it needs comes off a LiveSession and none of those accessors is optional. There is
// no optional left to coalesce a demo double into, which is the point.

@main
struct LAPSlockApp: App {
    // Present only to receive broker redirects. See AppDelegate below.
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            AppRootView()
                .tint(Brand.accent)
                .preferredColorScheme(AppSettings.shared.appearance.colorScheme)
                // THIS is the handler that actually runs. See the note on AppDelegate.
                .onOpenURL { url in
                    MSALRedirect.handle(url, sourceApplication: nil)
                }
        }
    }
}

/// Catches the redirect Microsoft Authenticator sends back after a broker sign-in.
///
/// Read this before deleting either handler.
///
/// This app is scene-based (UIApplicationSceneManifest is in the Info.plist), and SwiftUI
/// installs its own scene delegate. When a scene delegate exists, iOS routes incoming URLs
/// to `scene(_:openURLContexts:)` and never calls `application(_:open:options:)`. So on
/// this app as currently configured, the delegate method below does not fire, and the
/// `.onOpenURL` above is what handles the redirect.
///
/// The symptom when nothing handles it: MSAL invokes the broker, the user authenticates in
/// Authenticator, control returns, and MSAL reports
/// "application did not receive response from broker" (MSALErrorDomain -50000), which the
/// app surfaces as a generic sign-in failure. Invisible in the simulator, which has no
/// broker installed and keeps the whole flow in-process.
///
/// The delegate is kept because it is the correct path if this app ever stops being
/// scene-based or gains a custom scene delegate, and because a duplicate delivery is
/// harmless: MSAL returns false for a URL it has already consumed.
///
/// On `sourceApplication: nil` in the `.onOpenURL` path: SwiftUI does not expose it. MSAL
/// validates broker responses with a nonce instead (the logs show V2-broker-nonce), which
/// is what makes nil acceptable here rather than merely tolerated.
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ app: UIApplication,
        open url: URL,
        options: [UIApplication.OpenURLOptionsKey: Any] = [:]
    ) -> Bool {
        MSALRedirect.handle(
            url,
            sourceApplication: options[.sourceApplication] as? String
        )
    }
}

/// One meter for the whole app, per mode.
///
/// LIVE uses the Keychain store, so the count survives a delete-and-reinstall. That is
/// the entire reason for choosing the Keychain over UserDefaults, and it is the one
/// assumption in the design that has to be verified on real hardware rather than trusted.
///
/// DEMO uses an in-memory store. A reviewer or a prospect exploring fake data must not
/// burn the five reveals they will want for evaluating against their own tenant. It is
/// still metered rather than unlimited, deliberately: App Store review then exercises the
/// countdown and the blocked state, so a reviewer meeting the wall has already seen the
/// count going down and understands what happened. A reviewer surprised by a block they
/// were never warned about is a rejection risk.
@MainActor
enum RevealMeters {
    static let live = RevealMeter(store: KeychainRevealLedgerStore())
    static let demo = RevealMeter(store: InMemoryRevealLedgerStore())
}

/// One entitlement manager for the live path, mirroring `RevealMeters`.
///
/// There is deliberately no `demo` counterpart. Demo mode is for evaluating the app without
/// signing in, and an install in that state must have no code path that can contact Kainor
/// (entitlement contract section 7.1). Passing nil to Settings in demo is what enforces it.
/// The MSP customer list. Live path only — demo mode has no tenants to switch between, and
/// giving it a store would create a code path where an unsigned-in install holds a list of
/// organizations.
enum TenantStores {
    static let live = KeychainTenantStore()
}

enum Entitlements {
    static let live = EntitlementManager(
        store: KeychainEntitlementStore(),
        client: EntitlementClient()
    )
}

@MainActor
final class AppRootModel: ObservableObject {
    enum Mode: Equatable {
        case signedOut
        case demo
        case live(AdminAccount)
    }

    /// Everything the live path needs, bundled so it can only exist as a set.
    ///
    /// The existence of a LiveSession is the proof that authentication succeeded, so
    /// every accessor here returns a non-optional live service. That is deliberate:
    /// the previous shape returned optionals, and the call site — a non-@ViewBuilder
    /// closure returning a concrete DeviceDetailView, which cannot branch — had no way
    /// to handle nil except to coalesce in a demo provider while still reporting
    /// isDemo: false. A revealed value with no banner and no way to tell it was fake
    /// is the one bug this app cannot ship. Hoisting the check up to a place that can
    /// branch removes the possibility rather than documenting it.
    struct LiveSession {
        let auth: MSALAuthManager
        let inventory: DeviceInventoryService
        /// Display-name lookups, in memory for the session. Only consulted when the
        /// Settings toggle is on; constructing it costs nothing and requests nothing.
        let names: UserNameResolver

        /// Live credential provider for one platform, sharing the authenticated session.
        func provider(for platform: DevicePlatform) -> any LocalAdminCredentialProviding {
            switch platform {
            case .windows:
                return WindowsLapsProvider(auth: auth)
            case .macOS:
                return MacOSLapsProvider(auth: auth)
            case .other:
                // MacOSLapsProvider is not used for iOS devices; the platform seam reports
                // .other as unsupported before any request is made.
                return MacOSLapsProvider(auth: auth)
            }
        }

        /// Live BitLocker service, sharing the authenticated session.
        func bitLocker() -> any BitLockerKeyProviding {
            BitLockerService(auth: auth)
        }
    }

    @Published var mode: Mode = .signedOut
    @Published var isSigningIn = false
    @Published var consentState: ConsentState?
    @Published var signInError: String?

    /// The authenticated manager. Exposed (read-only) so provider construction can
    /// share the same session rather than creating a second one.
    private(set) var auth: MSALAuthManager?

    /// Live services, created after sign-in so they share the authenticated session.
    /// Nil whenever the app is not signed in.
    private(set) var liveSession: LiveSession?

    /// Tenant of the signed-in account, offered as an opt-in field in diagnostics.
    var signedInTenantId: String? {
        if case .live(let account) = mode { return account.tenantId }
        return nil
    }

    /// Domain of the signed-in account, for labelling the Activate button.
    ///
    /// The UPN's domain, not the tenant GUID: an administrator recognises "contoso.com"
    /// instantly and a GUID not at all, and the whole point of showing it is to stop
    /// somebody activating against an organization they did not mean to.
    var signedInDomain: String? {
        if case .live(let account) = mode {
            let domain = account.username.split(separator: "@").last.map(String.init)
            return domain?.isEmpty == false ? domain : nil
        }
        return nil
    }

    var consentURL: URL? {
        let tenant: String? = {
            if case .live(let account) = mode { return account.tenantId }
            return nil
        }()
        return AdminConsentLink.url(
            clientId: AuthConfiguration.vendorDefault.clientId,
            tenant: tenant
        )
    }

    /// Contract section 7.7: `storeKit || tier != free`. StoreKit is not wired yet, so the
    /// second operand is a literal false. When it lands, it goes here and nowhere else.
    @Published private(set) var isPro = false

    /// True when the MSP tenant switcher is available. **Stored rather than computed**, and
    /// that is not a style choice: it now depends on the Apple subscription, which changes
    /// asynchronously when a renewal or refund lands, and a computed property would give
    /// SwiftUI nothing to observe.
    @Published private(set) var canSwitchTenants = false

    /// Apple's side of the entitlement. Owned here, at the root, so one listener serves the
    /// whole app.
    let subscriptions = SubscriptionStore()

    private var cancellables = Set<AnyCancellable>()

    /// Recomputes both capabilities from the organization licence AND the Apple subscription.
    ///
    /// Merged per capability rather than by picking a winning tier — see
    /// `SubscriptionEntitlement.merge`. An Enterprise organization licence is paid but cannot
    /// switch tenants, while an MSP subscription can, so somebody holding both must end up
    /// with unmetered reveals *and* switching. Any single-tier answer drops one of them.
    func recomputeEntitlement() {
        let merged = SubscriptionEntitlement.merge(
            subscription: subscriptions.entitlement,
            organizationTier: Entitlements.live.state(signedInTenantId: signedInTenantId).tier)
        isPro = merged.isPro
        canSwitchTenants = merged.allowsTenantSwitching
    }

    /// Customer organizations, most recently used first.
    @Published private(set) var savedTenants: [TenantReference] = []
    /// The tenant being operated in, which differs from the account's own only for an MSP.
    @Published private(set) var operatingTenantId: String?

    /// True only for the msp tier. Enterprise and Pro are single-organization by design, so
    /// the switcher does not appear for them at all rather than appearing and refusing.

    /// Label for the tenant banner. Prefers a name a human recognises, falling back to the
    /// GUID only when nothing better exists.
    var operatingTenantLabel: String? {
        guard let operating = operatingTenantId?.lowercased() else { return signedInDomain }
        if operating == signedInTenantId?.lowercased() { return signedInDomain }
        if let saved = savedTenants.first(where: { $0.tenantId == operating }) { return saved.label }
        return operating
    }

    var isOperatingAwayFromHome: Bool {
        guard let operating = operatingTenantId?.lowercased(), let home = signedInTenantId?.lowercased() else { return false }
        return operating != home
    }

    func refreshTenants() async {
        savedTenants = TenantList.sorted((try? TenantStores.live.load()) ?? [])
        operatingTenantId = await liveSession?.auth.operatingTenantId
    }

    func rememberTenant(_ tenant: TenantReference) {
        let updated = TenantList.upsert(tenant, into: (try? TenantStores.live.load()) ?? [])
        try? TenantStores.live.save(updated)
        savedTenants = TenantList.sorted(updated)
    }

    func forgetTenant(_ tenantId: String) {
        let updated = TenantList.removing(tenantId, from: (try? TenantStores.live.load()) ?? [])
        try? TenantStores.live.save(updated)
        savedTenants = TenantList.sorted(updated)
    }

    func resolveTenant(_ input: String) async -> Result<String, TenantDirectoryError> {
        do {
            return .success(try await TenantDirectory.resolve(input))
        } catch let error as TenantDirectoryError {
            return .failure(error)
        } catch {
            return .failure(.network)
        }
    }

    /// Switches organization, or returns home when nil. Returns nil on success.
    ///
    /// Tenant-scoped state is discarded on success for the same reason it is on sign-out
    /// (§7): a device list or a revealed credential from one organization must not survive
    /// into another. `setActiveTenant` validates before committing, so on failure nothing
    /// has changed and nothing needs clearing.
    func switchTenant(to tenantId: String?) async -> AuthError? {
        guard let session = liveSession else { return .noAccount }
        do {
            try await session.auth.setActiveTenant(tenantId)
        } catch let error as AuthError {
            await recordTenantSwitchFailure(error)
            return error
        } catch {
            await recordTenantSwitchFailure(.underlying("tenant switch failed"))
            return .underlying("tenant switch failed")
        }

        await session.inventory.reset()
        operatingTenantId = await session.auth.operatingTenantId
        return nil
    }

    /// The ONE calendar-shaped trigger for the scheduled refresh, contract section 7.3.
    /// Called from launch and from nothing a user does. The manager's 24-hour floor turns
    /// "every launch" into "at most daily", and an install that has never activated a
    /// license returns before touching the network at all.
    func refreshEntitlementIfDue() async {
        await Entitlements.live.refreshIfDue()
        recomputeEntitlement()
    }

    func prepare() {
        // Apple subscriptions, started ONCE at launch rather than from a purchase screen.
        // Renewals, cancellations, refunds and Ask-to-Buy approvals arrive through
        // Transaction.updates while no paywall is open, and a listener owned by a screen
        // would miss every one of them.
        subscriptions.start()
        subscriptions.$entitlement
            .sink { [weak self] _ in self?.recomputeEntitlement() }
            .store(in: &cancellables)

        guard auth == nil else { return }
        do {
            auth = try MSALAuthManager(config: .vendorDefault)
        } catch {
            signInError = "LAPSlock couldn't start its sign-in system. Reinstalling the app usually fixes this."
        }
    }

    func signIn() async {
        guard let auth else { return }
        isSigningIn = true
        signInError = nil
        consentState = nil
        defer { isSigningIn = false }

        do {
            let account = try await auth.signIn()
            liveSession = LiveSession(
                auth: auth,
                inventory: DeviceInventoryService(auth: auth),
                names: UserNameResolver(auth: auth)
            )
            mode = .live(account)
            recomputeEntitlement()
        } catch let error as AuthError {
            // Consent problems get a recovery path, not just an error (§8).
            if let state = ConsentDiagnostics.state(from: error) {
                consentState = state
                await recordSignInFailure(.consentRequired)  // mapped by ConsentDiagnostics
            } else if case .userCancelled = error {
                await recordSignInFailure(.userCancelled)
                return                      // user chose not to continue; not an error
            } else if case .tenantMismatch = error {
                signInError = "The sign-in came back for a different organization than expected. Sign in again."
                await recordSignInFailure(.tenantMismatch)
            } else {
                signInError = "Sign-in didn't complete. Check your connection and try again."
                await recordSignInFailure(.unknown)
            }
        } catch {
            signInError = "Sign-in didn't complete. Check your connection and try again."
            await recordSignInFailure(.unknown)
        }
    }

    /// Records a failed tenant switch, with the MSAL detail behind it.
    ///
    /// This is the compensation for a feature that cannot be tested here. An MSP who cannot
    /// reach a customer tenant has an on-screen explanation from `SwitchFailure`, and if that
    /// is not enough, the support report now carries the AADSTS code, the correlation ID and
    /// whether the broker answered — which is what Microsoft support needs to say why.
    ///
    /// The TARGET TENANT IS DELIBERATELY NOT RECORDED. It identifies one of the MSP's
    /// customers, and a support report is a thing people email. The correlation ID lets
    /// Microsoft find the request, tenant included, without putting a customer's directory
    /// ID in our inbox.
    private func recordTenantSwitchFailure(_ error: AuthError) async {
        let detail = await auth?.lastAuthFailure
        await DiagnosticsRecorder.shared.record(DiagnosticEvent(
            operation: .tenantSwitch,
            outcome: Self.outcome(for: error),
            httpStatus: detail?.httpStatus,
            msalErrorCode: detail?.msalErrorCode,
            aadErrorCode: detail?.aadErrorCode,
            oauthError: detail?.oauthError,
            correlationId: detail?.correlationId,
            brokerInvolved: detail?.brokerInvolved
        ))
    }

    static func outcome(for error: AuthError) -> DiagnosticOutcome {
        switch error {
        case .noAccount:           return .missingIdentifier
        case .interactionRequired: return .notAuthorized
        case .consentRequired:     return .consentRequired
        case .userCancelled:       return .userCancelled
        case .tenantMismatch:      return .tenantMismatch
        case .underlying:          return .unknown
        }
    }

    /// Records a sign-in failure with whatever allowlisted detail MSAL left behind.
    ///
    /// This is the change the 2026-08-26 broker bug asked for: the user still sees a plain
    /// sentence, but the support report now carries the MSAL code, the AADSTS code, the
    /// correlation ID and whether the broker was in the path — and nothing else, because
    /// `AuthFailureDetail` and `DiagnosticEvent` each refuse anything that is not a number,
    /// a bool, or a string of a fixed shape.
    private func recordSignInFailure(_ outcome: DiagnosticOutcome) async {
        let detail = await auth?.lastAuthFailure
        await DiagnosticsRecorder.shared.record(DiagnosticEvent(
            operation: .signIn,
            outcome: outcome,
            httpStatus: detail?.httpStatus,
            msalErrorCode: detail?.msalErrorCode,
            aadErrorCode: detail?.aadErrorCode,
            oauthError: detail?.oauthError,
            correlationId: detail?.correlationId,
            brokerInvolved: detail?.brokerInvolved
        ))
    }

    func signOut() async {
        if case .live(let account) = mode, let auth {
            try? await auth.signOut(account: account)
        }
        // Tenant-scoped data must not survive an account change (§7).
        await liveSession?.inventory.reset()
        liveSession = nil
        mode = .signedOut
        consentState = nil
        recomputeEntitlement()
    }

    func enterDemoMode() {
        mode = .demo
    }

    /// Requests incremental consent for the device-write scope, used when the user turns
    /// on BitLocker rotation. Returns nil on success or a user-facing message on failure.
    ///
    /// Asking here — at the moment the toggle flips — means an admin discovers a blocked
    /// permission while sitting at their desk, not while standing at a broken machine.
    /// Requests consent for the PIM activation scopes.
    ///
    /// Mirrors `requestRotationConsent` deliberately: same opt-in shape, same incremental
    /// consent, same rule that a customer who never enables it never sees the permission
    /// requested. This one is the heavier ask of the two — it lets the app request a
    /// privilege escalation — so it stays off by default.
    func requestPrivilegedActivationConsent() async -> String? {
        guard let auth else { return "Sign in first." }
        do {
            // ALL of them — read and activate. Consenting to activation alone left the
            // read scopes unconsented, so the sheet failed the moment it opened.
            _ = try await auth.token(scopes: PrivilegedAccessGraph.allScopes, allowInteractive: true)
            return nil
        } catch let error as AuthError {
            if ConsentDiagnostics.state(from: error) != nil {
                return "Your organization hasn't approved permission for LAPSlock to request role activation. An Entra administrator needs to grant it."
            }
            if case .userCancelled = error { return "Permission wasn't granted." }
            return "Couldn't request permission. Check your connection and try again."
        } catch {
            return "Couldn't request permission. Check your connection and try again."
        }
    }

    /// Requests consent to read users' display names. Same opt-in shape as the other two.
    func requestUserNamesConsent() async -> String? {
        guard let auth else { return "Sign in first." }
        do {
            _ = try await auth.token(scopes: [UserNameResolver.scope], allowInteractive: true)
            return nil
        } catch let error as AuthError {
            if ConsentDiagnostics.state(from: error) != nil {
                return "Your organization hasn't approved permission for LAPSlock to read user names. An Entra administrator needs to grant it."
            }
            if case .userCancelled = error { return "Permission wasn't granted." }
            return "Couldn't request permission. Check your connection and try again."
        } catch {
            return "Couldn't request permission. Check your connection and try again."
        }
    }

    /// The tenant's activation rules for one piece of eligible access.
    func privilegedPolicy(for access: EligibleAccess) async -> ActivationPolicy {
        guard let session = liveSession else { return .unknown }
        return await PrivilegedAccessService(auth: session.auth).policy(for: access)
    }

    /// Reads what the signed-in user could activate.
    func loadEligibleAccess() async -> Result<[EligibleAccess], PrivilegedAccessError> {
        guard let session = liveSession else { return .failure(.notAuthorized) }
        do {
            return .success(try await PrivilegedAccessService(auth: session.auth).eligibleAccess())
        } catch let error as PrivilegedAccessError {
            return .failure(error)
        } catch {
            return .failure(.transport)
        }
    }

    /// Activates one piece of eligible access, recording a failure in diagnostics.
    func activatePrivilegedAccess(
        _ access: EligibleAccess,
        justification: String,
        ticketNumber: String?,
        duration: String
    ) async -> Result<ActivationOutcome, PrivilegedAccessError> {
        guard let session = liveSession else { return .failure(.notAuthorized) }
        do {
            let outcome = try await PrivilegedAccessService(auth: session.auth).activate(
                access, justification: justification, ticketNumber: ticketNumber, duration: duration)
            return .success(outcome)
        } catch let error as PrivilegedAccessError {
            await recordActivationFailure(error, access: access)
            return .failure(error)
        } catch {
            await recordActivationFailure(.transport, access: access)
            return .failure(.transport)
        }
    }

    /// Re-reads an activation request PIM already created, for the "Check again" button.
    ///
    /// **Not recorded in diagnostics, and that is deliberate.** A failed status read says
    /// nothing about the activation, which either succeeded or did not on its own; recording
    /// it would put a scary-looking entry in a support report for an operation that changed
    /// nothing. The failed activations that need explaining are already captured above.
    func recheckPrivilegedRequest(
        _ requestId: String,
        for access: EligibleAccess
    ) async -> Result<ActivationOutcome, PrivilegedAccessError> {
        guard let session = liveSession else { return .failure(.notAuthorized) }
        do {
            let outcome = try await PrivilegedAccessService(auth: session.auth)
                .status(ofRequest: requestId, for: access)
            return .success(outcome)
        } catch let error as PrivilegedAccessError {
            return .failure(error)
        } catch {
            return .failure(.transport)
        }
    }

    /// A failed activation reaches the support report, for the same reason a failed tenant
    /// switch does: the tenant policy that refused it is not reproducible here, so the
    /// Microsoft error code is the only thing that explains it.
    ///
    /// The role and the justification are NOT recorded. Which role somebody tried to
    /// activate and why is their business and their audit log's, not a support inbox's.
    private func recordActivationFailure(_ error: PrivilegedAccessError, access: EligibleAccess) async {
        let detail = await auth?.lastAuthFailure

        // A 4xx is our request being rejected; a 5xx is Microsoft being unavailable. Mapping
        // both to serviceUnavailable sent a diagnostics reader hunting an outage that was
        // not happening.
        let outcome: DiagnosticOutcome = {
            switch error {
            case .consentRequired: return .consentRequired
            case .notAuthorized, .claimsChallenge: return .notAuthorized
            case .noEligibleAccess, .alreadyActive: return .notFound
            case .transport: return .transportError
            case .decodeFailure: return .decodeFailure
            case .serviceError(let status, _): return status < 500 ? .badRequest : .serviceUnavailable
            }
        }()

        // Graph's status and code, not MSAL's. The previous version read httpStatus from the
        // AUTH failure detail, which is nil for a Graph error — so a 400 was reported with no
        // status at all and an outcome that claimed an outage.
        var graphStatus: Int?
        var graphCode: String?
        if case .serviceError(let status, let code) = error {
            graphStatus = status
            graphCode = code
        }

        await DiagnosticsRecorder.shared.record(DiagnosticEvent(
            operation: .roleActivation,
            outcome: outcome,
            httpStatus: graphStatus ?? detail?.httpStatus,
            // Which endpoint, so role and group failures are told apart at a glance. A
            // template, so no group or tenant identifier rides along.
            endpointTemplate: access.activationPath,
            msalErrorCode: detail?.msalErrorCode,
            aadErrorCode: detail?.aadErrorCode,
            oauthError: detail?.oauthError,
            correlationId: detail?.correlationId,
            brokerInvolved: detail?.brokerInvolved,
            graphErrorCode: graphCode
        ))
    }

    func requestRotationConsent() async -> String? {
        guard let auth else { return "Sign in first." }
        do {
            _ = try await auth.token(scopes: [LapsCredentialScopes.deviceWrite], allowInteractive: true)
            return nil
        } catch let error as AuthError {
            if ConsentDiagnostics.state(from: error) != nil {
                return "Your organization hasn't approved permission for LAPSlock to modify devices. An Entra administrator needs to grant it."
            }
            if case .userCancelled = error { return "Permission wasn't granted." }
            return "Couldn't request permission. Check your connection and try again."
        } catch {
            return "Couldn't request permission. Check your connection and try again."
        }
    }
}

struct AppRootView: View {
    @StateObject private var root = AppRootModel()
    @State private var showingSignedOutSettings = false

    var body: some View {
        content
            .task {
                root.prepare()
                await root.refreshEntitlementIfDue()
            }
    }

    @ViewBuilder
    private var content: some View {
        switch root.mode {
        case .signedOut:
            signedOut

        case .demo:
            DeviceListView(
                model: DeviceListModel(
                    inventory: DemoInventoryProvider(),
                    meter: RevealMeters.demo
                ),
                isDemo: true,
                settingsBuilder: {
                    SettingsView(
                        settings: AppSettings.shared,
                        requestRotationConsent: { nil },   // no tenant in demo mode
                        isDemo: true,
                        tenantId: nil,
                        meter: RevealMeters.demo,
                        endSession: { await root.signOut() }
                    )
                },
                detailBuilder: { device in
                    DeviceDetailView(
                        model: DeviceDetailModel(
                            device: device,
                            provider: DemoLapsProvider(platform: device.platform),
                            bitLocker: DemoBitLockerService(),
                            isDemo: true,
                            rotationEnabled: AppSettings.shared.bitLockerRotationEnabled,
                            meter: RevealMeters.demo
                        )
                    )
                }
            )

        case .live:
            if let session = root.liveSession {
                DeviceListView(
                    model: DeviceListModel(
                        inventory: session.inventory,
                        meter: RevealMeters.live,
                        isPro: root.isPro,
                        nameResolver: session.names,
                        settings: AppSettings.shared
                    ),
                    isDemo: false,
                    tenantSwitcher: root.canSwitchTenants ? {
                        TenantSwitcherView(
                            homeTenantId: root.signedInTenantId ?? "",
                            homeLabel: root.signedInDomain ?? "Your organization",
                            operatingTenantId: root.operatingTenantId ?? root.signedInTenantId,
                            saved: root.savedTenants,
                            resolve: { await root.resolveTenant($0) },
                            switchTo: { await root.switchTenant(to: $0) },
                            remember: { root.rememberTenant($0) },
                            forget: { root.forgetTenant($0) },
                            consentURL: { tenant in
                                AdminConsentLink.url(
                                    clientId: AuthConfiguration.vendorDefault.clientId,
                                    tenant: tenant
                                )
                            }
                        )
                    } : nil,
                    onAppearRefresh: { await root.refreshTenants() },
                    tenantBanner: root.operatingTenantLabel.map {
                        (label: $0, isAwayFromHome: root.isOperatingAwayFromHome)
                    },
                    settingsBuilder: {
                        SettingsView(
                            settings: AppSettings.shared,
                            requestRotationConsent: { await root.requestRotationConsent() },
                            isDemo: false,
                            tenantId: root.signedInTenantId,
                            meter: RevealMeters.live,
                            isPro: root.isPro,
                            entitlement: Entitlements.live,
                            entitlementDidChange: { root.recomputeEntitlement() },
                            lastAuthFailure: { await session.auth.lastAuthFailure },
                            signedInDomain: root.signedInDomain,
                            endSession: { await root.signOut() },
                            requestPrivilegedConsent: { await root.requestPrivilegedActivationConsent() },
                            requestUserNamesConsent: { await root.requestUserNamesConsent() },
                            privilegedSheet: {
                                PrivilegedAccessView(
                                    deviceName: nil,
                                    loadEligible: { await root.loadEligibleAccess() },
                                    activate: { access, justification, ticket, duration in
                                        await root.activatePrivilegedAccess(
                                            access, justification: justification,
                                            ticketNumber: ticket, duration: duration)
                                    },
                                    requestConsent: { await root.requestPrivilegedActivationConsent() },
                                    policy: { await root.privilegedPolicy(for: $0) },
                                    recheck: { requestId, access in
                                        await root.recheckPrivilegedRequest(requestId, for: access)
                                    }
                                )
                            },
                            subscriptions: root.subscriptions
                        )
                    },
                    detailBuilder: { device in
                        DeviceDetailView(
                            model: DeviceDetailModel(
                                device: device,
                                provider: session.provider(for: device.platform),
                                bitLocker: session.bitLocker(),
                                isDemo: false,
                                rotationEnabled: AppSettings.shared.bitLockerRotationEnabled,
                                meter: RevealMeters.live,
                                isPro: root.isPro
                            ),
                            privilegedSheet: {
                                PrivilegedAccessView(
                                    deviceName: device.deviceName,
                                    loadEligible: { await root.loadEligibleAccess() },
                                    activate: { access, justification, ticket, duration in
                                        await root.activatePrivilegedAccess(
                                            access, justification: justification,
                                            ticketNumber: ticket, duration: duration)
                                    },
                                    requestConsent: { await root.requestPrivilegedActivationConsent() },
                                    policy: { await root.privilegedPolicy(for: $0) },
                                    recheck: { requestId, access in
                                        await root.recheckPrivilegedRequest(requestId, for: access)
                                    }
                                )
                            }
                        )
                    }
                )
            } else {
                // A .live mode with no session shouldn't happen. Recover to signed out
                // rather than showing a blank screen or substituting a data source.
                ProgressView().task { await root.signOut() }
            }
        }
    }

    private var signedOut: some View {
        VStack(spacing: 0) {
            SignInView(
                consentState: root.consentState,
                consentURL: root.consentURL,
                isBusy: root.isSigningIn,
                onOpenSettings: { showingSignedOutSettings = true }
            ) {
                Task { await root.signIn() }
            }
            .sheet(isPresented: $showingSignedOutSettings) {
                // No tenant, so nothing tenant-scoped is offered: no consent requests, no
                // license, no sign-out. What IS here is the diagnostics report, with the
                // most recent sign-in failure attached — the reason this sheet exists.
                SettingsView(
                    settings: AppSettings.shared,
                    requestRotationConsent: { "Sign in first." },
                    isDemo: false,
                    tenantId: nil,
                    meter: RevealMeters.live,
                    isPro: root.isPro,
                    lastAuthFailure: { await root.auth?.lastAuthFailure },
                    hasSession: false
                )
            }

            if let error = root.signInError {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal, 24)
                    .padding(.bottom, 8)
            }

            // Demo entry lives here so a reviewer (or a prospect) can evaluate the app
            // without a tenant. Understated on purpose — it isn't the primary path.
            Button("Explore with demo data") {
                root.enterDemoMode()
            }
            .font(.footnote.weight(.medium))
            .padding(.bottom, 20)
        }
    }

}

// MARK: - previews

#Preview("Device list (demo)") {
    DeviceListView(
        model: DeviceListModel(inventory: DemoInventoryProvider(latency: .milliseconds(1))),
        isDemo: true,
        settingsBuilder: {
            SettingsView(settings: AppSettings.shared, requestRotationConsent: { nil }, isDemo: true, tenantId: nil)
        },
        detailBuilder: { device in
            DeviceDetailView(
                model: DeviceDetailModel(
                    device: device,
                    provider: DemoLapsProvider(platform: device.platform),
                    bitLocker: DemoBitLockerService(),
                    isDemo: true,
                    rotationEnabled: AppSettings.shared.bitLockerRotationEnabled
                )
            )
        }
    )
}

#Preview("Windows detail (demo)") {
    NavigationStack {
        DeviceDetailView(
            model: DeviceDetailModel(
                device: DemoInventoryProvider.fleet[0],
                provider: DemoLapsProvider(platform: .windows, latency: .milliseconds(1)),
                bitLocker: DemoBitLockerService(latency: .milliseconds(1)),
                isDemo: true,
                rotationEnabled: true
            )
        )
    }
}

#Preview("Windows, not Entra-joined") {
    NavigationStack {
        DeviceDetailView(
            model: DeviceDetailModel(
                device: DemoInventoryProvider.fleet[4],
                provider: DemoLapsProvider(platform: .windows, latency: .milliseconds(1)),
                bitLocker: DemoBitLockerService(latency: .milliseconds(1)),
                isDemo: true,
                rotationEnabled: true
            )
        )
    }
}

#Preview("macOS detail (reveal unavailable)") {
    NavigationStack {
        DeviceDetailView(
            model: DeviceDetailModel(
                device: DemoInventoryProvider.fleet[5],
                provider: DemoLapsProvider(platform: .macOS, latency: .milliseconds(1)),
                bitLocker: DemoBitLockerService(latency: .milliseconds(1)),
                isDemo: true,
                rotationEnabled: true
            )
        )
    }
}
