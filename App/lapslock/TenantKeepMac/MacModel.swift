import Foundation
import AuthKit
import AuthKitMSAL
import InventoryKit
import PrivilegedAccessKit
import TenantPulseKit

/// The Mac menu's state. One signed-in session, or the demo, or nothing.
@MainActor
@Observable
final class MacModel {
    enum Mode: Equatable { case signedOut, demo, live }

    private(set) var mode: Mode = .signedOut
    private(set) var account: AdminAccount?
    private(set) var sessionCheckedAt: Date?
    private(set) var sessionProblem: String?
    private(set) var busy = false
    var message: String?
    /// The organization turned this app off on its Macs. Nothing is signed in or read.
    private(set) var turnedOffByOrganization = false

    /// What an organization set for this app on a Mac it manages: a managed preference for
    /// `com.kainor.tenantkeep.menubar`, delivered by a configuration profile (in Intune, a
    /// preference file for that domain). Only a value the organization forced counts, so a
    /// value somebody wrote with `defaults` changes nothing. Like the iPhone app's policy,
    /// it can only take away: turn the app off, or keep it to one organization.
    struct Policy: Equatable {
        /// `menuBar.disabled`: this app is not to be used on the organization's Macs.
        var disabled = false
        /// `tenant.pin`: the one organization this app may be signed in to.
        var tenantPin: String?
        /// `modules.disabled`: the modules the organization turned off, the iPhone app's own
        /// key. The menu bar app has one of them, `privilegedAccess`, its Roles view. Before
        /// the second review's follow-up (2026-11-24) the Mac activated roles that the
        /// organization had turned off on the phone, as the watch did (R2-3).
        var modulesDisabled: Set<String> = []

        static let disabledKey = "menuBar.disabled"
        static let tenantPinKey = "tenant.pin"
        static let modulesDisabledKey = "modules.disabled"

        var privilegedAccessOff: Bool { modulesDisabled.contains("privilegedaccess") }

        /// `value` returns a key's value only when the organization forced it.
        init(forced value: (String) -> Any?) {
            switch value(Self.disabledKey) {
            case let flag as Bool:     disabled = flag
            case let text as String:   disabled = ["true", "yes", "1"].contains(text.trimmingCharacters(in: .whitespaces).lowercased())
            case let number as NSNumber: disabled = number.boolValue
            default:                   disabled = false
            }
            if let pin = (value(Self.tenantPinKey) as? String)?.trimmingCharacters(in: .whitespaces).lowercased(),
               UUID(uuidString: pin) != nil {
                tenantPin = pin
            }
            // An array of names, or one string with commas, as the iPhone app takes it.
            let names: [String]
            switch value(Self.modulesDisabledKey) {
            case let list as [String]: names = list
            case let text as String:   names = text.split(separator: ",").map(String.init)
            default:                   names = []
            }
            modulesDisabled = Set(names.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty })
        }

        static let privilegedAccessOffMessage = "Your organization has turned off Privileged Access in TenantKeep."

        static func current() -> Policy {
            let app = (Bundle.main.bundleIdentifier ?? "com.kainor.tenantkeep.menubar") as CFString
            return Policy { key in
                CFPreferencesAppValueIsForced(key as CFString, app) ? CFPreferencesCopyAppValue(key as CFString, app) : nil
            }
        }

        /// Whether an account from `tenant` may stay signed in.
        func allows(tenant: String) -> Bool {
            tenantPin.map { $0 == tenant.lowercased() } ?? true
        }
    }

    // Devices
    /// What is typed. The results follow it once typing pauses.
    var query = "" {
        didSet { if query != oldValue { scheduleResults() } }
    }
    /// Every device loaded, in name order.
    private(set) var devices: [ManagedDeviceSummary] = []
    /// The first dozen matches, kept rather than worked out on every redraw of the menu.
    private(set) var results: [ManagedDeviceSummary] = []
    private(set) var devicesLoading = false
    private(set) var devicesError: String?

    // Roles
    private(set) var eligible: [EligibleAccess] = []
    private(set) var rolesLoading = false
    private(set) var rolesError: String?

    // Pulse
    private(set) var degraded: [String] = []
    private(set) var expiringSoon: Int?
    private(set) var secureScorePercent: Int?
    private(set) var pulseError: String?

    @ObservationIgnored private var auth: MSALAuthManager?
    @ObservationIgnored private var inventory: (any DeviceInventoryProviding)?
    @ObservationIgnored private var pulse: (any TenantPulseProviding)?
    @ObservationIgnored private var privileged: PrivilegedAccessService?
    /// The one device load running. A second request for one waits for it instead of
    /// paging the tenant again alongside it, which appended the same pages twice.
    @ObservationIgnored private var deviceLoad: Task<Void, Never>?
    /// Set once the Devices tab has been opened. Until then a menu bar app that runs for
    /// days holds no copy of the tenant's devices.
    @ObservationIgnored private var devicesWanted = false
    @ObservationIgnored private var resultsTask: Task<Void, Never>?
    /// Reads the session and service health every fifteen minutes, so the icon is not left
    /// showing the state at launch for days. The system's scheduler, which waits out sleep.
    @ObservationIgnored private var statusRefresher: NSBackgroundActivityScheduler?
    @ObservationIgnored private var statusCheckedAt: Date?
    /// Whether this session has read which app the organization approved for role activation.
    @ObservationIgnored private var activationRouteSettled = false

    /// The same app registrations as the iPhone and iPad app, with this app's own
    /// redirect, which the read and role activation registrations list for this bundle id.
    static let authConfiguration = AuthConfiguration(
        redirectUri: "msauth." + (Bundle.main.bundleIdentifier ?? "com.kainor.tenantkeep.menubar") + "://auth")

    var attention: Bool { !degraded.isEmpty || sessionProblem != nil }

    private func scheduleResults() {
        resultsTask?.cancel()
        resultsTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(150))
            guard !Task.isCancelled else { return }
            self?.updateResults()
        }
    }

    private func updateResults() {
        results = Array(DeviceSearch.filter(devices, query: query).prefix(12))
    }

    /// `demo` is for previews; the app itself starts signed out or restores a session.
    init(demo: Bool = false) {
        if demo { enterDemo() } else { Task { await start() } }
    }

    private func start() async {
        #if DEBUG
        if CommandLine.arguments.contains("-LAPSlockDemo") { enterDemo(); return }
        #endif
        guard let auth = try? MSALAuthManager(config: Self.authConfiguration) else {
            sessionProblem = "The sign-in library could not start."
            return
        }
        self.auth = auth
        let policy = Policy.current()
        let restored = await auth.restoreSession()
        if policy.disabled {
            // Turned off since somebody last signed in here: that session ends too.
            if let restored { try? await auth.signOut(account: restored) }
            turnedOffByOrganization = true
            return
        }
        if let restored { await enter(auth, restored, policy: policy) }
    }

    /// Goes live, unless the organization keeps this app to another organization than the
    /// one that signed in. Then the account is signed straight back out, as on the iPhone.
    private func enter(_ auth: MSALAuthManager, _ signed: AdminAccount, policy: Policy) async {
        guard policy.allows(tenant: signed.tenantId) else {
            try? await auth.signOut(account: signed)
            message = "This Mac's organization allows TenantKeep for its own tenant only. That account belongs to another."
            return
        }
        goLive(auth, signed)
    }

    /// The policy again, while running: a menu bar app stays open for days.
    private func applyPolicy() async {
        let policy = Policy.current()
        if policy.disabled {
            if mode == .live { await signOut() }
            turnedOffByOrganization = true
        } else {
            turnedOffByOrganization = false
            if mode == .live, let account, !policy.allows(tenant: account.tenantId) {
                await signOut()
                message = "This Mac's organization allows TenantKeep for its own tenant only. That account belongs to another."
            }
        }
    }

    func signIn() async {
        let policy = Policy.current()
        guard !policy.disabled else { turnedOffByOrganization = true; return }
        guard let auth = auth ?? (try? MSALAuthManager(config: Self.authConfiguration)) else { return }
        self.auth = auth
        busy = true
        defer { busy = false }
        do {
            let signed = try await auth.signIn()
            await enter(auth, signed, policy: policy)
        } catch {
            message = "Sign-in didn't complete. " + (error as? AuthError).map { String(describing: $0) }.map { "(" + $0 + ")" }.orEmpty
        }
    }

    func signOut() async {
        if let auth, let account { try? await auth.signOut(account: account) }
        statusRefresher?.invalidate()
        statusRefresher = nil
        mode = .signedOut
        account = nil
        activationRouteSettled = false
        devices = []
        eligible = []
        degraded = []
        expiringSoon = nil
        secureScorePercent = nil
        sessionCheckedAt = nil
        sessionProblem = nil
    }

    func enterDemo() {
        mode = .demo
        account = AdminAccount(id: "demo", tenantId: "demo", username: "demo@demo.example", objectId: "demo")
        inventory = DemoInventoryProvider(latency: .milliseconds(200), pageSize: 200)
        pulse = DemoTenantPulseProvider()
        privileged = nil
        sessionCheckedAt = Date()
        startStatusRefresh()
        Task { await refreshAll() }
    }

    private func goLive(_ auth: MSALAuthManager, _ signed: AdminAccount) {
        mode = .live
        account = signed
        activationRouteSettled = false
        inventory = DeviceInventoryService(auth: auth, pageSize: 1000)
        pulse = TenantPulseService(graph: GraphClient(auth: auth))
        privileged = PrivilegedAccessService(auth: auth)
        startStatusRefresh()
        Task { await refreshAll() }
    }

    private func startStatusRefresh() {
        statusRefresher?.invalidate()
        let scheduler = NSBackgroundActivityScheduler(identifier: "com.kainor.tenantkeep.menubar.status")
        scheduler.repeats = true
        scheduler.interval = 15 * 60
        scheduler.tolerance = 5 * 60
        scheduler.qualityOfService = .utility
        scheduler.schedule { [weak self] completion in
            Task { @MainActor in
                await self?.refreshStatus()
                completion(.finished)
            }
        }
        statusRefresher = scheduler
    }

    /// The session and service health: what the menu bar icon shows. Never the devices.
    func refreshStatus() async {
        statusCheckedAt = Date()
        await applyPolicy()
        guard mode != .signedOut else { return }
        await checkSession()
        await loadPulse()
    }

    /// The menu opened: a status older than five minutes is read again.
    func menuOpened() {
        // Signed out, the timer is not running: the organization's switch is read here, so
        // turning the app off or back on shows without a relaunch.
        guard mode != .signedOut else { turnedOffByOrganization = Policy.current().disabled; return }
        if let statusCheckedAt, Date().timeIntervalSince(statusCheckedAt) < 5 * 60 { return }
        Task { await refreshStatus() }
    }

    func refreshAll() async {
        statusCheckedAt = Date()
        await checkSession()
        async let a: Void = devicesWanted ? loadDevices() : ()
        async let b: Void = loadRoles()
        async let c: Void = loadPulse()
        _ = await (a, b, c)
    }

    /// The Devices tab is on screen: load them the first time.
    func devicesTabOpened() async {
        guard !devicesWanted else { return }
        devicesWanted = true
        await loadDevices()
    }

    /// A silent token for the base scope says whether the session still works, without a
    /// prompt. Conditional Access sign-in frequency is the usual reason it does not.
    func checkSession() async {
        guard mode == .live, let auth else { return }
        do {
            _ = try await auth.token(scopes: DeviceInventoryService.requiredScopes, allowInteractive: false)
            sessionCheckedAt = Date()
            sessionProblem = nil
        } catch {
            sessionProblem = "Your session needs a sign-in again."
        }
    }

    func loadDevices() async {
        if let deviceLoad { return await deviceLoad.value }
        guard let inventory else { return }
        let load = Task { [weak self] in
            guard let self else { return }
            devicesLoading = true
            defer { devicesLoading = false }
            do {
                await inventory.reset()
                // A thousand a page: a 20,000-device tenant in 20 requests. Each page is
                // merged into the sorted list, not the whole list sorted again.
                var loaded = try await inventory.loadFirstPage().devices.sorted(by: DeviceSearch.inNameOrder)
                devices = loaded
                updateResults()
                while try await inventory.hasMore() {
                    guard let page = try await inventory.loadNextPage() else { break }
                    loaded = DeviceSearch.merged(loaded, adding: page.devices)
                    devices = loaded
                    updateResults()
                }
                devicesError = nil
            } catch {
                devicesError = "Couldn't read the device list."
            }
        }
        deviceLoad = load
        await load.value
        deviceLoad = nil
    }

    /// Whether the organization turned Privileged Access off, read when asked.
    var privilegedAccessOff: Bool { Policy.current().privilegedAccessOff }

    func loadRoles() async {
        guard !Policy.current().privilegedAccessOff else { eligible = []; rolesError = Policy.privilegedAccessOffMessage; return }
        guard let privileged else { eligible = []; rolesError = mode == .demo ? "Demo data has no roles to activate." : nil; return }
        rolesLoading = true
        defer { rolesLoading = false }
        do {
            eligible = try await privileged.eligibleAccess()
            rolesError = nil
        } catch {
            rolesError = "Couldn't read eligible roles. Turn on role activation in the iPhone or iPad app once, in this tenant."
        }
    }

    /// Which app serves role activation in this organization. An organization approves
    /// actions one of two ways: an app for each kind, or one app, TenantKeep Actions, for all
    /// of them. This app used to sign in to TenantKeep Role Activation whatever was chosen,
    /// so an organization that had approved only the one app was asked to approve a second.
    /// Now the organization's own record of what it approved is read, as the iPhone app
    /// does on Automatic: the separate app when that is approved, because its token is the
    /// narrower, and the combined one only when that alone is. A record that cannot be
    /// read changes nothing and is read again at the next activation.
    private func settleActivationRoute() async {
        guard !activationRouteSettled, mode == .live, let auth, let tenant = account?.tenantId else { return }
        let approved = await ApprovalProbe(graph: GraphClient(auth: auth)).approvedScopes(for: [.roleActivation, .actions])
        // The answer is for the person and the organization it was read for.
        guard mode == .live, account?.tenantId == tenant else { return }
        switch ApprovalProbe.choose(for: .roleActivation, approved: approved) {
        case .some(.actions): await auth.setCombinedWrites([.roleActivation], inTenant: tenant)
        case .some:           await auth.setCombinedWrites([], inTenant: tenant)
        case .none:           return
        }
        activationRouteSettled = true
    }

    func activate(_ access: EligibleAccess, justification: String, duration: String) async -> String {
        // The organization's switch, at the moment of acting, as on the watch.
        guard !Policy.current().privilegedAccessOff else { return Policy.privilegedAccessOffMessage }
        guard let privileged else { return "Sign in to activate." }
        busy = true
        defer { busy = false }
        // Activation goes through an app registration other than the one this app reads
        // with: the organization's choice of the two. Its first use on this Mac is one
        // sign-in; after that this is silent.
        await settleActivationRoute()
        do {
            _ = try await auth?.token(scopes: [access.activateScope], allowInteractive: true)
        } catch {
            return "Role activation needs one more sign-in, to the app your organization approved for it, and it didn't complete. An Entra administrator can approve one at tenantkeep.app/consent."
        }
        do {
            switch try await privileged.activate(access, justification: justification, ticketNumber: nil, duration: duration) {
            case .activated:                return (access.displayName ?? "The role") + " is active."
            case .provisioning:             return "Being applied. It becomes active on its own."
            case .pendingApproval:          return "Sent for approval."
            case .requested(_, let status): return "Requested. PIM says " + status + "."
            case .refused(let status):      return "PIM refused: " + status + "."
            }
        } catch PrivilegedAccessError.claimsChallenge(let challenge) {
            do {
                _ = try await auth?.token(scopes: [PrivilegedAccessGraph.roleActivateScope], claims: challenge.json, allowInteractive: true)
                return await activate(access, justification: justification, duration: duration)
            } catch {
                return "Microsoft wanted a fresh sign-in step, and it didn't complete."
            }
        } catch {
            return "Couldn't activate. Your policy may need a ticket number; use the iPhone or iPad app for that."
        }
    }

    func loadPulse() async {
        guard let pulse else { return }
        do {
            let report = try await pulse.health()
            degraded = report.degraded.map(\.service)
            pulseError = nil
        } catch {
            pulseError = "Couldn't read service health. Open Tenant Pulse in the iPhone or iPad app once to grant it."
        }
        let horizon = Date().addingTimeInterval(30 * 86_400)
        expiringSoon = (try? await pulse.expiringItems())?.filter { $0.expiresAt <= horizon }.count
        if let latest = (try? await pulse.secureScore(snapshots: 1))?.latest, let current = latest.currentScore, let max = latest.maxScore, max > 0 {
            secureScorePercent = Int((current / max * 100).rounded())
        }
    }
}

private extension Optional where Wrapped == String {
    var orEmpty: String { self ?? "" }
}
