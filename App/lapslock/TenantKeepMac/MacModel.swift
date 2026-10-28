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

    /// The same app registration as the iPhone and iPad app, with this app's own redirect,
    /// which the registration's iOS / macOS platform must list for this bundle id.
    static let authConfiguration = AuthConfiguration(
        clientId: AuthConfiguration.vendorDefault.clientId,
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
        if let restored = await auth.restoreSession() {
            goLive(auth, restored)
        }
    }

    func signIn() async {
        guard let auth = auth ?? (try? MSALAuthManager(config: Self.authConfiguration)) else { return }
        self.auth = auth
        busy = true
        defer { busy = false }
        do {
            let signed = try await auth.signIn()
            goLive(auth, signed)
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
        await checkSession()
        await loadPulse()
    }

    /// The menu opened: a status older than five minutes is read again.
    func menuOpened() {
        guard mode != .signedOut else { return }
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
            _ = try await auth.token(scopes: ["User.Read"], allowInteractive: false)
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

    func loadRoles() async {
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

    func activate(_ access: EligibleAccess, justification: String, duration: String) async -> String {
        guard let privileged else { return "Sign in to activate." }
        busy = true
        defer { busy = false }
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
        if let latest = (try? await pulse.secureScore())?.latest, let current = latest.currentScore, let max = latest.maxScore, max > 0 {
            secureScorePercent = Int((current / max * 100).rounded())
        }
    }
}

private extension Optional where Wrapped == String {
    var orEmpty: String { self ?? "" }
}
