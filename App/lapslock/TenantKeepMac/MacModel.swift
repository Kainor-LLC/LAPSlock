import Foundation
import Combine
import AuthKit
import AuthKitMSAL
import InventoryKit
import PrivilegedAccessKit
import TenantPulseKit

/// The Mac menu's state. One signed-in session, or the demo, or nothing.
@MainActor
final class MacModel: ObservableObject {
    enum Mode: Equatable { case signedOut, demo, live }

    @Published private(set) var mode: Mode = .signedOut
    @Published private(set) var account: AdminAccount?
    @Published private(set) var sessionCheckedAt: Date?
    @Published private(set) var sessionProblem: String?
    @Published private(set) var busy = false
    @Published var message: String?

    // Devices
    @Published var query = ""
    @Published private(set) var devices: [ManagedDeviceSummary] = []
    @Published private(set) var devicesLoading = false
    @Published private(set) var devicesError: String?

    // Roles
    @Published private(set) var eligible: [EligibleAccess] = []
    @Published private(set) var rolesLoading = false
    @Published private(set) var rolesError: String?

    // Pulse
    @Published private(set) var degraded: [String] = []
    @Published private(set) var expiringSoon: Int?
    @Published private(set) var secureScorePercent: Int?
    @Published private(set) var pulseError: String?

    private var auth: MSALAuthManager?
    private var inventory: (any DeviceInventoryProviding)?
    private var pulse: (any TenantPulseProviding)?
    private var privileged: PrivilegedAccessService?

    /// The same app registration as the iPhone and iPad app, with this app's own redirect,
    /// which the registration's iOS / macOS platform must list for this bundle id.
    static let authConfiguration = AuthConfiguration(
        clientId: AuthConfiguration.vendorDefault.clientId,
        redirectUri: "msauth." + (Bundle.main.bundleIdentifier ?? "com.kainor.tenantkeep.menubar") + "://auth")

    var attention: Bool { !degraded.isEmpty || sessionProblem != nil }

    var results: [ManagedDeviceSummary] {
        Array(DeviceSearch.filter(devices, query: query).prefix(12))
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
        Task { await refreshAll() }
    }

    private func goLive(_ auth: MSALAuthManager, _ signed: AdminAccount) {
        mode = .live
        account = signed
        inventory = DeviceInventoryService(auth: auth, pageSize: 200)
        pulse = TenantPulseService(graph: GraphClient(auth: auth))
        privileged = PrivilegedAccessService(auth: auth)
        Task { await refreshAll() }
    }

    func refreshAll() async {
        await checkSession()
        async let a: Void = loadDevices()
        async let b: Void = loadRoles()
        async let c: Void = loadPulse()
        _ = await (a, b, c)
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
        guard let inventory else { return }
        devicesLoading = true
        defer { devicesLoading = false }
        do {
            await inventory.reset()
            _ = try await inventory.loadFirstPage()
            while try await inventory.hasMore() {
                _ = try await inventory.loadNextPage()
                devices = try await inventory.cachedDevices()
            }
            devices = try await inventory.cachedDevices()
            devicesError = nil
        } catch {
            devicesError = "Couldn't read the device list."
        }
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
