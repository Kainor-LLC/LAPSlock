import SwiftUI
import UserNotifications
import RelayKit

// Instant alerts, hosted by Kainor (HOSTED-WATCH-PLAN.md, H4). An administrator turns them
// on, reads what they share, and the phone registers itself with Kainor's alert service:
// a new Secure Enclave key, a push registration, then one request carrying the push
// address, the public key and the break-glass accounts set in Notifications, signed with a
// Microsoft token for the On-Call app's Alerts.Register scope. The answer is the watcher's
// sender key, pinned for the organization, so the extension can open what it sends. An
// organization that has not approved TenantKeep Watch gets the approval link instead.
// Turning off unregisters and deletes the key, so nothing sent to it can be read.
//
// Replaces relayed alerts from the customer's own Automation account (retired 2026-10-29):
// no codes to copy.

/// What the root gives the coordinator for a signed-in organization. Nil in demo and when
/// signed out.
struct InstantAlertsSetup {
    /// A Microsoft token for Alerts.Register. Interactive only when the person asked for it.
    let token: @MainActor (_ interactive: Bool) async throws -> String
    /// The break-glass accounts set for this organization under Notifications.
    let breakGlass: @MainActor () -> [String]
}

@MainActor
@Observable
final class RelayCoordinator {
    static let shared = RelayCoordinator()

    enum Status: Equatable {
        case off
        case working(String)
        case on(label: String, accounts: Int, canConfigure: Bool)
        case needsApproval(URL)
        case problem(String)
    }

    private(set) var status: Status = .off
    var problem: String? {
        if case .problem(let text) = status { return text }
        return nil
    }
    @ObservationIgnored var setup: InstantAlertsSetup?

    let phone: RelayPhone

    static let endpoint = URL(string: "https://kainor-watch-prod-func.azurewebsites.net/api/v1/devices")!
    private static let stateKey = "instantAlerts.state"
    private static let checkInKey = "instantAlerts.lastCheckIn"

    static var environment: String {
        #if DEBUG
        return "sandbox"
        #else
        return "production"
        #endif
    }

    private struct Saved: Codable {
        var label: String
        var accounts: Int
        var canConfigure: Bool
    }

    private init() {
        let prefix = (Bundle.main.object(forInfoDictionaryKey: "TKAppIdentifierPrefix") as? String).flatMap { $0.isEmpty || $0.contains("$(") ? nil : $0 }
        phone = RelayPhone(store: KeychainRelayStateStore(teamPrefix: prefix))
        if phone.isOn, !phone.pinnedTenants().isEmpty,
           let data = UserDefaults.standard.data(forKey: Self.stateKey),
           let saved = try? JSONDecoder().decode(Saved.self, from: data) {
            status = .on(label: saved.label, accounts: saved.accounts, canConfigure: saved.canConfigure)
        }
    }

    var isOn: Bool { status != .off }
    var isRegistered: Bool { if case .on = status { return true }; return false }

    /// At every launch, as Apple asks: a token can change, and a registration that failed
    /// or whose callback was missed otherwise never happens again.
    func registerIfOn() {
        guard phone.isOn else { return }
        UIApplication.shared.registerForRemoteNotifications()
    }

    /// The person turned Instant alerts on, after reading what they share.
    func turnOn() async {
        guard let setup else {
            status = .problem("Sign in to your organization to turn on Instant alerts.")
            return
        }
        status = .working("Registering this phone")
        do {
            if !phone.isOn { try phone.turnOn(environment: Self.environment) }
        } catch {
            status = .problem("Couldn't make the alert key on this device.")
            return
        }
        UIApplication.shared.registerForRemoteNotifications()
        guard let code = await pairingCode() else {
            status = .problem("Apple didn't give this phone a push address. Check that notifications are allowed for TenantKeep, then try again.")
            return
        }
        await register(code, setup: setup, interactive: true)
    }

    /// Update: the break-glass accounts changed, or after the organization approved.
    func update() async {
        guard let setup, let code = try? phone.pairingCode() else { return await turnOn() }
        status = .working("Updating")
        await register(code, setup: setup, interactive: true)
    }

    func turnOff() async {
        if let setup, let code = try? phone.pairingCode(), let token = try? await setup.token(false) {
            var request = URLRequest(url: Self.endpoint)
            request.httpMethod = "DELETE"
            request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try? JSONEncoder().encode(["deviceToken": code.deviceToken])
            _ = try? await URLSession.shared.data(for: request)
        }
        try? phone.turnOff()
        UIApplication.shared.unregisterForRemoteNotifications()
        UserDefaults.standard.removeObject(forKey: Self.stateKey)
        UserDefaults.standard.removeObject(forKey: Self.checkInKey)
        status = .off
    }

    /// From the app delegate, once APNs gives the phone a token. A new token, or a day since
    /// the last check-in, registers again quietly, so the service keeps a live address and
    /// does not delete the phone after 30 days.
    func registered(token: Data) {
        guard phone.isOn else { return }
        let changed = (try? phone.setDeviceToken(token)) == true
        let last = UserDefaults.standard.object(forKey: Self.checkInKey) as? Date ?? .distantPast
        guard isRegistered, changed || Date().timeIntervalSince(last) > 86_400,
              let setup, let code = try? phone.pairingCode() else { return }
        Task { await register(code, setup: setup, interactive: false, quiet: true) }
    }

    func registrationFailed() {
        if phone.isOn, !isRegistered { status = .problem("This device couldn't register for push. Check that notifications are allowed.") }
    }

    /// The push address, once APNs has given one: up to twenty seconds after registering.
    private func pairingCode() async -> PairingCode? {
        for _ in 0..<40 {
            if let code = try? phone.pairingCode() { return code }
            try? await Task.sleep(for: .milliseconds(500))
        }
        return nil
    }

    private func register(_ code: PairingCode, setup: InstantAlertsSetup, interactive: Bool, quiet: Bool = false) async {
        let token: String
        do {
            token = try await setup.token(interactive)
        } catch {
            if !quiet { status = .problem("Couldn't get permission from Microsoft to register this phone. Try again, or sign in again.") }
            return
        }
        var request = URLRequest(url: Self.endpoint)
        request.httpMethod = "POST"
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let accounts = setup.breakGlass()
        request.httpBody = try? JSONEncoder().encode(InstantAlertsRegistration(code: code, breakGlass: accounts.isEmpty ? nil : accounts))
        let answer: InstantAlertsAnswer
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            answer = InstantAlertsAnswer.parse(status: (response as? HTTPURLResponse)?.statusCode ?? 0, body: data)
        } catch {
            if !quiet { status = .problem("Couldn't reach Kainor's alert service. Check your connection and try again.") }
            return
        }
        switch answer {
        case .registered(let tenantId, let label, let senderKey, let count, let canConfigure):
            do {
                try phone.pin(SenderPin(tenant: tenantId, senderKey: senderKey))
            } catch {
                status = .problem("Couldn't save the alert service's key on this device.")
                return
            }
            let saved = Saved(label: label, accounts: count, canConfigure: canConfigure)
            UserDefaults.standard.set(try? JSONEncoder().encode(saved), forKey: Self.stateKey)
            UserDefaults.standard.set(Date(), forKey: Self.checkInKey)
            status = .on(label: label, accounts: count, canConfigure: canConfigure)
        case .needsApproval(let url):
            status = .needsApproval(url)
        case .notPermitted:
            status = .problem("Your account needs an active Global Administrator, Security Administrator, Security Operator, Security Reader or Global Reader role. If yours is eligible in PIM, activate it first.")
        case .accountNotFound:
            status = .problem("A break-glass account set under Notifications isn't in this organization. Check the addresses and try again.")
        case .failed(let code):
            if !quiet { status = .problem("Kainor's alert service answered \(code). Try again shortly.") }
        }
    }

    /// A relayed alert that arrived before the phone was unlocked after a restart, opened on
    /// its tap. Shown again as a local notification with its real content, so it reads like
    /// any other alert, and returned so the tap can be routed. Same key, same pinned senders
    /// and the same one-day repeat check as the extension.
    func openDeferred(enc: String, ct: String) async -> RelayAlert? {
        let seenURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.kainor.lapslock")?
            .appendingPathComponent("relay-seen.json")
        guard let alert = try? phone.open(enc: enc, ct: ct, seen: RelaySeenStore(url: seenURL)) else { return nil }
        let content = UNMutableNotificationContent()
        content.title = alert.title
        content.body = alert.body
        if let late = alert.lateness() { content.subtitle = late }
        content.threadIdentifier = "relay-" + alert.tenant
        var info: [String: Any] = ["tenantId": alert.tenant, "relayKind": alert.kind]
        if let link = alert.link { info["link"] = link }
        content.userInfo = info
        try? await UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: "relay-" + alert.id, content: content, trigger: nil))
        return alert
    }

    #if DEBUG
    /// The self test pins a throwaway sender; reloads what the section shows.
    func reload() {}
    #endif
}

#if DEBUG
import CryptoKit
import UserNotifications

extension RelayCoordinator {
    /// Debug builds only: `-LAPSlockRelaySelfTest` turns the relay on with a fixed token, pins
    /// a throwaway sender, and writes three pushes to the app group for `simctl push`: one
    /// sealed by that sender, one by an impostor, and one the sender raised fifteen minutes
    /// ago, which the phone shows with its age.
    func runSelfTestIfAsked() {
        guard CommandLine.arguments.contains("-LAPSlockRelaySelfTest"),
              let folder = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.kainor.lapslock") else { return }
        do {
            try phone.turnOn(environment: "sandbox")
            try phone.setDeviceToken(Data((0..<32).map { UInt8($0) }))
            let sender = P256.KeyAgreement.PrivateKey()
            let tenant = "c0ffee00-1111-2222-3333-444455556666"
            try phone.pin(SenderPin(tenant: tenant, senderKey: sender.publicKey.x963Representation))
            let code = try phone.pairingCode()
            let key = Data(base64URL: code.publicKey) ?? Data()
            let alert = RelayAlert(v: 1, id: UUID().uuidString, at: Int(Date().timeIntervalSince1970), tenant: tenant, kind: "breakGlassSignIn",
                                   title: "Contoso: break-glass sign-in", body: "bg-admin signed in from 203.0.113.7", link: "tenantkeep://people")
            var late = alert
            late.id = UUID().uuidString
            late.at -= 15 * 60
            var results: [String] = []
            let seen = RelaySeenStore(url: nil)
            for (name, signer, sent) in [("relay-test-good.json", sender, alert),
                                         ("relay-test-impostor.json", P256.KeyAgreement.PrivateKey(), alert),
                                         ("relay-test-late.json", sender, late)] {
                let env = try RelayTestSender.seal(sent, to: key, deviceToken: code.deviceToken, sender: signer)
                let payload: [String: Any] = ["aps": ["alert": ["title": "TenantKeep alert", "body": "Open TenantKeep"], "mutable-content": 1],
                                              "e": ["enc": env.enc, "ct": env.ct]]
                try JSONSerialization.data(withJSONObject: payload).write(to: folder.appendingPathComponent(name))
                // The same open the extension does, here in the app, through the Keychain item.
                for attempt in 1...2 {
                    do {
                        let opened = try phone.open(enc: env.enc, ct: env.ct, seen: seen)
                        results.append(name + " try " + String(attempt) + ": opened \"" + opened.title + "\"")
                    } catch {
                        results.append(name + " try " + String(attempt) + ": refused " + String(describing: error))
                    }
                }
            }
            try results.joined(separator: "\n").write(to: folder.appendingPathComponent("relay-test-results.txt"), atomically: true, encoding: .utf8)
        } catch {
            status = .problem("Self-test failed: " + String(describing: error))
        }
        reload()
        Task { _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) }
    }
}

private extension Data {
    init?(base64URL: String) {
        var s = base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s.append("=") }
        self.init(base64Encoded: s)
    }
}
#endif

struct RelaySettingsSection: View {
    let relay = RelayCoordinator.shared
    let isPro: Bool
    let isDemo: Bool
    @State private var confirmingOn = false
    @State private var confirmingOff = false

    var body: some View {
        Section {
            if isDemo {
                Text("Instant alerts come from Kainor's alert service to a signed-in organization's phones. Sign in to turn them on.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else if !isPro {
                Text("Instant alerts are part of Pro.").font(.footnote).foregroundStyle(.secondary)
            } else {
                Toggle(isOn: Binding(
                    get: { relay.isOn },
                    set: { on in if on { confirmingOn = true } else { confirmingOff = true } })) {
                    Text("Instant alerts")
                    Text("Break-glass sign-ins, within minutes")
                }
                .disabled(isWorking)
                // On the row that asks, not the Section: a Section's modifiers are copied
                // onto each of its rows, and the copies race to present.
                .alert("Turn On Instant Alerts?", isPresented: $confirmingOn) {
                    Button("Turn on") { Task { await relay.turnOn() } }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("Kainor's alert service will read your organization's sign-in log for the break-glass accounts you name, with read-only access your organization approves once, and alert this phone within minutes. It keeps identifiers only, never names, addresses or log content, and encrypts every alert for this phone. The privacy policy has the details.")
                }
                .alert("Turn Off Instant Alerts?", isPresented: $confirmingOff) {
                    Button("Turn off", role: .destructive) { Task { await relay.turnOff() } }
                    Button("Keep on", role: .cancel) {}
                } message: {
                    Text("This phone is removed from Kainor's alert service and its alert key is deleted.")
                }
                statusRows
            }
        } header: {
            Text("Instant Alerts")
        } footer: {
            Text("Off by default. Part of Pro. The break-glass accounts are the ones set for your organization under Notifications above. Your organization can remove TenantKeep Watch in Microsoft Entra ID at any time, which stops all reading.")
        }
    }

    private var isWorking: Bool {
        if case .working = relay.status { return true }
        return false
    }

    @ViewBuilder
    private var statusRows: some View {
        switch relay.status {
        case .off:
            EmptyView()
        case .working(let text):
            HStack(spacing: 8) {
                ProgressView()
                Text(text).font(.footnote).foregroundStyle(.secondary)
            }
        case .on(let label, let accounts, let canConfigure):
            Label("On for " + label, systemImage: "checkmark.circle")
                .font(.footnote)
            Text(accounts == 0
                 ? "No break-glass accounts are watched yet. Add them under Notifications for your organization, then tap Update."
                 : accounts == 1 ? "Watching 1 break-glass account." : "Watching \(accounts) break-glass accounts.")
                .font(.footnote).foregroundStyle(.secondary)
            if !canConfigure {
                Text("Only a Global Administrator or Security Administrator can change which accounts are watched.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Button("Update") { Task { await relay.update() } }
        case .needsApproval(let url):
            Text("Your organization needs to approve TenantKeep Watch once. Only a Global Administrator or Privileged Role Administrator can.")
                .font(.footnote)
            Link(destination: url) {
                Label("Open the approval page", systemImage: "arrow.up.right.square")
            }
            ShareLink(item: url) {
                Label("Send the link to an administrator", systemImage: "square.and.arrow.up")
            }
            Button("Check again") { Task { await relay.update() } }
        case .problem(let text):
            Text(text).font(.footnote).foregroundStyle(.red)
            Button("Try again") { Task { await relay.update() } }
        }
    }
}
