import SwiftUI
import CoreImage.CIFilterBuiltins
import UserNotifications
import RelayKit

// Relayed alerts, phase 4 step D, docs/RELAY-API.md. The phone's half of pairing with the
// customer's own TenantKeep Watch: turn on (a new Secure Enclave key and a push
// registration), show the pairing code for the Automation account, pin the sender code it
// prints, and turn off, which deletes the key so nothing sent to it can be read again.

@MainActor
@Observable
final class RelayCoordinator {
    static let shared = RelayCoordinator()

    private(set) var isOn: Bool
    private(set) var pairing: PairingCode?
    private(set) var pinned: [String] = []
    @ObservationIgnored private var qrCache: (text: String, image: UIImage?)?

    /// The pairing code as a QR image, made once per code rather than on every redraw of
    /// Settings, which included each keystroke in the sender code field.
    var pairingImage: UIImage? {
        guard let text = pairing?.text else { return nil }
        if let cached = qrCache, cached.text == text { return cached.image }
        let image = RelaySettingsSection.qr(text)
        qrCache = (text, image)
        return image
    }
    var problem: String?
    /// APNs gave this phone a different token since Watch was paired. Every envelope is
    /// bound to the token, so until Watch has the new pairing code nothing it sends arrives.
    /// Kept until the new code is copied, across launches.
    private(set) var pairingOutOfDate = UserDefaults.standard.bool(forKey: RelayCoordinator.outOfDateKey)

    static let outOfDateKey = "relay.pairingOutOfDate"

    let phone: RelayPhone

    static var environment: String {
        #if DEBUG
        return "sandbox"
        #else
        return "production"
        #endif
    }

    private init() {
        let prefix = (Bundle.main.object(forInfoDictionaryKey: "TKAppIdentifierPrefix") as? String).flatMap { $0.isEmpty || $0.contains("$(") ? nil : $0 }
        phone = RelayPhone(store: KeychainRelayStateStore(teamPrefix: prefix))
        isOn = phone.isOn
        reload()
    }

    func reload() {
        isOn = phone.isOn
        pairing = try? phone.pairingCode()
        pinned = phone.pinnedTenants()
    }

    /// At every launch, as Apple asks: a token can change, and a registration that failed
    /// or whose callback was missed otherwise never happens again.
    func registerIfOn() {
        guard phone.isOn else { return }
        UIApplication.shared.registerForRemoteNotifications()
    }

    func turnOn() {
        problem = nil
        setPairingOutOfDate(false)
        do {
            try phone.turnOn(environment: Self.environment)
            UIApplication.shared.registerForRemoteNotifications()
        } catch {
            problem = "Couldn't make the relay key on this device."
        }
        reload()
    }

    func turnOff() {
        setPairingOutOfDate(false)
        try? phone.turnOff()
        UIApplication.shared.unregisterForRemoteNotifications()
        reload()
    }

    /// From the app delegate, once APNs gives the phone a token.
    func registered(token: Data) {
        guard phone.isOn else { return }
        if (try? phone.setDeviceToken(token)) == true { setPairingOutOfDate(true) }
        reload()
    }

    /// The new pairing code was copied to give to Watch.
    func pairingCodeCopied() {
        setPairingOutOfDate(false)
    }

    private func setPairingOutOfDate(_ value: Bool) {
        pairingOutOfDate = value
        UserDefaults.standard.set(value, forKey: Self.outOfDateKey)
    }

    /// A relayed alert that arrived before the phone was unlocked after a restart, opened on
    /// its tap. Shown again as a local notification with its real content, so it reads like
    /// any other relayed alert, and returned so the tap can be routed. Same key, same pinned
    /// senders and the same one-day repeat check as the extension.
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

    func registrationFailed() {
        if phone.isOn { problem = "This device couldn't register for push. Check that notifications are allowed." }
    }

    func pin(_ text: String) -> Bool {
        guard let pin = SenderPin.parse(text) else {
            problem = "That isn't a sender code from TenantKeep Watch. It starts tksender1:."
            return false
        }
        do {
            try phone.pin(pin)
            problem = nil
            reload()
            return true
        } catch {
            problem = "Couldn't save the sender code."
            return false
        }
    }
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
            problem = "Self-test failed: " + String(describing: error)
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
    @State private var senderText = ""
    @State private var confirmingOff = false
    @State private var copied = false

    var body: some View {
        Section {
            if isDemo {
                Text("Relayed alerts pair this device with TenantKeep Watch in your own Azure Automation account. Sign in to set them up.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else if !isPro {
                Text("Relayed alerts are part of Pro.").font(.footnote).foregroundStyle(.secondary)
            } else {
                Toggle("Relay alerts from TenantKeep Watch", isOn: Binding(
                    get: { relay.isOn },
                    set: { on in if on { relay.turnOn() } else { confirmingOff = true } }))
                    // On the row that asks, not the Section: a Section's modifiers are copied
                    // onto each of its rows, and the copies race to present.
                    .alert("Turn off relayed alerts?", isPresented: $confirmingOff) {
                        Button("Turn off", role: .destructive) { relay.turnOff() }
                        Button("Keep on", role: .cancel) {}
                    } message: {
                        Text("This device's relay key is deleted. To turn it on again you pair with Watch again.")
                    }
                if relay.isOn {
                    pairingRows
                }
                if let problem = relay.problem {
                    Text(problem).font(.footnote).foregroundStyle(.red)
                }
            }
        } header: {
            Text("Relayed Alerts")
        } footer: {
            Text("Off by default. Watch encrypts each alert for this device in your own Automation account and sends it through Kainor's relay to Apple. Kainor cannot read it and keeps nothing; while it passes through, the relay sees your tenant ID, this device's push token and the time. Turning this off deletes the key, so nothing sent to it can be read.")
        }
    }

    @ViewBuilder
    private var pairingRows: some View {
        if let pairing = relay.pairing {
            if relay.pairingOutOfDate {
                Label("This device's push address changed. Give TenantKeep Watch the new pairing code below, or relayed alerts will not arrive.",
                      systemImage: "exclamationmark.triangle")
                    .font(.footnote)
                    .foregroundStyle(.orange)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("1. Give this to TenantKeep Watch's setup").font(.subheadline.weight(.medium))
                if let image = relay.pairingImage {
                    Image(uiImage: image).interpolation(.none).resizable().scaledToFit().frame(maxWidth: 220)
                        .accessibilityLabel("Pairing code as a QR code")
                }
                Button {
                    UIPasteboard.general.string = pairing.text
                    copied = true
                    relay.pairingCodeCopied()
                } label: {
                    Label(copied ? "Copied" : "Copy pairing code", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.bordered)
            }
            .padding(.vertical, 4)
            VStack(alignment: .leading, spacing: 6) {
                Text("2. Paste the sender code it prints").font(.subheadline.weight(.medium))
                TextField("tksender1:…", text: $senderText, axis: .vertical)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.footnote.monospaced())
                Button("Pin sender") {
                    if relay.pin(senderText) { senderText = "" }
                }
                .disabled(senderText.isEmpty)
            }
            .padding(.vertical, 4)
            if !relay.pinned.isEmpty {
                LabeledContent("Senders pinned", value: String(relay.pinned.count))
                ForEach(relay.pinned, id: \.self) { tenant in
                    Text(tenant).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
        } else {
            HStack(spacing: 8) {
                ProgressView()
                Text("Registering this device for push").font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    static func qr(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = context.createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cg)
    }

    /// One for the process: a CIContext is costly to make and safe to reuse.
    private static let context = CIContext()
}
