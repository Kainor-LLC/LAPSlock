import SwiftUI
import Combine
import CoreImage.CIFilterBuiltins
import RelayKit

// Relayed alerts, phase 4 step D, docs/RELAY-API.md. The phone's half of pairing with the
// customer's own TenantKeep Watch: turn on (a new Secure Enclave key and a push
// registration), show the pairing code for the Automation account, pin the sender code it
// prints, and turn off, which deletes the key so nothing sent to it can be read again.

@MainActor
final class RelayCoordinator: ObservableObject {
    static let shared = RelayCoordinator()

    @Published private(set) var isOn: Bool
    @Published private(set) var pairing: PairingCode?
    @Published private(set) var pinned: [String] = []
    @Published var problem: String?

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

    func turnOn() {
        problem = nil
        do {
            try phone.turnOn(environment: Self.environment)
            UIApplication.shared.registerForRemoteNotifications()
        } catch {
            problem = "Couldn't make the relay key on this phone."
        }
        reload()
    }

    func turnOff() {
        try? phone.turnOff()
        UIApplication.shared.unregisterForRemoteNotifications()
        reload()
    }

    /// From the app delegate, once APNs gives the phone a token.
    func registered(token: Data) {
        guard phone.isOn else { return }
        try? phone.setDeviceToken(token)
        reload()
    }

    func registrationFailed() {
        if phone.isOn { problem = "This phone couldn't register for push. Check that notifications are allowed." }
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
    /// a throwaway sender, and writes two pushes to the app group for `simctl push`: one
    /// sealed by that sender, one by an impostor.
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
            var results: [String] = []
            let seen = RelaySeenStore(url: nil)
            for (name, signer) in [("relay-test-good.json", sender), ("relay-test-impostor.json", P256.KeyAgreement.PrivateKey())] {
                let env = try RelayTestSender.seal(alert, to: key, deviceToken: code.deviceToken, sender: signer)
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
    @ObservedObject var relay = RelayCoordinator.shared
    let isPro: Bool
    let isDemo: Bool
    @State private var senderText = ""
    @State private var confirmingOff = false
    @State private var copied = false

    var body: some View {
        Section {
            if isDemo {
                Text("Relayed alerts pair this phone with TenantKeep Watch in your own Azure Automation account. Sign in to set them up.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else if !isPro {
                Text("Relayed alerts are part of Pro.").font(.footnote).foregroundStyle(.secondary)
            } else {
                Toggle("Relay alerts from TenantKeep Watch", isOn: Binding(
                    get: { relay.isOn },
                    set: { on in if on { relay.turnOn() } else { confirmingOff = true } }))
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
            Text("Off by default. Watch encrypts each alert for this phone in your own Automation account and sends it through Kainor's relay to Apple. Kainor cannot read it and keeps nothing; while it passes through, the relay sees your tenant ID, this phone's push token and the time. Turning this off deletes the key, so nothing sent to it can be read.")
        }
        .alert("Turn off relayed alerts?", isPresented: $confirmingOff) {
            Button("Turn off", role: .destructive) { relay.turnOff() }
            Button("Keep on", role: .cancel) {}
        } message: {
            Text("This phone's relay key is deleted. To turn it on again you pair with Watch again.")
        }
    }

    @ViewBuilder
    private var pairingRows: some View {
        if let pairing = relay.pairing {
            VStack(alignment: .leading, spacing: 8) {
                Text("1. Give this to TenantKeep Watch's setup").font(.subheadline.weight(.medium))
                if let image = Self.qr(pairing.text) {
                    Image(uiImage: image).interpolation(.none).resizable().scaledToFit().frame(maxWidth: 220)
                        .accessibilityLabel("Pairing code as a QR code")
                }
                Button {
                    UIPasteboard.general.string = pairing.text
                    copied = true
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
                Text("Registering this phone for push").font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    static func qr(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
