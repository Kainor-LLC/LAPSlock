#if DEBUG
import SwiftUI
import UIKit
import AuthKit
import AuthKitMSAL

// LAPSlock-internal CAE-PLAN.md, step 0. Debug builds only, on the branch cae-measure,
// which is never merged and never uploaded.
//
// It times what declaring continuous access evaluation changes: how long a token lasts,
// how long Microsoft Graph keeps taking one after a revoke, a blocked sign-in or a role
// that ended, and what the app's own session check is told. Launch arguments:
//
//   -LAPSlockCAE              declares the capability (CP1) on the registrations that call Graph
//   -LAPSlockNoSessionCheck   the app's ten-minute check stays off, so Graph's answer is timed
//
// Every line starts "[CAE]" so the console can be filtered. A token's claims that matter
// here are printed: its lifetime, whether Microsoft marked it for continuous access
// evaluation (xms_cc), the directory roles it carries (wids) and its authentication
// contexts (acrs). Never the token, and no claim that names the person or the tenant.

@MainActor
@Observable
final class TokenMeasurement {
    static let shared = TokenMeasurement()

    private(set) var lines: [String] = []
    private(set) var everyMinute = false
    @ObservationIgnored private var loop: Task<Void, Never>?
    /// The app's own session check, asked now and acted on. Set by the root model.
    @ObservationIgnored var checkSession: (() async -> SessionStanding?)?

    /// The sign-in permission behind the device read, and the read itself.
    static let deviceScopes = ["Device.Read.All"]
    /// The sign-in log, which needs a directory role as well as the permission: Reports
    /// Reader at least, Microsoft's page says (List signIns, read 2026-11-24).
    static let signInScopes = ["AuditLog.Read.All"]
    /// Reports Reader's template ID, from Microsoft's built-in roles page.
    static let reportsReader = "4a5d8f65-41da-4de4-8968-e035b65339cf"

    enum Read {
        case devices, signIns

        var name: String { self == .devices ? "devices" : "sign-in log" }
        var scopes: [String] { self == .devices ? TokenMeasurement.deviceScopes : TokenMeasurement.signInScopes }
        var url: URL {
            URL(string: self == .devices
                ? "https://graph.microsoft.com/v1.0/devices?$top=1&$select=id"
                : "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1&$select=id")!
        }
    }

    var declared: Bool { ProcessInfo.processInfo.arguments.contains("-LAPSlockCAE") }
    var checkOff: Bool { ProcessInfo.processInfo.arguments.contains("-LAPSlockNoSessionCheck") }

    private static let session = URLSession(configuration: .ephemeral)
    private static let clock: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()

    func say(_ text: String) {
        let line = "[CAE] " + Self.clock.string(from: Date()) + " " + text
        print(line)
        lines.insert(line, at: 0)
        if lines.count > 40 { lines.removeLast(lines.count - 40) }
    }

    func started() {
        say("build: capability " + (declared ? "declared (CP1)" : "not declared") + ", session check " + (checkOff ? "off" : "on"))
    }

    /// A forced refresh, and what the new token carries. For each read's permission, since
    /// the sign-in library keeps a token for each set of permissions asked for, and the
    /// reads that follow must use the new one.
    func freshToken() async {
        guard let auth = SessionAuth.shared.auth else { return say("no sign-in manager") }
        for read in [Read.devices, .signIns] {
            do {
                let token = try await auth.measurementToken(scopes: read.scopes, fresh: true)
                say("fresh token for the " + read.name + ": " + Self.describe(token))
            } catch {
                say("fresh token for the " + read.name + " refused: " + Self.describe(error, detail: await auth.lastAuthFailure))
            }
        }
    }

    /// One Graph read with whatever token MSAL has cached.
    func read(_ what: Read) async {
        guard let auth = SessionAuth.shared.auth else { return say("no sign-in manager") }
        let token: String
        do {
            token = try await auth.measurementToken(scopes: what.scopes, fresh: false)
        } catch {
            return say(what.name + ": no token, " + Self.describe(error, detail: await auth.lastAuthFailure))
        }
        var request = URLRequest(url: what.url)
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        do {
            let (_, response) = try await Self.session.data(for: request)
            guard let http = response as? HTTPURLResponse else { return say(what.name + ": no HTTP answer") }
            var line = what.name + " " + String(http.statusCode) + ", token left " + Self.timeLeft(token)
            if what == .signIns { line += ", Reports Reader in token " + (Self.roles(token).contains(Self.reportsReader) ? "yes" : "no") }
            if http.statusCode == 401, let challenge = http.value(forHTTPHeaderField: "WWW-Authenticate") {
                line += ", " + Self.challenge(challenge)
            }
            say(line)
        } catch {
            say(what.name + ": " + error.localizedDescription)
        }
    }

    /// The app's own check, asked now even with the switch off, and acted on as it would be.
    func sessionCheck() async {
        guard let check = checkSession else { return say("session check: not wired") }
        guard let standing = await check() else { return say("session check: not signed in") }
        say("session check: " + String(describing: standing))
    }

    func setEveryMinute(_ on: Bool) {
        everyMinute = on
        loop?.cancel()
        loop = nil
        // The phone stays awake while it runs, so nobody has to change Auto-Lock.
        UIApplication.shared.isIdleTimerDisabled = on
        guard on else { return say("every minute: off") }
        say("every minute: on")
        loop = Task { [weak self] in
            while !Task.isCancelled {
                await self?.read(.devices)
                await self?.read(.signIns)
                try? await Task.sleep(for: .seconds(60))
            }
        }
    }

    // MARK: - reading a token without printing it

    static func claims(of token: String) -> [String: Any]? {
        let parts = token.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        var text = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while text.count % 4 != 0 { text += "=" }
        guard let data = Data(base64Encoded: text) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    static func roles(_ token: String) -> [String] {
        (claims(of: token)?["wids"] as? [String]) ?? []
    }

    static func describe(_ token: String) -> String {
        guard let claims = claims(of: token) else { return "not a token that can be read" }
        let issued = (claims["iat"] as? NSNumber)?.doubleValue ?? 0
        let expires = (claims["exp"] as? NSNumber)?.doubleValue ?? 0
        let marked = (claims["xms_cc"] as? [String])?.joined(separator: ",") ?? "none"
        let wids = roles(token)
        let contexts = (claims["acrs"] as? [String])?.joined(separator: ",") ?? "none"
        return "lifetime " + duration(expires - issued) + ", left " + timeLeft(token)
            + ", xms_cc " + marked
            + ", roles " + String(wids.count) + (wids.contains(reportsReader) ? " (Reports Reader among them)" : "")
            + ", acrs " + contexts
    }

    static func timeLeft(_ token: String) -> String {
        guard let expires = (claims(of: token)?["exp"] as? NSNumber)?.doubleValue else { return "unknown" }
        return duration(expires - Date().timeIntervalSince1970)
    }

    static func duration(_ seconds: TimeInterval) -> String {
        let minutes = Int((seconds / 60).rounded())
        return String(minutes / 60) + "h" + String(format: "%02d", abs(minutes % 60)) + "m"
    }

    /// `error="insufficient_claims"` and whether claims came with it. The claims themselves
    /// are a challenge for the sign-in library, not something to print.
    static func challenge(_ header: String) -> String {
        let error = header.range(of: #"error="[^"]*""#, options: .regularExpression).map { String(header[$0]) } ?? "no error named"
        return error + (header.contains("claims=") ? ", with claims" : ", no claims")
    }

    static func describe(_ error: Error, detail: AuthFailureDetail?) -> String {
        let code = detail?.aadErrorCode ?? "no AADSTS code"
        let msal = detail?.msalErrorCode.map { "msal " + String($0) } ?? "no msal code"
        return String(describing: error) + ", " + code + ", " + msal + ", " + (detail?.oauthError ?? "no oauth error")
    }
}

/// The rows in Settings, Debug.
struct TokenMeasurementRows: View {
    @State private var model = TokenMeasurement.shared

    var body: some View {
        LabeledContent("Capability", value: model.declared ? "CP1 declared" : "Not declared")
        LabeledContent("Session check", value: model.checkOff ? "Off" : "On")
        Button("Fresh token") { Task { await model.freshToken() } }
        Button("Devices now") { Task { await model.read(.devices) } }
        Button("Sign-in log now") { Task { await model.read(.signIns) } }
        Button("Session check now") { Task { await model.sessionCheck() } }
        Toggle("Every minute", isOn: Binding(get: { model.everyMinute }, set: { model.setEveryMinute($0) }))
        ForEach(Array(model.lines.prefix(8).enumerated()), id: \.offset) { _, line in
            Text(line).font(.caption2.monospaced()).textSelection(.enabled)
        }
    }
}
#endif
