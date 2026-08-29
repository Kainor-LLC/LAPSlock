import Foundation
import UIKit
import DiagnosticsKit

// Packaging a diagnostic report for support.
//
// TWO EXPORT PATHS, on purpose:
//
//   1. Email (mailto:) — what you asked for. Opens the default mail app with the address,
//      subject, and body prefilled. The catch is that mailto URLs have practical length
//      limits (a couple of thousand characters before iOS or the mail client truncates),
//      and a full 200-event report blows straight past that. So the emailed body carries
//      the environment plus the most recent events only, and says so.
//
//   2. Share sheet — carries the COMPLETE report with no length limit, and lets someone
//      put it in Slack, Teams, Files, or a ticket instead of email.
//
// Both are offered because the person hitting a bug isn't always the person who emails
// support, and silently truncating someone's evidence would be the wrong default.

enum DiagnosticsExport {

    /// Where reports go. Change this alongside any support address change on the site.
    static let supportAddress = "connor@kainor.com"

    /// Events included in the emailed body. Enough to see a failure and what led to it,
    /// small enough to survive a mailto URL.
    static let emailedEventLimit = 40

    /// Environment facts. All non-identifying except the tenant id, which is opt-in.
    @MainActor
    static func environment(tenantId: String?) -> DiagnosticEnvironment {
        DiagnosticEnvironment(
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
            buildNumber: Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown",
            osVersion: "\(UIDevice.current.systemName) \(UIDevice.current.systemVersion)",
            deviceModel: hardwareIdentifier(),
            tenantId: tenantId
        )
    }

    /// The machine identifier ("iPhone16,1"), which is more useful for triage than the
    /// marketing name and doesn't identify a person.
    ///
    /// On the simulator `uname` returns the HOST architecture ("arm64"), which is both
    /// useless for triage and misleading — it looks like a device model. The simulator
    /// exposes the model it is pretending to be in an environment variable, so use that
    /// and label it plainly.
    static func hardwareIdentifier() -> String {
        let env = ProcessInfo.processInfo.environment
        if let simulated = env["SIMULATOR_MODEL_IDENTIFIER"] {
            return "\(simulated) (Simulator)"
        }

        var info = utsname()
        uname(&info)
        let raw = withUnsafePointer(to: &info.machine) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
        }
        if raw.isEmpty { return "unknown" }
        // Belt and braces: a bare architecture string means we're not on real hardware.
        if raw == "arm64" || raw == "x86_64" {
            return "\(raw) (Simulator)"
        }
        return raw
    }

    /// Builds a `mailto:` URL with the report prefilled.
    /// Returns nil if the URL can't be formed, so the caller can fall back to sharing.
    static func mailtoURL(subject: String, body: String) -> URL? {
        var comps = URLComponents()
        comps.scheme = "mailto"
        comps.path = supportAddress
        comps.queryItems = [
            URLQueryItem(name: "subject", value: subject),
            URLQueryItem(name: "body", value: body)
        ]
        return comps.url
    }

    static func subject(appVersion: String) -> String {
        "LAPSlock diagnostic report (\(appVersion))"
    }

    /// Trims a report to the most recent events and states plainly that it was trimmed,
    /// so nobody reading it assumes they have the whole picture.
    static func trimmedForEmail(_ full: String, limit: Int = emailedEventLimit) -> String {
        let lines = full.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        // Header runs up to and including the "Recent events" line.
        guard let eventsHeaderIndex = lines.firstIndex(where: { $0.hasPrefix("Recent events") }) else {
            return full
        }
        let header = lines[...eventsHeaderIndex]
        let events = lines[(eventsHeaderIndex + 1)...].filter { !$0.isEmpty }

        guard events.count > limit else { return full }

        let kept = events.suffix(limit)
        var out = Array(header)
        out.append("  (trimmed for email: showing the most recent \(limit) of \(events.count) events;")
        out.append("   use Share full report for the complete list)")
        out.append(contentsOf: kept)
        return out.joined(separator: "\n")
    }
}
