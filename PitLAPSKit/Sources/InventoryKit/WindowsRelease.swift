import Foundation

// Turns a Windows build number into the name admins actually use.
//
// "10.0.26100.2314" is precise and unmemorable. "Windows 11 24H2" is how people talk,
// compare fleets, and decide whether something is current. So the UI leads with the
// friendly name and keeps the build underneath, because the build is what you need when
// verifying a specific patch level.
//
// TWO DELIBERATE CONSTRAINTS
//
// 1. Graceful degradation. New Windows releases ship on their own schedule, and this
//    table is a snapshot. An unknown build returns nil and the UI falls back to showing
//    the raw version — never a wrong guess, never a crash. Adding a release later is one
//    line here.
//
// 2. No Server claims from ambiguous builds. Several builds are shared between client
//    and Server (26100 is both Windows 11 24H2 and Server 2025), and the Intune
//    `operatingSystem` field says only "Windows" for both. Where a build is
//    unambiguously Server, it's named as Server. Where it's shared, the client name is
//    used, because Intune-managed fleets are overwhelmingly clients — and the raw build
//    stays on screen so an admin can always tell.

public enum WindowsRelease {

    /// Build number → release name. Builds are the fourth component of the version
    /// string's `10.0.BUILD.revision` form.
    private static let names: [Int: String] = [
        // Windows 11
        26200: "Windows 11 25H2",
        26100: "Windows 11 24H2",
        22631: "Windows 11 23H2",
        22621: "Windows 11 22H2",
        22000: "Windows 11 21H2",

        // Windows 10
        19045: "Windows 10 22H2",
        19044: "Windows 10 21H2",
        19043: "Windows 10 21H1",
        19042: "Windows 10 20H2",
        19041: "Windows 10 2004",
        18363: "Windows 10 1909",
        18362: "Windows 10 1903",
        17763: "Windows 10 1809",
        16299: "Windows 10 1709",
        15063: "Windows 10 1703",
        14393: "Windows 10 1607",

        // Server builds with no client counterpart
        25398: "Windows Server 23H2",
        20348: "Windows Server 2022"
    ]

    /// Parses the build number out of an Intune `osVersion` string.
    /// Accepts "10.0.26100.2314", "10.0.26100", and tolerates surrounding whitespace.
    public static func buildNumber(from osVersion: String?) -> Int? {
        guard let osVersion else { return nil }
        let parts = osVersion
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: ".")
        // 10 . 0 . BUILD [. revision]
        guard parts.count >= 3, let build = Int(parts[2]) else { return nil }
        return build
    }

    /// The friendly release name, or nil when the build isn't in the table.
    /// Nil is a normal outcome, not an error: it means "show the raw version".
    public static func friendlyName(osVersion: String?) -> String? {
        guard let build = buildNumber(from: osVersion) else { return nil }
        if let exact = names[build] { return exact }

        // Unknown build: still worth distinguishing the major generation, since the
        // 22000 boundary is well established and unlikely to move.
        if build >= 22000 { return "Windows 11" }
        if build >= 10240 { return "Windows 10" }
        return nil
    }

    /// True when the name came from the table rather than the generation fallback.
    /// The UI uses this to decide whether the raw build adds information worth showing.
    public static func isExactMatch(osVersion: String?) -> Bool {
        guard let build = buildNumber(from: osVersion) else { return false }
        return names[build] != nil
    }
}
