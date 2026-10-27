import XCTest
import Foundation

/// The Graph change watch (phase 3 step J) only watches what scripts/graph-watch/manifest.json
/// lists. This keeps that list honest: every Graph path written in a Kit's source must be
/// covered by a manifest entry, so a new call cannot ship unwatched.
final class GraphManifestTests: XCTestCase {

    private static let roots = [
        "users", "me", "deviceManagement", "directory", "directoryObjects", "directoryRoleTemplates",
        "identity", "identityProtection", "identityGovernance", "security", "admin", "auditLogs",
        "servicePrincipals", "applications", "roleManagement", "policies", "informationProtection",
        "groups", "organization", "reports", "subscribedSkus", "domains", "devices"
    ]

    private var packageRoot: URL {
        // Tests/AuthKitTests/this file -> LAPSlockKit
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    /// Placeholders and interpolations become one token; the API version prefix goes.
    private func normalize(_ path: String) -> String {
        var p = path
        for version in ["/v1.0/", "/beta/"] where p.hasPrefix(version) { p = "/" + p.dropFirst(version.count) }
        if let q = p.firstIndex(of: "?") { p = String(p[..<q]) }
        p = p.replacingOccurrences(of: #"\{[^}]*\}"#, with: "{x}", options: .regularExpression)
        p = p.replacingOccurrences(of: #"\\\([^)]*\)"#, with: "{x}", options: .regularExpression)
        p = p.replacingOccurrences(of: #"\([^)]*\)"#, with: "", options: .regularExpression)
        return p
    }

    private func manifestPaths() throws -> [String] {
        let url = packageRoot.deletingLastPathComponent().appendingPathComponent("scripts/graph-watch/manifest.json")
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        let calls = try XCTUnwrap(json?["calls"] as? [[String: Any]])
        return calls.compactMap { $0["path"] as? String }.map(normalize)
    }

    private func sourcePaths() throws -> [(file: String, path: String)] {
        let sources = packageRoot.appendingPathComponent("Sources")
        let alternation = Self.roots.joined(separator: "|")
        let regex = try NSRegularExpression(pattern: "\"(/(?:v1\\.0/|beta/)?(?:" + alternation + ")(?:[/?(][^\"]*)?)\"")
        var found: [(String, String)] = []
        let files = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil)
        while let file = files?.nextObject() as? URL {
            guard file.pathExtension == "swift", !file.lastPathComponent.hasPrefix("Demo") else { continue }
            let text = try String(contentsOf: file, encoding: .utf8)
            for line in text.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("//") || trimmed.hasPrefix("///") { continue }
                let range = NSRange(line.startIndex..., in: line)
                for match in regex.matches(in: line, range: range) {
                    if let r = Range(match.range(at: 1), in: line) {
                        found.append((file.lastPathComponent, String(line[r])))
                    }
                }
            }
        }
        return found
    }

    func testEveryGraphPathInTheKitsIsInTheManifest() throws {
        let manifest = try manifestPaths()
        let paths = try sourcePaths()
        XCTAssertGreaterThan(paths.count, 30, "the source scan found too little; the pattern is probably broken")
        var missing: [String] = []
        for (file, raw) in paths {
            let path = normalize(raw)
            // A literal that is the start of a longer path built by concatenation counts when
            // a manifest path starts with it.
            let covered = manifest.contains { $0 == path || $0.hasPrefix(path) }
            if !covered { missing.append(file + ": " + raw) }
        }
        XCTAssertTrue(missing.isEmpty, "Graph paths not in scripts/graph-watch/manifest.json, so the change watch cannot see them:\n" + missing.joined(separator: "\n"))
    }

    func testTheScanCatchesAnUnlistedPath() throws {
        let manifest = try manifestPaths()
        XCTAssertFalse(manifest.contains { $0.hasPrefix(normalize("/teams/{id}/channels")) })
        XCTAssertTrue(manifest.contains { $0.hasPrefix(normalize("/v1.0/deviceManagement/managedDevices")) })
    }
}
