import Foundation

// The shift log: every write the app made, on the device, for the ticket. Spec section 4.
//
// Not a substitute for the tenant's audit log, which is Microsoft's and authoritative;
// this is the thing the admin pastes into the incident when asked what they did at 02:14.
// Device-local only: a file in Application Support, never the Keychain (it is not a
// credential, and the Keychain holds exactly four non-credential items by rule), never a
// server. Capped, append-only, exportable as text, clearable in Settings.

public struct ShiftLogEntry: Sendable, Codable, Equatable, Identifiable {
    public let id: String
    public let at: Date
    public let tenantId: String
    /// The action's stable name: "device.restart".
    public let actionId: String
    public let actionTitle: String
    public let targetLabel: String
    public let targetId: String
    /// "requested", "notAuthorized", "failed", "challenged", "needsActivation".
    public let outcome: String
    /// Microsoft's request-id when there was a response.
    public let requestId: String?

    public init(id: String = UUID().uuidString, at: Date, tenantId: String, actionId: String, actionTitle: String, targetLabel: String, targetId: String, outcome: String, requestId: String?) {
        self.id = id
        self.at = at
        self.tenantId = tenantId
        self.actionId = actionId
        self.actionTitle = actionTitle
        self.targetLabel = targetLabel
        self.targetId = targetId
        self.outcome = outcome
        self.requestId = requestId
    }

    /// One line, the way it goes into a ticket.
    public var line: String {
        let stamp = ShiftLogFormat.stamp.string(from: at)
        var parts = [stamp, actionTitle, targetLabel + " (" + targetId + ")", outcome]
        if let requestId { parts.append("request-id " + requestId) }
        return parts.joined(separator: " | ")
    }
}

enum ShiftLogFormat {
    static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss'Z'"
        return f
    }()
}

public protocol ShiftLogging: Sendable {
    func append(_ entry: ShiftLogEntry) async
    func entries(tenantId: String) async -> [ShiftLogEntry]
    /// Newest first, as text, with a header naming the tenant and the export time.
    func export(tenantId: String, now: Date) async -> String
    func clear(tenantId: String) async
}

/// JSON in Application Support. One file for every tenant; entries carry the tenant id and
/// every read filters by it, so an MSP's customers never see each other's lines in an
/// export.
public actor FileShiftLog: ShiftLogging {

    public static let cap = 500
    public static let fileName = "shift-log.json"

    private let url: URL
    private var cache: [ShiftLogEntry]?

    /// The one instance the app uses. Each instance keeps the file in memory after its
    /// first read, so two over the same file, two iPad windows or two sessions either side
    /// of a tenant switch, would each write back their own copy and drop the other's lines.
    public static let shared = FileShiftLog.standard()

    /// The app's location: Application Support/TenantKeep/shift-log.json.
    public static func standard() -> FileShiftLog {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return FileShiftLog(directory: base.appendingPathComponent("TenantKeep", isDirectory: true))
    }

    public init(directory: URL) {
        self.url = directory.appendingPathComponent(Self.fileName)
    }

    public func append(_ entry: ShiftLogEntry) {
        var all = load()
        all.append(entry)
        if all.count > Self.cap { all.removeFirst(all.count - Self.cap) }
        save(all)
    }

    public func entries(tenantId: String) -> [ShiftLogEntry] {
        load().filter { $0.tenantId == tenantId }.sorted { $0.at > $1.at }
    }

    public func export(tenantId: String, now: Date = Date()) -> String {
        Self.render(entries(tenantId: tenantId), tenantId: tenantId, now: now)
    }

    public func clear(tenantId: String) {
        save(load().filter { $0.tenantId != tenantId })
    }

    static func render(_ entries: [ShiftLogEntry], tenantId: String, now: Date) -> String {
        var lines = [
            "TenantKeep On-Call shift log",
            "Tenant " + tenantId,
            "Exported " + ShiftLogFormat.stamp.string(from: now),
            "Device-local record of write actions requested from this app. The tenant audit log is authoritative.",
            ""
        ]
        if entries.isEmpty {
            lines.append("No actions recorded.")
        } else {
            lines.append(contentsOf: entries.map(\.line))
        }
        return lines.joined(separator: "\n")
    }

    private func load() -> [ShiftLogEntry] {
        if let cache { return cache }
        guard let data = try? Data(contentsOf: url),
              let decoded = try? Self.decoder.decode([ShiftLogEntry].self, from: data) else {
            cache = []
            return []
        }
        cache = decoded
        return decoded
    }

    private func save(_ entries: [ShiftLogEntry]) {
        cache = entries
        let directory = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        guard let data = try? Self.encoder.encode(entries) else { return }
        // Complete protection until first unlock: the file is readable only while the
        // device is unlocked, the same class the rest of the app's preferences get.
        try? data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    private static var encoder: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }

    private static var decoder: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}

/// For tests, previews and demo mode.
public actor InMemoryShiftLog: ShiftLogging {
    private var all: [ShiftLogEntry] = []
    public init() {}
    public func append(_ entry: ShiftLogEntry) {
        all.append(entry)
        if all.count > FileShiftLog.cap { all.removeFirst(all.count - FileShiftLog.cap) }
    }
    public func entries(tenantId: String) -> [ShiftLogEntry] {
        all.filter { $0.tenantId == tenantId }.sorted { $0.at > $1.at }
    }
    public func export(tenantId: String, now: Date = Date()) -> String {
        FileShiftLog.render(entries(tenantId: tenantId), tenantId: tenantId, now: now)
    }
    public func clear(tenantId: String) {
        all.removeAll { $0.tenantId == tenantId }
    }
}
