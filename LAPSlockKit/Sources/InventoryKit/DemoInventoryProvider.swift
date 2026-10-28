import Foundation
import AuthKit

// Demo inventory. Powers SwiftUI previews, UI development without a tenant, and
// App Store review (Guideline 2.1, reviewers can't sign into a customer tenant).
//
// THE DATA IS CHOSEN TO EXERCISE EVERY UI STATE, not to look pretty:
//   * Windows devices that can reveal (the happy path)
//   * a Windows device with NO Entra device id → structural block, needs an explanation
//   * macOS devices → reveal unavailable for an API reason, portal handoff instead
//   * an iOS device → unsupported platform
//   * non-compliant and stale-sync devices → status badges
//   * enough devices to make paging and search worth testing
//
// Building the fleet this way means the UI gets developed against its awkward cases
// from the start, instead of looking correct on three tidy rows and falling apart in
// a real tenant.

public actor DemoInventoryProvider: DeviceInventoryProviding {

    /// Simulated network latency, so loading states are visible during development
    /// rather than snapping instantly and hiding a spinner bug.
    private let latency: Duration
    private let pageSize: Int
    /// Every page after the first, as the live service pages in larger steps after it.
    private let fillPageSize: Int
    private var loaded: [ManagedDeviceSummary] = []
    private var cursor: Int = 0
    /// The second sample customer in demo mode: a calm tenant with nothing open, so switching
    /// customers shows different data and anything left over from the first stands out.
    private let quiet: Bool

    /// Set for the large demo tenant, which replaces the twelve hand-built devices.
    private let customFleet: [ManagedDeviceSummary]?

    public init(latency: Duration = .milliseconds(400), pageSize: Int = 8, fillPageSize: Int? = nil,
                quiet: Bool = false, fleet: [ManagedDeviceSummary]? = nil) {
        self.latency = latency
        self.quiet = quiet
        self.pageSize = max(1, pageSize)
        self.fillPageSize = max(self.pageSize, fillPageSize ?? pageSize)
        self.customFleet = fleet
    }

    private var fleet: [ManagedDeviceSummary] { quiet ? [] : (customFleet ?? Self.fleet) }

    // MARK: - DeviceInventoryProviding

    @discardableResult
    public func loadFirstPage() async throws -> DevicePage {
        try await Task.sleep(for: latency)
        loaded = []
        cursor = 0
        return nextChunk(pageSize)
    }

    @discardableResult
    public func loadNextPage() async throws -> DevicePage? {
        guard cursor < fleet.count else { return nil }
        try await Task.sleep(for: latency)
        return nextChunk(fillPageSize)
    }

    /// Exact matches on name, serial or sign-in address, and names starting with it, over
    /// the whole sample fleet, as the live lookup asks Graph.
    public func lookup(_ query: String) async -> [ManagedDeviceSummary] {
        let typed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !typed.isEmpty, (try? await Task.sleep(for: latency)) != nil else { return [] }
        let folded = typed.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
        return Array(fleet.filter { device in
            device.searchKey.name.hasPrefix(folded) || device.searchKey.others.contains(folded)
        }.prefix(25))
    }

    public func cachedDevices() async throws -> [ManagedDeviceSummary] { loaded }

    public func hasMore() async throws -> Bool { cursor < fleet.count }

    public func reset() async {
        loaded = []
        cursor = 0
    }

    private func nextChunk(_ size: Int) -> DevicePage {
        let end = min(cursor + size, fleet.count)
        let slice = Array(fleet[cursor..<end])
        loaded.append(contentsOf: slice)
        cursor = end
        let more = cursor < fleet.count
        return DevicePage(devices: slice, nextLink: more ? "demo://page/\(cursor)" : nil)
    }

    // MARK: - the large fleet

    /// A tenant the size of a large customer, for measuring rather than for review: 20,000
    /// devices by default, roughly 70 percent Windows, 15 percent macOS and 15 percent phones,
    /// shared by 5,000 people, a few in every hundred non-compliant or stale.
    ///
    /// Every field comes from the index, so the same count gives the same fleet on every run
    /// and a measurement can be repeated. Names follow the hand-built fleet's patterns and
    /// resemble no real organization's convention.
    public static func largeFleet(count: Int = 20_000) -> [ManagedDeviceSummary] {
        let prefixes = ["LT-SALES", "LT-FIELD", "DESKTOP-FRONT", "WS-LAB", "WS-ENG", "LT-FIN", "KIOSK-LOBBY", "LT-OPS"]
        let macPrefixes = ["MBP-DESIGN", "MBA-EXEC", "MBP-ENG", "MBA-MKT"]
        let phonePrefixes = ["iPhone (Field", "iPad (Store"]
        let windowsModels = [("OptiPlex 7010", "Dell Inc."), ("ThinkPad T14", "LENOVO"), ("Latitude 5440", "Dell Inc."), ("EliteBook 840", "HP")]
        let macModels = ["MacBook Pro (14-inch, M3)", "MacBook Air (13-inch, M2)"]
        let people = 5_000
        let now = Date()
        return (0..<max(0, count)).map { i in
            let person = i % people
            let upn = "user" + String(format: "%04d", person) + "@demo.example"
            let synced = now.addingTimeInterval(-Double((i * 7919) % (30 * 24)) * 3_600)
            let compliance = i % 37 == 0 ? "noncompliant" : (i % 53 == 0 ? "unknown" : "compliant")
            let serial = "DL" + String(format: "%06X", (i &* 2_654_435_761) & 0xFFFFFF)
            switch i % 20 {
            case 0..<14:
                let model = windowsModels[i % windowsModels.count]
                return ManagedDeviceSummary(
                    id: "large-w-" + String(i), entraDeviceId: "large-entra-" + String(i),
                    deviceName: prefixes[i % prefixes.count] + "-" + String(format: "%05d", i),
                    platform: .windows, operatingSystemRaw: "Windows",
                    osVersion: i % 3 == 0 ? "10.0.22631.4460" : "10.0.26100.2314",
                    userPrincipalName: upn, userDisplayName: i % 4 == 0 ? nil : "Person " + String(person),
                    serialNumber: serial, model: model.0, manufacturer: model.1,
                    complianceState: compliance, lastSyncDateTime: synced)
            case 14..<17:
                return ManagedDeviceSummary(
                    id: "large-m-" + String(i), entraDeviceId: "large-entra-" + String(i),
                    deviceName: macPrefixes[i % macPrefixes.count] + "-" + String(format: "%05d", i),
                    platform: .macOS, operatingSystemRaw: "macOS", osVersion: "15.6",
                    userPrincipalName: upn, userDisplayName: "Person " + String(person),
                    serialNumber: serial, model: macModels[i % macModels.count], manufacturer: "Apple",
                    complianceState: compliance, lastSyncDateTime: synced)
            default:
                return ManagedDeviceSummary(
                    id: "large-p-" + String(i), entraDeviceId: nil,
                    deviceName: phonePrefixes[i % phonePrefixes.count] + " " + String(i) + ")",
                    platform: .other, operatingSystemRaw: "iOS", osVersion: "18.6",
                    userPrincipalName: upn, userDisplayName: "Person " + String(person),
                    serialNumber: serial, model: "iPhone", manufacturer: "Apple",
                    complianceState: compliance, lastSyncDateTime: synced)
            }
        }
    }

    // MARK: - the fleet

    private static func daysAgo(_ d: Double) -> Date {
        Date().addingTimeInterval(-d * 86_400)
    }

    /// Names deliberately avoid resembling any real organization's convention, and no
    /// value here is derived from a real tenant.
    public static let fleet: [ManagedDeviceSummary] = [
        // ── Windows, healthy: the happy path ────────────────────────────────
        ManagedDeviceSummary(
            id: "demo-w-001", entraDeviceId: "demo-entra-001",
            deviceName: "DESKTOP-FRONT01", platform: .windows,
            operatingSystemRaw: "Windows", osVersion: "10.0.26100.2314",
            userPrincipalName: "rlee@demo.example", serialNumber: "DM0001AA",
            model: "OptiPlex 7010", manufacturer: "Dell Inc.",
            complianceState: "compliant", lastSyncDateTime: daysAgo(0.2)
        ),
        ManagedDeviceSummary(
            id: "demo-w-002", entraDeviceId: "demo-entra-002",
            deviceName: "LT-SALES-114", platform: .windows,
            operatingSystemRaw: "Windows", osVersion: "10.0.26100.2314",
            userPrincipalName: "jgarcia@demo.example", serialNumber: "DM0002BB",
            model: "ThinkPad T14", manufacturer: "LENOVO",
            complianceState: "compliant", lastSyncDateTime: daysAgo(0.5)
        ),
        // ── Windows, non-compliant: status badge ────────────────────────────
        ManagedDeviceSummary(
            id: "demo-w-003", entraDeviceId: "demo-entra-003",
            deviceName: "LT-FIELD-207", platform: .windows,
            operatingSystemRaw: "Windows", osVersion: "10.0.22631.4317",
            userPrincipalName: "tnguyen@demo.example", serialNumber: "DM0003CC",
            model: "Latitude 5540", manufacturer: "Dell Inc.",
            complianceState: "noncompliant", lastSyncDateTime: daysAgo(3)
        ),
        // ── Windows, stale sync: "last seen" needs to look wrong at a glance ─
        ManagedDeviceSummary(
            id: "demo-w-004", entraDeviceId: "demo-entra-004",
            deviceName: "WS-LAB-009", platform: .windows,
            operatingSystemRaw: "Windows", osVersion: "10.0.19045.5011",
            userPrincipalName: nil, serialNumber: "DM0004DD",
            model: "Precision 3660", manufacturer: "Dell Inc.",
            complianceState: "compliant", lastSyncDateTime: daysAgo(64)
        ),
        // ── Windows with NO Entra device id: structural block ───────────────
        // The important awkward case. LAPS cannot exist for this device, so the UI
        // must explain that instead of offering a button that 404s.
        ManagedDeviceSummary(
            id: "demo-w-005", entraDeviceId: nil,
            deviceName: "KIOSK-LOBBY-2", platform: .windows,
            operatingSystemRaw: "Windows", osVersion: "10.0.22631.4317",
            userPrincipalName: nil, serialNumber: "DM0005EE",
            model: "ThinkCentre M70q", manufacturer: "LENOVO",
            complianceState: "compliant", lastSyncDateTime: daysAgo(1.1)
        ),
        // ── macOS: reveal unavailable (API), portal handoff ─────────────────
        ManagedDeviceSummary(
            id: "demo-m-001", entraDeviceId: "demo-entra-101",
            deviceName: "MBP-DESIGN-03", platform: .macOS,
            operatingSystemRaw: "macOS", osVersion: "15.1.1",
            userPrincipalName: "achen@demo.example", serialNumber: "DMAC001",
            model: "MacBook Pro 14-inch", manufacturer: "Apple",
            complianceState: "compliant", lastSyncDateTime: daysAgo(0.3)
        ),
        ManagedDeviceSummary(
            id: "demo-m-002", entraDeviceId: "demo-entra-102",
            deviceName: "MBA-EXEC-01", platform: .macOS,
            operatingSystemRaw: "macOS", osVersion: "15.0.1",
            userPrincipalName: "pmurphy@demo.example", serialNumber: "DMAC002",
            model: "MacBook Air 15-inch", manufacturer: "Apple",
            complianceState: "compliant", lastSyncDateTime: daysAgo(2.4)
        ),
        // ── iOS: unsupported platform ──────────────────────────────────────
        ManagedDeviceSummary(
            id: "demo-i-001", entraDeviceId: "demo-entra-201",
            deviceName: "iPhone (Field 12)", platform: .other,
            operatingSystemRaw: "iOS", osVersion: "18.1",
            userPrincipalName: "dwalker@demo.example", serialNumber: "DMIOS01",
            model: "iPhone 15", manufacturer: "Apple",
            complianceState: "compliant", lastSyncDateTime: daysAgo(0.1)
        ),
        // ── Second page, so paging is exercised ────────────────────────────
        ManagedDeviceSummary(
            id: "demo-w-006", entraDeviceId: "demo-entra-006",
            deviceName: "DESKTOP-FRONT02", platform: .windows,
            operatingSystemRaw: "Windows", osVersion: "10.0.26100.2314",
            userPrincipalName: "bkhan@demo.example", serialNumber: "DM0006FF",
            model: "OptiPlex 7010", manufacturer: "Dell Inc.",
            complianceState: "compliant", lastSyncDateTime: daysAgo(0.9)
        ),
        ManagedDeviceSummary(
            id: "demo-w-007", entraDeviceId: "demo-entra-007",
            deviceName: "LT-SALES-115", platform: .windows,
            operatingSystemRaw: "Windows", osVersion: "10.0.26100.2314",
            userPrincipalName: "sokafor@demo.example", serialNumber: "DM0007GG",
            model: "ThinkPad T14", manufacturer: "LENOVO",
            complianceState: "compliant", lastSyncDateTime: daysAgo(1.4)
        ),
        ManagedDeviceSummary(
            id: "demo-w-008", entraDeviceId: "demo-entra-008",
            deviceName: "WS-ENG-041", platform: .windows,
            operatingSystemRaw: "Windows", osVersion: "10.0.26100.2314",
            userPrincipalName: "mrossi@demo.example", serialNumber: "DM0008HH",
            model: "Precision 5860", manufacturer: "Dell Inc.",
            complianceState: "compliant", lastSyncDateTime: daysAgo(0.7)
        ),
        ManagedDeviceSummary(
            id: "demo-m-003", entraDeviceId: "demo-entra-103",
            deviceName: "MBP-ENG-11", platform: .macOS,
            operatingSystemRaw: "macOS", osVersion: "15.1.1",
            userPrincipalName: "hpatel@demo.example", serialNumber: "DMAC003",
            model: "MacBook Pro 16-inch", manufacturer: "Apple",
            complianceState: "noncompliant", lastSyncDateTime: daysAgo(9)
        )
    ]
}
