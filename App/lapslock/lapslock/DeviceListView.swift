import SwiftUI
import Combine
import CredentialKit
import InventoryKit
import DiagnosticsKit

// Build Spec §5 — the device list. First screen after sign-in.
//
// The job is narrow: find one device fast. So search is prominent, rows carry only
// what's needed to identify and triage (name, who has it, platform, anything wrong),
// and everything else waits for the detail screen.
//
// Rows do NOT show credential state. Whether a password exists is a privileged
// question, and answering it in a scrollable list would leak inventory-wide LAPS
// coverage to anyone holding the phone.

@MainActor
final class DeviceListModel: ObservableObject {
    @Published var devices: [ManagedDeviceSummary] = []
    @Published var query: String = ""
    @Published var isLoading = false
    @Published var isLoadingMore = false
    @Published var hasMore = false
    @Published var errorMessage: String?

    /// Filtered view of what's loaded. Search is client-side because Graph's
    /// managedDevices has no dependable server-side name search (§5).
    ///
    /// STORED, not computed, and that is the point. As a computed property this
    /// recalculated on every access, and `deviceList` reads it twice per body evaluation
    /// (once for the ForEach, once to decide whether to show the no-results row). So every
    /// keystroke ran the full filter and sort at least twice over the entire device set,
    /// on the main thread, before SwiftUI had even started diffing the list.
    ///
    /// Now it is recomputed only when the inputs actually change, and the query side is
    /// debounced, so typing "connor" costs one pass instead of six.
    @Published private(set) var visibleDevices: [ManagedDeviceSummary] = []

    /// How long to wait after the last keystroke before filtering. Short enough to feel
    /// immediate, long enough that a burst of typing collapses into one pass.
    private static let searchDebounce = 180

    private let inventory: any DeviceInventoryProviding

    init(inventory: any DeviceInventoryProviding) {
        self.inventory = inventory

        // Only the query is debounced. Device changes (first page, paging, refresh) flow
        // through immediately, because those are not user-typing bursts and delaying them
        // would make loading look slower than it is.
        let debouncedQuery = $query
            .removeDuplicates()
            .debounce(for: .milliseconds(Self.searchDebounce), scheduler: DispatchQueue.main)

        Publishers.CombineLatest($devices, debouncedQuery)
            .map { devices, query in
                DeviceSearch.filter(devices, query: query)
            }
            .assign(to: &$visibleDevices)
    }

    func load() async {
        isLoading = true
        errorMessage = nil
        let started = Date()
        defer { isLoading = false }
        do {
            _ = try await inventory.loadFirstPage()
            devices = try await inventory.cachedDevices()
            hasMore = try await inventory.hasMore()
            await Self.record(.deviceListFirstPage, .success, since: started)
        } catch {
            errorMessage = Self.describe(error)
            await Self.record(.deviceListFirstPage, Self.outcome(for: error), since: started)
        }
    }

    func loadMore() async {
        guard hasMore, !isLoadingMore else { return }
        isLoadingMore = true
        defer { isLoadingMore = false }
        let started = Date()
        do {
            _ = try await inventory.loadNextPage()
            devices = try await inventory.cachedDevices()
            hasMore = try await inventory.hasMore()
            await Self.record(.deviceListNextPage, .success, since: started)
        } catch {
            errorMessage = Self.describe(error)
            await Self.record(.deviceListNextPage, Self.outcome(for: error), since: started)
        }
    }

    // MARK: - diagnostics

    /// Records an operation outcome. Typed fields only — no device names, no URLs, no
    /// response bodies, because DiagnosticEvent cannot carry them.
    ///
    /// TODO: Graph's `request-id` header is the single most useful field for a Microsoft
    /// support case, and it is NOT captured yet — the services don't surface it on their
    /// typed errors. Threading it through is a small refactor worth doing before launch.
    static func record(
        _ op: DiagnosticOperation,
        _ outcome: DiagnosticOutcome,
        since started: Date
    ) async {
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        await DiagnosticsRecorder.shared.record(
            op, outcome,
            endpointTemplate: DiagnosticEndpoint.managedDevicesList,
            durationMs: ms
        )
    }

    static func outcome(for error: Error) -> DiagnosticOutcome {
        guard let e = error as? InventoryError else { return .unknown }
        switch e {
        case .notAuthorized:      return .notAuthorized
        case .consentRequired:    return .consentRequired
        case .throttled:          return .throttled
        case .serviceUnavailable: return .serviceUnavailable
        case .transport:          return .transportError
        case .decodeFailure:      return .decodeFailure
        case .cancelled:          return .userCancelled
        }
    }

    /// Error copy that says what happened and what to do (§8). No apologies, no
    /// error codes in the user's face.
    static func describe(_ error: Error) -> String {
        guard let e = error as? InventoryError else {
            return "Couldn't load devices. Check your connection and try again."
        }
        switch e {
        case .notAuthorized:
            return "Your account can't read device inventory. You'll need an Intune role that includes managed device read access."
        case .consentRequired:
            return "Your session expired. Sign in again to continue."
        case .throttled(let retryAfter):
            if let retryAfter {
                return "Microsoft Graph is rate limiting this tenant. Try again in about \(Int(retryAfter)) seconds."
            }
            return "Microsoft Graph is rate limiting this tenant. Wait a moment and try again."
        case .serviceUnavailable:
            return "Microsoft Intune isn't responding right now. This is on Microsoft's side — try again shortly."
        case .transport(let status):
            return "The request failed (HTTP \(status)). Check your connection and try again."
        case .decodeFailure:
            return "Microsoft Graph returned something unexpected. Try again, and let us know if it keeps happening."
        case .cancelled:
            return "Cancelled."
        }
    }
}

struct DeviceListView: View {
    @StateObject var model: DeviceListModel
    let isDemo: Bool
    /// Opens Settings. Injected so the list doesn't need to know how consent is requested.
    let settingsBuilder: () -> SettingsView
    /// Builds the detail screen for a device. Injected so the list doesn't need to know
    /// how credentials are provided.
    let detailBuilder: (ManagedDeviceSummary) -> DeviceDetailView

    @State private var showingSettings = false

    var body: some View {
        NavigationStack {
            Group {
                if model.isLoading && model.devices.isEmpty {
                    loadingState
                } else if let error = model.errorMessage, model.devices.isEmpty {
                    errorState(error)
                } else if model.devices.isEmpty {
                    emptyState
                } else {
                    deviceList
                }
            }
            .navigationTitle("Devices")
            // Opaque nav bar: otherwise list rows scroll visibly behind the title.
            .toolbarBackground(.visible, for: .navigationBar)
            .searchable(text: $model.query, prompt: "Device, user, or serial")
            .refreshable { await model.load() }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showingSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .accessibilityLabel("Settings")
                }
            }
            .sheet(isPresented: $showingSettings) {
                settingsBuilder()
            }
            .safeAreaInset(edge: .top) {
                if isDemo { DemoBanner() }
            }
        }
        .task {
            if model.devices.isEmpty { await model.load() }
        }
    }

    // MARK: - states

    private var deviceList: some View {
        List {
            ForEach(model.visibleDevices) { device in
                NavigationLink {
                    detailBuilder(device)
                } label: {
                    DeviceRow(device: device)
                }
            }

            if !model.query.isEmpty && model.visibleDevices.isEmpty {
                noSearchResults
            }

            if model.hasMore && model.query.isEmpty {
                loadMoreRow
            }
        }
        .listStyle(.plain)
    }

    private var loadMoreRow: some View {
        HStack {
            Spacer()
            if model.isLoadingMore {
                ProgressView()
            } else {
                Button("Load more devices") {
                    Task { await model.loadMore() }
                }
                .font(.subheadline)
            }
            Spacer()
        }
        .padding(.vertical, 8)
        .task {
            // Auto-page when this row appears. Keeps scrolling continuous without an
            // explicit tap, while the button stays for anyone who prefers it.
            await model.loadMore()
        }
    }

    private var noSearchResults: some View {
        VStack(spacing: 6) {
            Text("No devices match \"\(model.query)\"")
                .font(.subheadline.weight(.medium))
            if model.hasMore {
                Text("Not all devices are loaded yet. Load more and search again.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
    }

    private var loadingState: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("Loading devices…").font(.subheadline).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// An empty screen is an invitation to act, not a shrug.
    private var emptyState: some View {
        ContentUnavailableView {
            Label("No managed devices", systemImage: "laptopcomputer.slash")
        } description: {
            Text("This tenant has no devices enrolled in Microsoft Intune, so there's nothing to look up yet.")
        } actions: {
            Button("Check again") { Task { await model.load() } }
        }
    }

    private func errorState(_ message: String) -> some View {
        ContentUnavailableView {
            Label("Couldn't load devices", systemImage: "exclamationmark.triangle")
        } description: {
            Text(message)
        } actions: {
            Button("Try again") { Task { await model.load() } }
        }
    }
}

// MARK: - row

struct DeviceRow: View {
    let device: ManagedDeviceSummary

    private var icon: String {
        switch device.platform {
        case .windows: return "pc"
        case .macOS: return "macbook"
        case .other: return "iphone"
        }
    }

    private var staleDays: Int? {
        guard let sync = device.lastSyncDateTime else { return nil }
        let days = Int(Date().timeIntervalSince(sync) / 86_400)
        return days >= 30 ? days : nil
    }

    var body: some View {
        HStack(spacing: 10) {
            PlatformIcon(systemName: icon)

            VStack(alignment: .leading, spacing: 3) {
                // Device name is an identifier, so it's monospaced like other data.
                Text(device.deviceName)
                    .font(Brand.data(15, weight: .medium))
                    .lineLimit(1)

                if let upn = device.userPrincipalName {
                    Text(upn)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                } else if let model = device.model {
                    Text(model)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                HStack(spacing: 6) {
                    if device.complianceState?.lowercased() == "noncompliant" {
                        StatusPill(kind: .noncompliant)
                    }
                    if let days = staleDays {
                        StatusPill(kind: .stale(days: days))
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 3)
    }
}
