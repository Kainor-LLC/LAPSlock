import SwiftUI
import Combine
import CredentialKit
import InventoryKit
import DiagnosticsKit
import LicensingKit

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

    /// Where the background fill has got to. Drives every "still loading" indicator, and
    /// the search empty state reads it to avoid the lie this exists to fix — "no devices
    /// match" while half the tenant has not arrived yet.
    enum FillState: Equatable {
        case idle
        case filling(loaded: Int)
        /// Every page loaded. Search results are the whole tenant.
        case complete
        /// Stopped at the cap or on an error, with pages remaining. Manual load-more
        /// still works, and search must say it is incomplete.
        case incomplete(loaded: Int)
    }
    @Published private(set) var fill: FillState = .idle
    private var fillTask: Task<Void, Never>?

    /// True while the background fill is paging. Manual paging is a no-op meanwhile: two
    /// concurrent pagers read the same next link across the fetch suspension and append the
    /// same page twice.
    var isFilling: Bool {
        if case .filling = fill { return true }
        return false
    }

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

    /// Free-tier meter, shared with the detail screen so both read one ledger.
    private let meter: RevealMeter
    private let isPro: Bool

    /// Reveals left in the current window. Shown on the LIST, not just on the detail
    /// screen, because an admin scrolling twenty machines should already know they are
    /// on their last one. Finding out only after opening a device is half a warning.
    @Published private(set) var remainingReveals: Int = 0

    init(
        inventory: any DeviceInventoryProviding,
        // Nil rather than a constructed default: a default argument expression is
        // evaluated in a nonisolated context and RevealMeter.init is @MainActor.
        meter: RevealMeter? = nil,
        isPro: Bool = false
    ) {
        self.inventory = inventory
        let resolvedMeter = meter ?? RevealMeter(store: InMemoryRevealLedgerStore())
        self.meter = resolvedMeter
        self.isPro = isPro
        self.remainingReveals = resolvedMeter.remaining(isPro: isPro)

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

    /// Re-reads the meter. Called when the list appears, which includes popping back
    /// from a detail screen where a reveal may have just been spent.
    func refreshRemaining() {
        remainingReveals = meter.remaining(isPro: isPro)
    }

    /// The line shown above the list. Nil for Pro, who have no meter to report.
    var allowanceNote: String? {
        guard !isPro else { return nil }
        switch remainingReveals {
        case 0:  return "No free reveals left this month."
        case 1:  return "1 free reveal left this month."
        default: return "\(remainingReveals) free reveals left this month."
        }
    }

    func load() async {
        // A refresh replaces the cache underneath any running fill, so stop it first.
        fillTask?.cancel()
        fill = .idle
        isLoading = true
        errorMessage = nil
        let started = Date()
        defer { isLoading = false }
        do {
            _ = try await inventory.loadFirstPage()
            devices = try await inventory.cachedDevices()
            hasMore = try await inventory.hasMore()
            await Self.record(.deviceListFirstPage, .success, since: started)
            if hasMore { startFill() } else { fill = .complete }
        } catch {
            errorMessage = Self.describe(error)
            await Self.record(.deviceListFirstPage, Self.outcome(for: error), since: started)
        }
    }

    /// Pages the rest of the tenant in the background so search covers all of it.
    ///
    /// Starts right after the first page rather than only once somebody types, because the
    /// working set should already be full by the time they do — a few seconds of background
    /// paging against a search that lies until then is not a close call.
    private func startFill() {
        fillTask?.cancel()
        fill = .filling(loaded: devices.count)
        fillTask = Task { [weak self] in
            guard let self else { return }
            let outcome = await InventoryFill.run(inventory) { @MainActor [weak self] loaded in
                guard let self else { return }
                self.devices = loaded
                self.fill = .filling(loaded: loaded.count)
            }
            guard !Task.isCancelled else { return }
            hasMore = (try? await inventory.hasMore()) ?? hasMore
            switch outcome {
            case .complete:
                fill = .complete
            case .capped:
                fill = .incomplete(loaded: devices.count)
            case .cancelled:
                return
            case .failed(let error):
                // Not surfaced as the list's error: the first page is on screen and usable,
                // and the manual load-more row remains. Recorded, because a fill that keeps
                // failing on one tenant is worth seeing in a diagnostics report.
                fill = .incomplete(loaded: devices.count)
                await Self.record(.deviceListNextPage, Self.outcome(for: error), since: Date())
            }
        }
    }

    deinit {
        fillTask?.cancel()
    }

    func loadMore() async {
        guard hasMore, !isLoadingMore, !isFilling else { return }
        isLoadingMore = true
        defer { isLoadingMore = false }
        let started = Date()
        do {
            _ = try await inventory.loadNextPage()
            devices = try await inventory.cachedDevices()
            hasMore = try await inventory.hasMore()
            // A manual page after the fill stopped keeps the indicator honest.
            fill = hasMore ? .incomplete(loaded: devices.count) : .complete
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

    /// The MSP organization picker, or nil when this tier cannot switch. Passing nil rather

    /// than disabling a visible control is deliberate: a single-organization admin should

    /// not see chrome for a feature that does not apply to them.

    var tenantSwitcher: (() -> TenantSwitcherView)? = nil

    /// Refreshes tenant state when the list appears. Note the NavigationStack does not

    /// disappear when a detail view is pushed, so this fires once at launch — which is

    /// enough here, because switching organizations happens through the sheet below.

    var onAppearRefresh: (() async -> Void)? = nil
    /// Which organization's devices these are, and whether that is the account's own.
    /// Nil in demo, where the demo banner already says there is no tenant.
    var tenantBanner: (label: String, isAwayFromHome: Bool)? = nil
    /// Opens Settings. Injected so the list doesn't need to know how consent is requested.
    let settingsBuilder: () -> SettingsView
    /// Builds the detail screen for a device. Injected so the list doesn't need to know
    /// how credentials are provided.
    let detailBuilder: (ManagedDeviceSummary) -> DeviceDetailView

    @State private var showingSettings = false


    @State private var showingTenantSwitcher = false

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
                if tenantSwitcher != nil {
                    ToolbarItem(placement: .topBarLeading) {
                        Button {
                            showingTenantSwitcher = true
                        } label: {
                            Image(systemName: "building.2")
                        }
                        .accessibilityLabel("Switch organization")
                    }
                }
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
            .sheet(isPresented: $showingTenantSwitcher) {
                if let tenantSwitcher { tenantSwitcher() }
            }
            .task { await onAppearRefresh?() }
            .safeAreaInset(edge: .top) {
                if isDemo {
                    DemoBanner()
                } else if let tenantBanner {
                    TenantBanner(label: tenantBanner.label, isAwayFromHome: tenantBanner.isAwayFromHome)
                }
            }
        }
        .task {
            if model.devices.isEmpty { await model.load() }
        }
        .onAppear {
            // Also fires on the way back from a detail screen, which is exactly when
            // the count may have changed.
            model.refreshRemaining()
        }
    }

    // MARK: - states

    private var deviceList: some View {
        List {
            // Scrolls away with the content rather than pinning to the top. Present on
            // arrival so nobody is surprised at a broken machine, absent once you are
            // working, because this audience is unusually allergic to being sold to.
            if let note = model.allowanceNote {
                Text(note)
                    .font(.footnote)
                    .foregroundStyle(model.remainingReveals == 0 ? .orange : .secondary)
                    .listRowSeparator(.hidden)
                    .listRowBackground(Color.clear)
            }

            ForEach(model.visibleDevices) { device in
                NavigationLink {
                    // Refresh on the way BACK, not on the list's onAppear. A
                    // NavigationStack does not disappear when a detail is pushed onto
                    // it, so onAppear on the stack fires once at launch and never again.
                    // The detail view's disappearance is the actual moment a reveal may
                    // have been spent.
                    detailBuilder(device)
                        .onDisappear { model.refreshRemaining() }
                } label: {
                    DeviceRow(device: device)
                }
            }

            if !model.query.isEmpty && model.visibleDevices.isEmpty {
                noSearchResults
            } else if !model.query.isEmpty, let note = partialSearchNote {
                // Results exist but may not be all of them. Said beneath the results rather
                // than not at all: a list that looks complete and is not is the same lie as
                // an empty one, just harder to notice.
                Text(note)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .listRowSeparator(.hidden)
            }

            if model.hasMore && model.query.isEmpty {
                loadMoreRow
            }
        }
        .listStyle(.plain)
    }

    /// While the fill is running or after it stopped short, one line saying so.
    private var partialSearchNote: String? {
        switch model.fill {
        case .filling(let loaded):
            return "Still loading devices — \(loaded) so far. Results update as they arrive."
        case .incomplete(let loaded):
            return "Not every device is loaded (\(loaded) so far). Clear the search and load more to widen it."
        case .idle, .complete:
            return nil
        }
    }

    @ViewBuilder
    private var loadMoreRow: some View {
        if model.isFilling {
            // The fill is paging; a manual load would only duplicate a page. Show progress
            // instead of a button that does nothing.
            HStack(spacing: 8) {
                Spacer()
                ProgressView()
                if case .filling(let loaded) = model.fill {
                    Text("Loading all devices — \(loaded) so far")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.vertical, 8)
        } else {
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
                // Auto-page when this row appears. Only reached once the fill has stopped
                // short — at the cap or on an error — so scrolling still continues past it.
                await model.loadMore()
            }
        }
    }

    private var noSearchResults: some View {
        VStack(spacing: 6) {
            switch model.fill {
            case .filling(let loaded):
                // NOT "no devices match". Nothing has been ruled out yet, and saying so
                // was the bug: an empty state during a partial load read as "this app
                // cannot find my machine".
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Still looking — \(loaded) devices loaded so far")
                        .font(.subheadline.weight(.medium))
                }
                Text("Results appear as the rest of the tenant loads.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            case .incomplete(let loaded):
                Text("No match among the \(loaded) devices loaded")
                    .font(.subheadline.weight(.medium))
                Text("Not every device is loaded yet. Clear the search and load more, then search again.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            case .idle, .complete:
                Text("No devices match \"\(model.query)\"")
                    .font(.subheadline.weight(.medium))
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

                // primaryUserLabel prefers the display name, then UPN, then email. Search matches on
                // all three, so a row showing only the UPN could match on a field it never displayed,
                // which read as a phantom hit.
                if let user = device.primaryUserLabel {
                    Text(user)
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
