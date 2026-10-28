import SwiftUI
import AuthKit
import CredentialKit
import InventoryKit
import DiagnosticsKit
import LicensingKit

// Build Spec §5, the device list. First screen after sign-in.
//
// The job is narrow: find one device fast. So search is prominent, rows carry only
// what's needed to identify and triage (name, who has it, platform, anything wrong),
// and everything else waits for the detail screen.
//
// Rows do NOT show credential state. Whether a password exists is a privileged
// question, and answering it in a scrollable list would leak inventory-wide LAPS
// coverage to anyone holding the phone.

@MainActor
@Observable
final class DeviceListModel {
    /// Every device loaded, in name order. Pages are merged in as they arrive rather than
    /// re-sorted with everything else, and each device's search fields were folded when it
    /// was built, off the main thread (OPTIMIZATION-PLAN.md, step E).
    private(set) var devices: [ManagedDeviceSummary] = []
    /// The same devices by id, for the detail column and the favourites.
    private(set) var devicesById: [String: ManagedDeviceSummary] = [:]
    /// What is typed. The list filters on `appliedQuery`, which follows this after a pause.
    var query: String = "" {
        didSet { if query != oldValue { scheduleFilter() } }
    }
    var isLoading = false
    var isLoadingMore = false
    var hasMore = false
    var errorMessage: String?

    /// Where the background fill has got to. Drives every "still loading" indicator, and
    /// the search empty state reads it to avoid the lie this exists to fix, "no devices
    /// match" while half the tenant has not arrived yet.
    enum FillState: Equatable {
        case idle
        case filling(loaded: Int)
        /// A pull to refresh reading the tenant again. The list on screen stays until the
        /// new one is complete, then replaces it.
        case refreshing(loaded: Int)
        /// Every page loaded. Search results are the whole tenant.
        case complete
        /// Stopped at the cap or on an error, with pages remaining. Manual load-more
        /// still works, and search must say it is incomplete.
        case incomplete(loaded: Int)
    }
    private(set) var fill: FillState = .idle
    @ObservationIgnored private var fillTask: Task<Void, Never>?

    /// True while the background fill is paging. Manual paging is a no-op meanwhile: two
    /// concurrent pagers read the same next link across the fetch suspension and append the
    /// same page twice.
    var isFilling: Bool {
        switch fill {
        case .filling, .refreshing: return true
        case .idle, .complete, .incomplete: return false
        }
    }

    /// The refreshed tenant as it arrives, in name order, until it replaces `devices`.
    @ObservationIgnored private var refreshBuffer: [ManagedDeviceSummary] = []

    /// Filtered view of what's loaded. Search is client-side because Graph's
    /// managedDevices has no dependable server-side name search (§5).
    ///
    /// STORED, not computed: recomputed only when the inputs change, with the query side
    /// debounced and filtered off the main thread, and each arriving page merged into it.
    private(set) var visibleDevices: [ManagedDeviceSummary] = []

    /// The query `visibleDevices` was filtered with: `query` once typing pauses.
    @ObservationIgnored private var appliedQuery = ""
    @ObservationIgnored private var debounceTask: Task<Void, Never>?
    /// A full search running off the main thread. A page that lands meanwhile starts it
    /// again over everything, rather than being merged into a result about to be replaced.
    @ObservationIgnored private var searchTask: Task<Void, Never>?

    /// True while Graph is being asked directly for what was typed.
    private(set) var isLookingUp = false
    @ObservationIgnored private var lookupTask: Task<Void, Never>?

    /// How long to wait after the last keystroke before filtering. Short enough to feel
    /// immediate, long enough that a burst of typing collapses into one pass.
    private static let searchDebounce = 180

    private let inventory: any DeviceInventoryProviding

    /// Looks up primary users' display names when Intune left them empty. Nil in demo, and
    /// consulted only while the Settings toggle is on, it is the only thing in this model
    /// that can touch the user directory, and the toggle is the customer's consent to that.
    private let nameResolver: (any UserNameResolving)?
    private let settings: AppSettings?
    /// Names found so far, by lowercased sign-in address, applied to every page as it lands
    /// so a row never goes back from a name to an address.
    @ObservationIgnored private var resolvedNames: [String: String] = [:]
    /// Addresses already asked about, found or not.
    @ObservationIgnored private var askedNames: Set<String> = []

    /// Favourites and recents, keyed by the tenant being operated in. Nil in demo, where
    /// there is no tenant to key by and nothing worth remembering between launches.
    private let shortcutStore: (any DeviceShortcutStoring)?
    private let tenantId: String?

    /// The stored IDs. A favourite pointing at a machine that has left the tenant simply
    /// stops appearing.
    private(set) var shortcuts: DeviceShortcuts = .empty {
        didSet { resolveShortcuts() }
    }
    /// Pinned devices, in pin order, among those loaded.
    private(set) var favouriteDevices: [ManagedDeviceSummary] = []
    /// Recently opened devices, excluding anything already pinned, a device in both lists
    /// twice is noise, and the favourite is the more deliberate of the two.
    private(set) var recentDevices: [ManagedDeviceSummary] = []

    /// Free-tier meter, shared with the detail screen so both read one ledger.
    private let meter: RevealMeter
    private let isPro: Bool

    /// Reveals left in the current window. Shown on the LIST, not just on the detail
    /// screen, because an admin scrolling twenty machines should already know they are
    /// on their last one. Finding out only after opening a device is half a warning.
    private(set) var remainingReveals: Int = 0

    init(
        inventory: any DeviceInventoryProviding,
        // Nil rather than a constructed default: a default argument expression is
        // evaluated in a nonisolated context and RevealMeter.init is @MainActor.
        meter: RevealMeter? = nil,
        isPro: Bool = false,
        nameResolver: (any UserNameResolving)? = nil,
        settings: AppSettings? = nil,
        shortcutStore: (any DeviceShortcutStoring)? = nil,
        tenantId: String? = nil
    ) {
        self.inventory = inventory
        self.nameResolver = nameResolver
        self.settings = settings
        self.shortcutStore = shortcutStore
        self.tenantId = tenantId
        if let shortcutStore, let tenantId {
            self.shortcuts = shortcutStore.shortcuts(tenantId: tenantId)
        }
        let resolvedMeter = meter ?? RevealMeter(store: InMemoryRevealLedgerStore())
        self.meter = resolvedMeter
        self.isPro = isPro
        self.remainingReveals = resolvedMeter.remaining(isPro: isPro)
    }

    // MARK: - the device set

    /// Replaces everything: the first page, or a refreshed tenant once it is complete.
    private func replaceDevices(_ fresh: [ManagedDeviceSummary], sorted: Bool = false) {
        let named = applyNames(fresh)
        devices = sorted ? named : named.sorted(by: DeviceSearch.inNameOrder)
        devicesById = Dictionary(devices.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        resolveShortcuts()
        refilter()
        enrichNames(for: devices)
    }

    /// Merges a page into the devices on screen. Only its new devices are sorted, matched
    /// and merged; nothing already here is sorted or searched again.
    private func receive(_ page: [ManagedDeviceSummary]) {
        let fresh = applyNames(page).filter { devicesById[$0.id] == nil }
        guard !fresh.isEmpty else { return }
        devices = DeviceSearch.merged(devices, adding: fresh)
        var index = devicesById
        for device in fresh { index[device.id] = device }
        devicesById = index
        resolveShortcuts()
        if appliedQuery.isEmpty {
            visibleDevices = devices
        } else if searchTask != nil {
            refilter()
        } else {
            let query = appliedQuery
            visibleDevices = PerfProbe.measure("deviceFilter", "kind=merge devices=" + String(devices.count) + " queryLength=" + String(query.count)) {
                DeviceSearch.merged(results: visibleDevices, query: query, adding: fresh)
            }
        }
        enrichNames(for: fresh)
    }

    // MARK: - search

    /// Filters once typing pauses. Each keystroke cancels the wait before it, so a burst
    /// of typing costs one pass.
    private func scheduleFilter() {
        debounceTask?.cancel()
        debounceTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(Self.searchDebounce))
            guard !Task.isCancelled, let self, self.query != self.appliedQuery else { return }
            self.appliedQuery = self.query
            self.refilter()
        }
    }

    /// Searches everything loaded off the main thread, and shows the result only if the
    /// search is still the one typed.
    private func refilter() {
        searchTask?.cancel()
        searchTask = nil
        lookupTask?.cancel()
        isLookingUp = false
        let query = appliedQuery
        guard !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            visibleDevices = devices
            return
        }
        let snapshot = devices
        searchTask = Task { [weak self] in
            let started = ContinuousClock.now
            let result = await Task.detached(priority: .userInitiated) {
                DeviceSearch.filter(snapshot, query: query)
            }.value
            guard !Task.isCancelled, let self, self.appliedQuery == query else { return }
            PerfProbe.mark("deviceFilter", since: started, "kind=full devices=" + String(snapshot.count) + " queryLength=" + String(query.count))
            self.searchTask = nil
            self.visibleDevices = result
            if result.isEmpty { self.lookUp(query) }
        }
    }

    /// Asks Graph directly when nothing loaded matches and the tenant is not all here yet.
    /// What it finds joins the list like any other device.
    private func lookUp(_ query: String) {
        switch fill {
        case .filling, .refreshing, .incomplete: break
        case .idle, .complete: return
        }
        isLookingUp = true
        lookupTask = Task { [weak self] in
            guard let inventory = self?.inventory else { return }
            let found = await inventory.lookup(query)
            guard !Task.isCancelled, let self, self.appliedQuery == query else { return }
            self.isLookingUp = false
            self.receive(found)
        }
    }

    // MARK: - names

    /// Names already found, applied to devices that arrive without one.
    private func applyNames(_ page: [ManagedDeviceSummary]) -> [ManagedDeviceSummary] {
        guard !resolvedNames.isEmpty else { return page }
        return UserNameResolver.enrich(page, names: resolvedNames)
    }

    /// Whether the Settings toggle is on. The list view watches it, and calls
    /// `userNamesTurnedOn()` when it flips on mid-session.
    var userNamesEnabled: Bool { settings?.userNamesEnabled ?? false }

    func userNamesTurnedOn() { enrichNames(for: devices) }

    /// Fills in display names Intune left empty, if the customer has opted in, for the
    /// devices given: each page as it lands, and everything when the toggle turns on.
    /// Each address is asked about once; the resolver shares a lookup already running, so
    /// nothing here cancels one.
    ///
    /// Silent on failure. Names are a nicety; a row falling back to the UPN is the
    /// default experience, not an error, and a toggle left on in a tenant that has not
    /// consented should degrade to that rather than complain on every page.
    private func enrichNames(for batch: [ManagedDeviceSummary]) {
        guard let nameResolver, settings?.userNamesEnabled == true else { return }
        let needed = UserNameResolver.upnsNeedingNames(in: batch).filter { !askedNames.contains($0) }
        guard !needed.isEmpty else { return }
        askedNames.formUnion(needed)
        Task { [weak self] in
            guard let names = try? await nameResolver.displayNames(forUserPrincipalNames: needed) else {
                // Asked again with the next page, or when the toggle is turned on again.
                self?.askedNames.subtract(needed)
                return
            }
            self?.applyFound(names)
        }
    }

    private func applyFound(_ names: [String: String]) {
        guard !names.isEmpty else { return }
        resolvedNames.merge(names) { _, new in new }
        refreshBuffer = UserNameResolver.enrich(refreshBuffer, names: names)
        let enriched = UserNameResolver.enrich(devices, names: names)
        guard enriched != devices else { return }
        // A name never moves a device: the list is in device-name order.
        devices = enriched
        devicesById = Dictionary(devices.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        resolveShortcuts()
        refilter()
    }

    // MARK: - favourites and recents

    private func resolveShortcuts() {
        favouriteDevices = shortcuts.favourites.compactMap { devicesById[$0] }
        recentDevices = shortcuts.recents.filter { !shortcuts.favourites.contains($0) }.compactMap { devicesById[$0] }
    }

    func isFavourite(_ device: ManagedDeviceSummary) -> Bool {
        shortcuts.isFavourite(device.id)
    }

    func toggleFavourite(_ device: ManagedDeviceSummary) {
        guard let shortcutStore, let tenantId else { return }
        shortcuts = shortcutStore.toggleFavourite(device.id, tenantId: tenantId)
    }

    /// Records that a device was opened. Called by the shell when the selection changes,
    /// which is the one event that means the same thing on iPhone and on iPad. The detail
    /// screen's disappearance used to be the hook, and in a split view it never disappears.
    func recordVisit(_ device: ManagedDeviceSummary) {
        guard let shortcutStore, let tenantId else { return }
        shortcuts = shortcutStore.recordVisit(device.id, tenantId: tenantId)
    }

    /// Re-reads the meter. Called by the shell on selection change and whenever the meter
    /// announces a charge, so the count beside the list is right while a detail screen
    /// stays open on iPad.
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

    // MARK: - loading

    /// The first load, and a pull to refresh. A refresh with devices on screen keeps them
    /// there, with "Refreshing" in the fill note, until the tenant has been read again; it
    /// used to drop to the first page and lose an open device and its reveal for a while.
    ///
    /// A first load returns once the first page is on screen and the rest pages in behind
    /// it. A refresh returns only when the new list has replaced the old one, so the pull
    /// to refresh spinner stays up until then: with nothing typed, the fill note is the
    /// last row of the whole list and nobody would see it.
    func load() async {
        let refreshing = !devices.isEmpty
        // A refresh replaces the cache underneath any running fill, so stop it first.
        fillTask?.cancel()
        isLoading = true
        errorMessage = nil
        let started = Date()
        defer { isLoading = false }
        do {
            let firstPageStarted = ContinuousClock.now
            let first = try await inventory.loadFirstPage().devices
            PerfProbe.mark("deviceFirstPage", since: firstPageStarted, "devices=" + String(first.count))
            hasMore = try await inventory.hasMore()
            await Self.record(.deviceListFirstPage, .success, since: started)
            if refreshing {
                refreshBuffer = applyNames(first).sorted(by: DeviceSearch.inNameOrder)
                if hasMore {
                    startFill(refreshing: true)
                    await fillTask?.value
                } else {
                    replaceDevices(refreshBuffer, sorted: true)
                    refreshBuffer = []
                    fill = .complete
                }
            } else {
                replaceDevices(first)
                if hasMore { startFill(refreshing: false) } else { fill = .complete }
            }
        } catch {
            errorMessage = Self.describe(error)
            await Self.record(.deviceListFirstPage, Self.outcome(for: error), since: started)
        }
    }

    /// Pages the rest of the tenant in the background so search covers all of it.
    ///
    /// Starts right after the first page rather than only once somebody types, because the
    /// working set should already be full by the time they do, a few seconds of background
    /// paging against a search that lies until then is not a close call.
    private func startFill(refreshing: Bool) {
        fillTask?.cancel()
        fill = refreshing ? .refreshing(loaded: refreshBuffer.count) : .filling(loaded: devices.count)
        let fillStarted = ContinuousClock.now
        fillTask = Task { [weak self] in
            guard let self else { return }
            let outcome = await InventoryFill.run(inventory) { @MainActor [weak self] added, total in
                guard let self else { return }
                if refreshing {
                    self.refreshBuffer = DeviceSearch.merged(self.refreshBuffer, adding: self.applyNames(added))
                    self.fill = .refreshing(loaded: total)
                } else {
                    self.receive(added)
                    self.fill = .filling(loaded: total)
                }
            }
            guard !Task.isCancelled else { return }
            PerfProbe.mark("deviceFill", since: fillStarted, "devices=" + String(refreshing ? refreshBuffer.count : devices.count) + " outcome=" + String(describing: outcome))
            hasMore = (try? await inventory.hasMore()) ?? hasMore
            if refreshing {
                switch outcome {
                case .complete, .capped:
                    // The tenant as it is now, replacing what was on screen: changed
                    // devices updated, new ones added, any gone from Intune dropped.
                    replaceDevices(refreshBuffer, sorted: true)
                case .cancelled:
                    return
                case .failed(let error):
                    // The list on screen is kept rather than replaced by part of a tenant.
                    await Self.record(.deviceListNextPage, Self.outcome(for: error), since: Date())
                }
                refreshBuffer = []
            }
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
                if !refreshing {
                    await Self.record(.deviceListNextPage, Self.outcome(for: error), since: Date())
                }
            }
        }
    }

    deinit {
        fillTask?.cancel()
        debounceTask?.cancel()
        searchTask?.cancel()
        lookupTask?.cancel()
    }

    func loadMore() async {
        guard hasMore, !isLoadingMore, !isFilling else { return }
        isLoadingMore = true
        defer { isLoadingMore = false }
        let started = Date()
        do {
            let page = try await inventory.loadNextPage()
            receive(page?.devices ?? [])
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

    /// Records an operation outcome. Typed fields only, no device names, no URLs, no
    /// response bodies, because DiagnosticEvent cannot carry them.
    ///
    /// Graph's `request-id` is filled in by `DiagnosticsRecorder` rather than passed here:
    /// this call site does not hold the HTTP response, and the typed errors deliberately
    /// carry no diagnostics payload. See `GraphResponseTracer`.
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
            return "Microsoft Intune isn't responding right now. This is on Microsoft's side. Try again shortly."
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
    /// Owned by the shell, which also owns the selection, so the list and the detail column
    /// read one model and one answer to which device is open.
    @Bindable var model: DeviceListModel
    let isDemo: Bool
    /// The open device, by id. Set by a tap here, cleared by the shell when the module
    /// changes, and cleared by the system on the way back on iPhone.
    @Binding var selection: String?
    /// Driven by Cmd-K from the shell. `searchable(isPresented:)` is what lets a keyboard
    /// shortcut land in the search field at all.
    @Binding var searchPresented: Bool

    /// Which organization's devices these are, and whether that is the account's own.
    /// Nil in demo, where the demo banner already says there is no tenant, and for an MSP,
    /// whose banner and organization switcher the module shell shows above every module.
    var tenantBanner: (label: String, isAwayFromHome: Bool)? = nil
    /// Opens Settings. Nil whenever the shell's sidebar is on screen with its own gear,
    /// which is every regular-width layout. In a compact stack the sidebar is a swipe
    /// away, so the gear stays here where it has always been.
    var settingsBuilder: (() -> SettingsView)? = nil

    @State private var showingSettings = false

    var body: some View {
        let _ = PerfProbe.body("DeviceListView")
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
        .searchable(text: $model.query, isPresented: $searchPresented, prompt: "Device, user, or serial")
        .refreshable { await model.load() }
        .onChange(of: model.userNamesEnabled) { _, on in
            if on { model.userNamesTurnedOn() }
        }
        .toolbar {
            if settingsBuilder != nil {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showingSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .accessibilityLabel("Settings")
                }
            }
        }
        .sheet(isPresented: $showingSettings) {
            if let settingsBuilder { settingsBuilder() }
        }
        .task {
            guard model.devices.isEmpty else { return }
            await model.load()
            if let delay = PerfProbe.refreshAfter {
                try? await Task.sleep(for: .seconds(delay))
                PerfProbe.mark("deviceRefresh", "devices=" + String(model.devices.count))
                await model.load()
            }
        }
        .safeAreaInset(edge: .top) {
            if isDemo {
                DemoBanner()
            } else if let tenantBanner {
                TenantBanner(label: tenantBanner.label, isAwayFromHome: tenantBanner.isAwayFromHome)
            }
        }
    }

    // MARK: - states

    private var deviceList: some View {
        List(selection: $selection) {
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

            // Only when NOT searching. A search is a deliberate request for one device, and
            // pinned rows above the results would compete with the thing just asked for.
            if model.query.isEmpty {
                shortcutSection("Favourites", model.favouriteDevices, systemImage: "star.fill")
                shortcutSection("Recent", model.recentDevices, systemImage: "clock")
            }

            ForEach(model.visibleDevices) { device in
                // A value link, not a destination link: the shell owns the selection and
                // builds the detail column from it, which is what makes the same row work
                // beside a detail pane on iPad and above a pushed one on iPhone.
                NavigationLink(value: device.id) {
                    DeviceRow(device: device)
                }
                .swipeActions(edge: .leading, allowsFullSwipe: true) {
                    Button {
                        model.toggleFavourite(device)
                    } label: {
                        Label(model.isFavourite(device) ? "Unpin" : "Pin",
                              systemImage: model.isFavourite(device) ? "star.slash" : "star")
                    }
                    .tint(Brand.accent)
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
            return "Still loading devices, \(loaded) so far. Results update as they arrive."
        case .refreshing(let loaded):
            return "Refreshing the device list, \(loaded) read so far. These results are from before the refresh."
        case .incomplete(let loaded):
            return "Not every device is loaded (\(loaded) so far). Clear the search and load more to widen it."
        case .idle, .complete:
            return nil
        }
    }

    /// A pinned or recent group. Renders nothing when empty, so a fresh install shows no
    /// scaffolding for lists that do not exist yet.
    @ViewBuilder
    private func shortcutSection(
        _ title: String,
        _ devices: [ManagedDeviceSummary],
        systemImage: String
    ) -> some View {
        if !devices.isEmpty {
            Section {
                ForEach(devices) { device in
                    NavigationLink(value: device.id) {
                        DeviceRow(device: device)
                    }
                }
            } header: {
                Label(title, systemImage: systemImage)
                    .font(.footnote)
            }
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
                    Text("Loading all devices, \(loaded) so far")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else if case .refreshing(let loaded) = model.fill {
                    Text("Refreshing, \(loaded) read so far")
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
                // short, at the cap or on an error, so scrolling still continues past it.
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
                    Text("Still looking, \(loaded) devices loaded so far")
                        .font(.subheadline.weight(.medium))
                }
                Text(model.isLookingUp
                     ? "Asking Intune directly while the rest of the tenant loads."
                     : "Results appear as the rest of the tenant loads.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            case .refreshing:
                Text("No devices match \"\(model.query)\"")
                    .font(.subheadline.weight(.medium))
                Text("The list is being refreshed; results update when it finishes.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            case .incomplete(let loaded):
                Text("No match among the \(loaded) devices loaded")
                    .font(.subheadline.weight(.medium))
                Text(model.isLookingUp
                     ? "Asking Intune directly for an exact match."
                     : "Not every device is loaded yet. Clear the search and load more, then search again.")
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
