import SwiftUI
import SignInTriageKit
import DiagnosticsKit
import UserActionsKit

// People. Sign-in triage (spec 3.4) and user actions (3.5) in one place, merged
// 2026-10-26; a directory since 2026-10-29 (DIGEST-AND-PEOPLE-PLAN.md, step L).
//
// Content column: the whole directory, loaded the way the device list loads the fleet, to
// scroll through or search. Detail column: the person's page (PersonView.swift), pushed on
// iPhone: their account at a glance, their actions, leaver checklist and groups, and their
// recent sign-ins with two filters, each sign-in opening with the error explained in plain
// English, the policy that blocked it named, the device, the location and the client, and
// risk when the tenant has P2.
//
// Pro, by decision D2: the module people open every morning is the one that converts.
// Demo mode shows it in full so App Review can evaluate it.

// MARK: - the directory

@MainActor
@Observable
final class PeopleDirectoryModel {
    /// Everyone loaded, in name order. Pages are merged in as they arrive.
    private(set) var entries: [DirectoryEntry] = []
    /// What the list shows: everyone, or who matches what was typed.
    private(set) var visible: [DirectoryEntry] = []
    /// What is typed. The list filters once typing pauses.
    var query = "" {
        didSet { if query != oldValue { scheduleFilter() } }
    }

    enum FillState: Equatable {
        case idle
        /// The first read, with the list growing as each page lands.
        case loading(loaded: Int)
        /// A pull to refresh reading everyone again. The list on screen stays until the new
        /// one is complete, then replaces it.
        case refreshing(loaded: Int)
        /// Everyone is here. Search results are the whole directory.
        case complete
        /// Stopped at the cap or on an error with people not loaded. Search asks Graph for
        /// anyone it does not find here.
        case incomplete(loaded: Int)
    }
    private(set) var fill: FillState = .idle
    /// The first page failed, so there is nothing to show but this.
    private(set) var errorMessage: String?
    private(set) var lastFailureWasConsent = false
    /// True while Graph is being asked for what was typed.
    private(set) var isLookingUp = false

    private let provider: any SignInTriageProviding
    @ObservationIgnored private var byId: [String: DirectoryEntry] = [:]
    /// The directory read again by a pull to refresh, until it replaces `entries`.
    @ObservationIgnored private var refreshBuffer: [DirectoryEntry] = []
    /// The query `visible` was filtered with: `query` once typing pauses.
    @ObservationIgnored private var appliedQuery = ""
    @ObservationIgnored private var fillTask: Task<Void, Never>?
    @ObservationIgnored private var debounceTask: Task<Void, Never>?
    /// A search running off the main thread. A page that lands meanwhile starts it again
    /// over everyone, rather than being merged into a result about to be replaced.
    @ObservationIgnored private var searchTask: Task<Void, Never>?
    @ObservationIgnored private var lookupTask: Task<Void, Never>?

    init(provider: any SignInTriageProviding) {
        self.provider = provider
    }

    deinit {
        fillTask?.cancel()
        debounceTask?.cancel()
        searchTask?.cancel()
        lookupTask?.cancel()
    }

    /// Whether the list may be missing people.
    var isPartial: Bool {
        switch fill {
        case .loading, .refreshing, .incomplete: return true
        case .idle, .complete: return false
        }
    }

    func entry(_ id: String) -> DirectoryEntry? { byId[id] }

    /// The first read. Once per shell: the shell is built again on sign-out and on a switch
    /// of organization, so one tenant's directory never shows in another.
    func loadIfNeeded() {
        guard fill == .idle, entries.isEmpty, errorMessage == nil else { return }
        start(refreshing: false)
    }

    /// After the first read failed: consent granted, or the network back.
    func retry() {
        start(refreshing: false)
    }

    /// Pull to refresh. Returns when the new list has replaced the old one, so the spinner
    /// stays up until then.
    func refresh() async {
        start(refreshing: !entries.isEmpty)
        await fillTask?.value
    }

    /// The person with this sign-in address or mail: from the list, or from Graph when they
    /// are not loaded yet. Nil when Graph has nobody by that address either.
    func person(withAddress address: String) async -> DirectoryUser? {
        if let entry = DirectorySearch.person(withAddress: address, in: entries) { return entry.user }
        guard let found = try? await provider.searchUsers(prefix: address) else { return nil }
        let fresh = found.map(DirectoryEntry.init)
        add(fresh)
        return DirectorySearch.person(withAddress: address, in: fresh)?.user
    }

    // MARK: - loading

    private func start(refreshing: Bool) {
        fillTask?.cancel()
        errorMessage = nil
        lastFailureWasConsent = false
        refreshBuffer = []
        fill = refreshing ? .refreshing(loaded: 0) : .loading(loaded: entries.count)
        let provider = provider
        let started = ContinuousClock.now
        let startedAt = Date()
        fillTask = Task { [weak self] in
            let outcome = await DirectoryFill.run(provider) { users, _ in
                // Folded here, before the page reaches the main actor.
                let fresh = users.map(DirectoryEntry.init)
                await self?.receive(fresh, refreshing: refreshing)
            }
            guard !Task.isCancelled, let self else { return }
            PerfProbe.mark("peopleFill", since: started, "people=" + String(refreshing ? refreshBuffer.count : entries.count) + " outcome=" + String(describing: outcome))
            await finish(outcome, refreshing: refreshing, since: startedAt)
        }
    }

    private func receive(_ fresh: [DirectoryEntry], refreshing: Bool) {
        if refreshing {
            refreshBuffer = DirectorySearch.merged(refreshBuffer, adding: fresh)
            fill = .refreshing(loaded: refreshBuffer.count)
        } else {
            add(fresh)
            fill = .loading(loaded: entries.count)
        }
    }

    private func finish(_ outcome: DirectoryFill.Outcome, refreshing: Bool, since started: Date) async {
        defer { refreshBuffer = [] }
        switch outcome {
        case .complete, .capped:
            if refreshing { replace(with: refreshBuffer) }
            fill = outcome == .complete ? .complete : .incomplete(loaded: entries.count)
            await Self.record(.success, since: started)
        case .cancelled:
            return
        case .failed(let error):
            if entries.isEmpty {
                fill = .idle
                errorMessage = Self.describe(error)
                lastFailureWasConsent = error == .consentRequired
            } else {
                // What loaded stays, a refresh keeps the list it had, and search asks Graph.
                fill = .incomplete(loaded: entries.count)
            }
            await Self.record(SignInTriageModel.outcome(for: error), since: started)
        }
    }

    /// People joining the list: a page, or whoever Graph found for a search.
    private func add(_ fresh: [DirectoryEntry]) {
        let new = fresh.filter { byId[$0.id] == nil }
        guard !new.isEmpty else { return }
        for entry in new { byId[entry.id] = entry }
        entries = DirectorySearch.merged(entries, adding: new)
        if appliedQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            visible = entries
        } else if searchTask != nil {
            refilter()
        } else {
            visible = DirectorySearch.merged(results: visible, query: appliedQuery, adding: new)
        }
    }

    /// A refreshed directory: changed people updated, new ones added, anyone gone dropped.
    private func replace(with fresh: [DirectoryEntry]) {
        entries = fresh
        byId = Dictionary(fresh.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        refilter()
    }

    // MARK: - search

    private func scheduleFilter() {
        debounceTask?.cancel()
        debounceTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(150))
            guard !Task.isCancelled, let self, self.query != self.appliedQuery else { return }
            self.appliedQuery = self.query
            self.refilter()
        }
    }

    private func refilter() {
        searchTask?.cancel()
        searchTask = nil
        lookupTask?.cancel()
        isLookingUp = false
        let query = appliedQuery
        guard !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            visible = entries
            return
        }
        let snapshot = entries
        searchTask = Task { [weak self] in
            let started = ContinuousClock.now
            let result = await Task.detached(priority: .userInitiated) {
                DirectorySearch.filter(snapshot, query: query)
            }.value
            guard !Task.isCancelled, let self, self.appliedQuery == query else { return }
            PerfProbe.mark("peopleFilter", since: started, "people=" + String(snapshot.count) + " queryLength=" + String(query.count))
            self.searchTask = nil
            self.visible = result
            if result.isEmpty { self.lookUp(query) }
        }
    }

    /// Asks Graph when nobody loaded matches and the directory is not all here. Whoever it
    /// finds joins the list like anyone else.
    private func lookUp(_ query: String) {
        guard isPartial, query.trimmingCharacters(in: .whitespacesAndNewlines).count >= 2 else { return }
        isLookingUp = true
        let provider = provider
        lookupTask = Task { [weak self] in
            let found = (try? await provider.searchUsers(prefix: query)) ?? []
            guard !Task.isCancelled, let self, self.appliedQuery == query else { return }
            self.isLookingUp = false
            self.add(found.map(DirectoryEntry.init))
        }
    }

    // MARK: - diagnostics and copy

    static func record(_ outcome: DiagnosticOutcome, since started: Date) async {
        await DiagnosticsRecorder.shared.record(
            .graphRead, outcome,
            endpointTemplate: "/v1.0" + SignInTriageService.usersPath + "?directory",
            durationMs: Int(Date().timeIntervalSince(started) * 1000))
    }

    static func describe(_ error: SignInTriageError) -> String {
        switch error {
        case .consentRequired:
            return "This organization hasn't granted TenantKeep permission to read its directory yet."
        case .notAuthorized:
            return "Your account can't list the people in this organization. A guest account, or an organization that limits reading the directory, needs a directory reader role."
        default:
            return SignInTriageModel.describe(error)
        }
    }
}

// MARK: - the person's sign-ins

/// The person whose page is open, and their recent sign-ins with the two filters.
@MainActor
@Observable
final class SignInTriageModel {
    private(set) var selectedUser: DirectoryUser?
    private(set) var signIns: [SignInEvent] = []
    private(set) var isLoadingSignIns = false
    private(set) var signInsError: String?
    private(set) var lastFailureWasConsent = false

    var failuresOnly = false {
        didSet { if selectedUser != nil { reloadSignIns() } }
    }
    var last24Hours = false {
        didSet { if selectedUser != nil { reloadSignIns() } }
    }

    let glossary = ErrorGlossary.bundled
    private let provider: any SignInTriageProviding
    @ObservationIgnored private var signInsTask: Task<Void, Never>?

    init(provider: any SignInTriageProviding) {
        self.provider = provider
    }

    deinit { signInsTask?.cancel() }

    func signIn(_ id: String) -> SignInEvent? {
        signIns.first { $0.id == id }
    }

    func select(_ user: DirectoryUser) {
        selectedUser = user
        signIns = []
        signInsError = nil
        reloadSignIns()
    }

    /// Pull to refresh: the same reload, waited for, so the indicator stays until the rows
    /// have changed rather than snapping back at once.
    func refreshSignIns() async {
        reloadSignIns()
        await signInsTask?.value
    }

    func reloadSignIns() {
        guard let user = selectedUser, let upn = user.userPrincipalName else { return }
        signInsTask?.cancel()
        let query = SignInQuery(userPrincipalName: upn, failuresOnly: failuresOnly, last24Hours: last24Hours)
        signInsTask = Task { [weak self] in
            guard let self else { return }
            isLoadingSignIns = true
            signInsError = nil
            lastFailureWasConsent = false
            let started = Date()
            defer { isLoadingSignIns = false }
            do {
                let events = try await provider.signIns(query)
                guard !Task.isCancelled else { return }
                signIns = events
                await Self.record(.success, since: started)
            } catch {
                guard !Task.isCancelled else { return }
                signInsError = Self.describe(error)
                lastFailureWasConsent = (error as? SignInTriageError) == .consentRequired
                await Self.record(Self.outcome(for: error), since: started)
            }
        }
    }

    static func record(_ outcome: DiagnosticOutcome, since started: Date) async {
        await DiagnosticsRecorder.shared.record(
            .graphRead, outcome,
            endpointTemplate: "/v1.0" + SignInTriageService.signInsPath,
            durationMs: Int(Date().timeIntervalSince(started) * 1000))
    }

    static func outcome(for error: Error) -> DiagnosticOutcome {
        guard let e = error as? SignInTriageError else { return .unknown }
        switch e {
        case .consentRequired:    return .consentRequired
        case .notAuthorized:      return .notAuthorized
        case .throttled:          return .throttled
        case .serviceUnavailable: return .serviceUnavailable
        case .transport:          return .transportError
        case .decodeFailure:      return .decodeFailure
        case .cancelled:          return .userCancelled
        }
    }

    static func describe(_ error: Error) -> String {
        guard let e = error as? SignInTriageError else {
            return "Couldn't load sign-ins. Check your connection and try again."
        }
        switch e {
        case .consentRequired:
            return "This organization hasn't granted TenantKeep permission to read the sign-in log yet."
        case .notAuthorized:
            return "Your account can't read the sign-in log, or this tenant has no Entra ID P1. Reports Reader, Security Reader or Global Reader can read it."
        case .throttled(let retryAfter):
            if let retryAfter { return "Microsoft Graph is rate limiting this tenant. Try again in about \(Int(retryAfter)) seconds." }
            return "Microsoft Graph is rate limiting this tenant. Wait a moment and try again."
        case .serviceUnavailable:
            return "Microsoft Entra isn't responding right now. Try again shortly."
        case .transport(let status):
            return "The request failed (HTTP \(status)). Check your connection and try again."
        case .decodeFailure:
            return "Microsoft Graph returned something unexpected. Try again, and let us know if it keeps happening."
        case .cancelled:
            return "Cancelled."
        }
    }
}

// MARK: - content column

struct PeopleView: View {
    @Bindable var directory: PeopleDirectoryModel
    let isDemo: Bool
    /// The open person, by id. The shell owns it and builds the detail column from it.
    @Binding var selection: String?
    var requestConsent: (() async -> String?)? = nil

    @State private var consentMessage: String?

    var body: some View {
        let _ = PerfProbe.body("PeopleView")
        Group {
            if let error = directory.errorMessage, directory.entries.isEmpty {
                errorState(error)
            } else if directory.entries.isEmpty, directory.fill != .complete {
                HStack(spacing: 8) { ProgressView(); Text("Reading the directory").font(.footnote).foregroundStyle(.secondary) }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                list
            }
        }
        .navigationTitle("People")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .searchable(text: $directory.query, prompt: "Name or sign-in address")
        .refreshable { await directory.refresh() }
        .task { directory.loadIfNeeded() }
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    private var list: some View {
        ScrollViewReader { proxy in
            List(selection: $selection) {
                PeopleNote(directory: directory)
                ForEach(directory.visible) { entry in
                    // A value link: the shell owns the selection and builds the person's page
                    // from it, beside the list on iPad and pushed over it on iPhone.
                    NavigationLink(value: entry.id) {
                        PersonRow(entry: entry)
                    }
                }
                if directory.visible.isEmpty, !directory.query.trimmingCharacters(in: .whitespaces).isEmpty {
                    PeopleNoMatch(directory: directory)
                }
            }
            .listStyle(.plain)
            // A person opened from an incident, an alert or a saved search comes into view.
            // No anchor scrolls the least it can, so a tapped row, already in view, stays put.
            .onChange(of: selection) { _, id in
                if let id { withAnimation { proxy.scrollTo(id) } }
            }
        }
    }

    @ViewBuilder
    private func errorState(_ error: String) -> some View {
        ContentUnavailableView {
            Label("Can't Read the Directory", systemImage: "person.2.slash")
        } description: {
            Text(error)
        } actions: {
            if directory.lastFailureWasConsent, let requestConsent {
                ConsentRequestButton(request: requestConsent) { refusal in
                    consentMessage = refusal
                    if refusal == nil { directory.retry() }
                }
                if let consentMessage {
                    Text(consentMessage).font(.footnote).foregroundStyle(.secondary)
                }
            } else {
                Button("Try again") { directory.retry() }
            }
        }
    }
}

/// The line above the list: how many people, or how far the read has got. Its own view, so
/// a page landing redraws this line and the rows, not the search field and toolbar.
private struct PeopleNote: View {
    let directory: PeopleDirectoryModel

    var body: some View {
        if let note {
            HStack(spacing: 8) {
                if isReading { ProgressView().controlSize(.small) }
                Text(note).font(.footnote).foregroundStyle(.secondary)
            }
            .listRowSeparator(.hidden)
            .listRowBackground(Color.clear)
            .selectionDisabled()
        }
    }

    private var isReading: Bool {
        switch directory.fill {
        case .loading, .refreshing: return true
        case .idle, .complete, .incomplete: return false
        }
    }

    private var note: String? {
        let searching = !directory.query.trimmingCharacters(in: .whitespaces).isEmpty
        switch directory.fill {
        case .loading(let loaded):
            return searching
                ? "Still reading the directory, \(loaded) so far. Results update as they arrive."
                : "Reading the directory, \(loaded) so far."
        case .refreshing(let loaded):
            return "Refreshing the directory, \(loaded) read so far."
        case .incomplete(let loaded):
            return "The first \(loaded) people. Search asks Microsoft Graph for anyone not here."
        case .complete:
            if searching { return nil }
            return directory.entries.count == 1 ? "1 person" : "\(directory.entries.count) people"
        case .idle:
            return nil
        }
    }
}

/// Nobody in the list matches what was typed.
private struct PeopleNoMatch: View {
    let directory: PeopleDirectoryModel

    var body: some View {
        Group {
            if directory.isLookingUp {
                HStack(spacing: 8) { ProgressView(); Text("Asking Microsoft Graph").font(.footnote).foregroundStyle(.secondary) }
            } else if directory.isPartial {
                Text("Nobody loaded matches \"\(typed)\", and Microsoft Graph has no one whose name or sign-in address starts with it.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else {
                Text("Nobody matches \"\(typed)\".").foregroundStyle(.secondary)
            }
        }
        .listRowSeparator(.hidden)
        .selectionDisabled()
    }

    private var typed: String { directory.query.trimmingCharacters(in: .whitespaces) }
}

struct PersonRow: View {
    let entry: DirectoryEntry

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.title)
                if let address = entry.address, address != entry.title {
                    Text(address)
                        .font(Brand.data(12))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            if entry.isGuest {
                Spacer(minLength: 8)
                Text("Guest")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.16), in: Capsule())
            }
        }
        .accessibilityElement(children: .combine)
    }
}

struct SignInRow: View {
    let event: SignInEvent
    let glossary: ErrorGlossary

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(event.isFailure ? "Failed" : "Success")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background((event.isFailure ? Color.orange : Color.green).opacity(0.16), in: Capsule())
                if event.isFailure {
                    Text(String(event.errorCode)).font(Brand.data(12)).foregroundStyle(.secondary)
                }
                if event.isLegacyClient {
                    Text("Legacy auth")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.red.opacity(0.14), in: Capsule())
                }
                if event.hasRisk {
                    Text("Risk").font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.red.opacity(0.14), in: Capsule())
                }
                Spacer(minLength: 8)
                if let date = event.createdDateTime {
                    Text(Self.relative(date))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .fixedSize()
                }
            }
            Text(event.isFailure
                 ? (glossary.entry(for: event.errorCode)?.title ?? event.status?.failureReason ?? "Failed")
                 : (event.appDisplayName ?? "Signed in"))
                .font(.subheadline.weight(.medium))
            // One string, so it wraps as a sentence rather than as two columns.
            if let caption {
                Text(caption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 3)
    }

    private var caption: String? {
        var parts: [String] = []
        if event.isFailure, let app = event.appDisplayName { parts.append(app) }
        if let blocked = event.blockingPolicies.first?.displayName { parts.append("Blocked by " + blocked) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    /// Minutes and hours, never seconds: a value that ticks on every refresh is noise.
    static func relative(_ date: Date) -> String {
        RelativeDates.short(date)
    }
}

// MARK: - detail column

struct SignInDetailView: View {
    let event: SignInEvent
    let glossary: ErrorGlossary

    var body: some View {
        List {
            outcomeSection
            policySection
            deviceSection
            whereSection
            riskSection
            identitySection
        }
        .navigationTitle(event.appDisplayName ?? "Sign-in")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    private var outcomeSection: some View {
        Section {
            if event.isFailure {
                let entry = glossary.entry(for: event.errorCode)
                Text(entry?.title ?? "Failed with code \(event.errorCode)").font(.headline)
                if let entry {
                    Text(entry.meaning)
                    Text(entry.action).foregroundStyle(.secondary)
                } else if let reason = event.status?.failureReason {
                    Text(reason)
                }
                if let details = event.status?.additionalDetails, !details.isEmpty {
                    DataRow(label: "Detail", value: details, monospaced: false)
                }
                DataRow(label: "Code", value: String(event.errorCode))
            } else {
                Label("Signed in", systemImage: "checkmark.circle").foregroundStyle(.green)
            }
            DataRow(label: "When", value: event.createdDateTime?.formatted(date: .abbreviated, time: .shortened), monospaced: false)
            DataRow(label: "App", value: event.appDisplayName, monospaced: false)
            DataRow(label: "Resource", value: event.resourceDisplayName, monospaced: false)
            DataRow(label: "Client", value: event.clientAppUsed.map { event.isLegacyClient ? $0 + " (legacy authentication)" : $0 }, monospaced: false)
        } header: {
            Text("Outcome")
        } footer: {
            if event.isFailure, glossary.entry(for: event.errorCode) == nil {
                Text("This code is not in the glossary yet. Microsoft's own text is shown.")
            }
        }
    }

    @ViewBuilder
    private var policySection: some View {
        Section {
            DataRow(label: "Result", value: SignInVocabulary.conditionalAccessLabel(event.conditionalAccessStatus), monospaced: false)
            let policies = event.appliedConditionalAccessPolicies ?? []
            if policies.isEmpty {
                Text(event.conditionalAccessStatus?.lowercased() == "notapplied"
                     ? "No Conditional Access policy applied to this sign-in."
                     : "Applied policies are not shown. Reading them needs a Conditional Access reader role.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else {
                ForEach(event.decisivePolicies + policies.filter { !$0.applied }) { policy in
                    HStack(alignment: .firstTextBaseline) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(policy.displayName ?? policy.id)
                                .font(policy.failed ? .subheadline.weight(.semibold) : .subheadline)
                            if let controls = policy.enforcedGrantControls, !controls.isEmpty, policy.applied {
                                Text(controls.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        Text(SignInVocabulary.policyResultLabel(policy.result))
                            .font(.caption.weight(.medium))
                            .foregroundStyle(policy.failed ? .orange : .secondary)
                    }
                }
            }
        } header: {
            Text("Conditional Access")
        }
    }

    @ViewBuilder
    private var deviceSection: some View {
        if let device = event.deviceDetail {
            Section("Device") {
                DataRow(label: "Name", value: device.displayName)
                DataRow(label: "OS", value: device.operatingSystem, monospaced: false)
                DataRow(label: "Browser", value: device.browser, monospaced: false)
                DataRow(label: "Join type", value: device.trustType, monospaced: false)
                if let compliant = device.isCompliant {
                    DataRow(label: "Compliant", value: compliant ? "Yes" : "No", monospaced: false)
                }
                if let managed = device.isManaged {
                    DataRow(label: "Managed", value: managed ? "Yes" : "No", monospaced: false)
                }
                DataRow(label: "Device ID", value: device.deviceId)
            }
        }
    }

    private var whereSection: some View {
        Section("Where") {
            DataRow(label: "Location", value: event.location?.label, monospaced: false)
            DataRow(label: "IP address", value: event.ipAddress)
        }
    }

    private var riskSection: some View {
        Section {
            if event.riskIsHidden {
                Text("Risk details need Microsoft Entra ID P2. This tenant's sign-in reports them as hidden.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else {
                DataRow(label: "Sign-in risk", value: SignInVocabulary.riskLabel(event.riskLevelDuringSignIn), monospaced: false)
                DataRow(label: "User risk", value: SignInVocabulary.riskLabel(event.riskLevelAggregated), monospaced: false)
                DataRow(label: "State", value: SignInVocabulary.riskStateLabel(event.riskState), monospaced: false)
            }
        } header: {
            Text("Risk")
        }
    }

    private var identitySection: some View {
        Section("Sign-in") {
            DataRow(label: "User", value: event.userPrincipalName)
            DataRow(label: "Request ID", value: event.id)
            DataRow(label: "Correlation ID", value: event.correlationId)
        }
    }
}

// MARK: - Pro gate

/// What a free install sees in place of the module. Says what it is and where to get it,
/// and nothing else: no countdown, no nag.
struct ProGateView: View {
    let title: String
    let detail: String
    let openSettings: () -> Void

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: "star.circle")
        } description: {
            Text(detail)
        } actions: {
            Button("See plans in Settings") { openSettings() }
        }
    }
}

#Preview("People (demo)") {
    NavigationStack {
        PeopleView(
            directory: PeopleDirectoryModel(provider: DemoSignInTriageProvider(latency: .milliseconds(1))),
            isDemo: true,
            selection: .constant(nil))
    }
}

extension UserActionTarget: Identifiable {
    public var id: String { userId }
}
