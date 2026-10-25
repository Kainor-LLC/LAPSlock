import SwiftUI
import Combine
import ConditionalAccessKit
import DiagnosticsKit

// Conditional Access, read-only. Spec section 3.7.
//
// Two columns: the policy list sorted by last change with a badge on anything changed in
// the last seven days, and the policy itself with its assignments resolved to names. The
// one deliberate absence is any way to edit: if an administrator wants to change a policy
// from a parking lot, the app should not help them.
//
// Names are a courtesy, not a requirement. The list renders the moment the policies
// arrive; names fill in afterwards, and an id that could not be resolved is shown
// shortened rather than hidden, so a policy never looks narrower than it is.

@MainActor
final class ConditionalAccessListModel: ObservableObject {
    @Published private(set) var policies: [ConditionalAccessPolicy] = []
    @Published var query = ""
    /// Last change first, or by name. Remembered between launches.
    @Published var sortOrder: SortOrder {
        didSet { UserDefaults.standard.set(sortOrder.rawValue, forKey: Self.sortKey) }
    }
    static let sortKey = "settings.conditionalAccessSort"

    enum SortOrder: String, CaseIterable, Identifiable {
        case lastChanged
        case name
        var id: String { rawValue }
        var label: String {
            switch self {
            case .lastChanged: return "Last changed"
            case .name:        return "Name"
            }
        }
    }
    @Published private(set) var visible: [ConditionalAccessPolicy] = []
    @Published private(set) var isLoading = false
    @Published private(set) var errorMessage: String?
    /// True when the failure was a missing consent, so the screen can offer the prompt.
    @Published private(set) var lastFailureWasConsent = false
    @Published private(set) var names: [DirectoryReference: String] = [:]

    static let recentWindowDays = 7

    private let provider: any ConditionalAccessProviding
    private var cancellables = Set<AnyCancellable>()

    init(provider: any ConditionalAccessProviding) {
        self.provider = provider
        self.sortOrder = SortOrder(rawValue: UserDefaults.standard.string(forKey: Self.sortKey) ?? "") ?? .lastChanged
        Publishers.CombineLatest3(
            $policies,
            $query.removeDuplicates().debounce(for: .milliseconds(150), scheduler: DispatchQueue.main),
            $sortOrder.removeDuplicates())
            .map { policies, query, order in Self.sorted(Self.filter(policies, query: query), by: order) }
            .assign(to: &$visible)
    }

    static func filter(_ policies: [ConditionalAccessPolicy], query: String) -> [ConditionalAccessPolicy] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return policies }
        return policies.filter { $0.displayName.localizedCaseInsensitiveContains(trimmed) }
    }

    /// The provider already delivers last-change order; by name is applied here.
    static func sorted(_ policies: [ConditionalAccessPolicy], by order: SortOrder) -> [ConditionalAccessPolicy] {
        switch order {
        case .lastChanged: return policies
        case .name:        return policies.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
        }
    }

    func policy(_ id: String) -> ConditionalAccessPolicy? {
        policies.first { $0.id == id }
    }

    func load() async {
        isLoading = true
        errorMessage = nil
        lastFailureWasConsent = false
        let started = Date()
        defer { isLoading = false }
        do {
            policies = try await provider.policies()
            await Self.record(.success, since: started)
            await resolveNames()
        } catch {
            let typed = error as? ConditionalAccessError
            lastFailureWasConsent = typed == .consentRequired
            errorMessage = Self.describe(error)
            await Self.record(Self.outcome(for: error), since: started)
        }
    }

    /// Fills in names for every reference across the loaded policies. Silent on failure:
    /// the ids are already on screen.
    private func resolveNames() async {
        let refs = policies.reduce(into: Set<DirectoryReference>()) { $0.formUnion($1.references) }
        guard !refs.isEmpty, let resolved = try? await provider.names(for: refs) else { return }
        names.merge(resolved) { _, new in new }
    }

    func name(for reference: DirectoryReference) -> String {
        names[reference] ?? ConditionalAccessVocabulary.shortId(reference.id)
    }

    static func record(_ outcome: DiagnosticOutcome, since started: Date) async {
        await DiagnosticsRecorder.shared.record(
            .graphRead, outcome,
            endpointTemplate: "/v1.0" + ConditionalAccessService.policiesPath,
            durationMs: Int(Date().timeIntervalSince(started) * 1000))
    }

    static func outcome(for error: Error) -> DiagnosticOutcome {
        guard let e = error as? ConditionalAccessError else { return .unknown }
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
        guard let e = error as? ConditionalAccessError else {
            return "Couldn't load Conditional Access policies. Check your connection and try again."
        }
        switch e {
        case .consentRequired:
            return "This organization hasn't granted LAPSlock permission to read Conditional Access policies yet."
        case .notAuthorized:
            return "Your account can't read Conditional Access policies. You'll need a role such as Security Reader or Global Reader."
        case .throttled(let retryAfter):
            if let retryAfter {
                return "Microsoft Graph is rate limiting this tenant. Try again in about \(Int(retryAfter)) seconds."
            }
            return "Microsoft Graph is rate limiting this tenant. Wait a moment and try again."
        case .serviceUnavailable:
            return "Microsoft Entra isn't responding right now. This is on Microsoft's side. Try again shortly."
        case .transport(let status):
            return "The request failed (HTTP \(status)). Check your connection and try again."
        case .decodeFailure:
            return "Microsoft Graph returned something unexpected. Try again, and let us know if it keeps happening."
        case .cancelled:
            return "Cancelled."
        }
    }
}

/// One policy's audit trail, loaded on request because it costs a scope the list does not.
@MainActor
final class ConditionalAccessDetailModel: ObservableObject {
    let policy: ConditionalAccessPolicy
    @Published private(set) var changes: [PolicyChange]?
    @Published private(set) var isLoadingChanges = false
    @Published private(set) var changesError: String?
    @Published private(set) var changesNeedConsent = false

    private let provider: any ConditionalAccessProviding

    init(policy: ConditionalAccessPolicy, provider: any ConditionalAccessProviding) {
        self.policy = policy
        self.provider = provider
    }

    func loadChanges() async {
        isLoadingChanges = true
        changesError = nil
        changesNeedConsent = false
        defer { isLoadingChanges = false }
        do {
            changes = try await provider.changes(forPolicyId: policy.id)
        } catch {
            changesNeedConsent = (error as? ConditionalAccessError) == .consentRequired
            changesError = changesNeedConsent
                ? "Reading the audit log needs a permission this organization hasn't granted yet."
                : ConditionalAccessListModel.describe(error)
        }
    }
}

// MARK: - list column

struct ConditionalAccessListView: View {
    @ObservedObject var model: ConditionalAccessListModel
    let isDemo: Bool
    @Binding var selection: String?
    /// Requests the module's scopes interactively. Nil in demo.
    var requestConsent: (() async -> String?)? = nil

    @State private var isRequestingConsent = false
    @State private var consentMessage: String?

    var body: some View {
        Group {
            if model.isLoading && model.policies.isEmpty {
                loadingState
            } else if let error = model.errorMessage, model.policies.isEmpty {
                errorState(error)
            } else if model.policies.isEmpty {
                emptyState
            } else {
                policyList
            }
        }
        .navigationTitle("Conditional Access")
        // Inline: the large title truncates to "Conditional Acce…" in a 290 pt column.
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .searchable(text: $model.query, prompt: "Policy name")
        .refreshable { await model.load() }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Picker("Sort by", selection: $model.sortOrder) {
                        ForEach(ConditionalAccessListModel.SortOrder.allCases) { order in
                            Text(order.label).tag(order)
                        }
                    }
                } label: {
                    Image(systemName: "arrow.up.arrow.down")
                }
                .accessibilityLabel("Sort policies")
            }
        }
        .task {
            if model.policies.isEmpty { await model.load() }
        }
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    private var policyList: some View {
        List(selection: $selection) {
            Section {
                ForEach(model.visible) { policy in
                    NavigationLink(value: policy.id) {
                        ConditionalAccessRow(policy: policy)
                    }
                }
            } footer: {
                Text(model.sortOrder == .name
                     ? "Read-only. Sorted by name; anything changed in the last \(ConditionalAccessListModel.recentWindowDays) days carries a badge."
                     : "Read-only. Sorted by last change, newest first; anything changed in the last \(ConditionalAccessListModel.recentWindowDays) days carries a badge.")
            }
            if !model.query.isEmpty && model.visible.isEmpty {
                Text("No policies match \"\(model.query)\"")
                    .font(.subheadline.weight(.medium))
                    .frame(maxWidth: .infinity)
                    .listRowSeparator(.hidden)
            }
        }
    }

    private var loadingState: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("Loading policies…").font(.subheadline).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No Conditional Access policies", systemImage: "checkmark.shield")
        } description: {
            Text("This tenant has no Conditional Access policies, or none your account can read.")
        } actions: {
            Button("Check again") { Task { await model.load() } }
        }
    }

    private func errorState(_ message: String) -> some View {
        ContentUnavailableView {
            Label("Couldn't load policies", systemImage: "exclamationmark.triangle")
        } description: {
            VStack(spacing: 8) {
                Text(message)
                if let consentMessage {
                    Text(consentMessage).foregroundStyle(.secondary)
                }
            }
        } actions: {
            // Recoverable right here. Consent is granted per organization, so somebody who
            // works across tenants meets this every time they reach a new one.
            if model.lastFailureWasConsent, let requestConsent {
                Button {
                    Task {
                        isRequestingConsent = true
                        consentMessage = await requestConsent()
                        isRequestingConsent = false
                        if consentMessage == nil { await model.load() }
                    }
                } label: {
                    HStack {
                        if isRequestingConsent { ProgressView().padding(.trailing, 6) }
                        Text(isRequestingConsent ? "Requesting…" : "Request permission")
                    }
                }
                .disabled(isRequestingConsent)
            }
            Button("Try again") { Task { await model.load() } }
        }
    }
}

struct ConditionalAccessRow: View {
    let policy: ConditionalAccessPolicy

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(policy.displayName)
                .font(.body.weight(.medium))
                .lineLimit(2)
            HStack(spacing: 6) {
                PolicyStatePill(state: policy.state)
                if policy.changed(withinDays: ConditionalAccessListModel.recentWindowDays) {
                    // Primary text, not accent: on a selected row the background is the
                    // accent, and accent-on-accent made the badge vanish exactly where
                    // somebody had just tapped.
                    Text("Changed " + relative(policy.lastChanged))
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(Brand.accent.opacity(0.18), in: Capsule())
                        .foregroundStyle(.primary)
                } else if let date = policy.lastChanged {
                    Text("Changed " + relative(date))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 3)
    }

    private func relative(_ date: Date?) -> String {
        guard let date else { return "at an unknown time" }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

/// On, off, or report-only. Text as well as colour, so the state survives colour blindness.
struct PolicyStatePill: View {
    let state: ConditionalAccessPolicy.State

    private var color: Color {
        switch state {
        case .enabled:    return .green
        case .disabled:   return .secondary
        case .reportOnly: return .orange
        case .unknown:    return .secondary
        }
    }

    var body: some View {
        Text(state.label)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.14), in: Capsule())
            .foregroundStyle(color)
    }
}

// MARK: - detail column

struct ConditionalAccessDetailView: View {
    @StateObject var model: ConditionalAccessDetailModel
    /// Resolves an id to a name, from the list model's cache.
    let name: (DirectoryReference) -> String
    let isDemo: Bool
    /// Requests the audit scope interactively. Nil in demo.
    var requestChangesConsent: (() async -> String?)? = nil

    @State private var isRequestingConsent = false
    @State private var consentMessage: String?

    private var policy: ConditionalAccessPolicy { model.policy }

    var body: some View {
        List {
            summarySection
            usersSection
            applicationsSection
            conditionsSection
            grantSection
            sessionSection
            changesSection
            identitySection
        }
        .navigationTitle(policy.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    private var summarySection: some View {
        Section {
            HStack {
                Text("State")
                Spacer()
                PolicyStatePill(state: policy.state)
            }
            LabeledContent("Last changed", value: absolute(policy.lastChanged))
            if let created = policy.createdDateTime {
                LabeledContent("Created", value: absolute(created))
            }
        } footer: {
            if policy.state == .reportOnly {
                Text("Report-only: the policy is evaluated and logged but never enforced.")
            }
        }
    }

    // MARK: assignments

    private var usersSection: some View {
        Section("Users") {
            assignmentRows("Include", keywords: policy.conditions.users.includeUsers, label: ConditionalAccessVocabulary.userLabel, kind: .user)
            assignmentRows("Include groups", keywords: policy.conditions.users.includeGroups, label: { $0 }, kind: .group)
            assignmentRows("Include roles", keywords: policy.conditions.users.includeRoles, label: { $0 }, kind: .role)
            assignmentRows("Exclude", keywords: policy.conditions.users.excludeUsers, label: ConditionalAccessVocabulary.userLabel, kind: .user)
            assignmentRows("Exclude groups", keywords: policy.conditions.users.excludeGroups, label: { $0 }, kind: .group)
            assignmentRows("Exclude roles", keywords: policy.conditions.users.excludeRoles, label: { $0 }, kind: .role)
        }
    }

    private var applicationsSection: some View {
        Section("Target resources") {
            assignmentRows("Include", keywords: policy.conditions.applications.includeApplications, label: ConditionalAccessVocabulary.applicationLabel, kind: .application)
            assignmentRows("Exclude", keywords: policy.conditions.applications.excludeApplications, label: ConditionalAccessVocabulary.applicationLabel, kind: .application)
            if !policy.conditions.applications.includeUserActions.isEmpty {
                row("User actions", policy.conditions.applications.includeUserActions.joined(separator: ", "))
            }
            if !policy.conditions.applications.includeAuthenticationContextClassReferences.isEmpty {
                row("Authentication contexts", policy.conditions.applications.includeAuthenticationContextClassReferences.joined(separator: ", "))
            }
        }
    }

    /// Keywords read as English; ids read as names, or as shortened ids when no name came
    /// back. Nothing is dropped: an unresolved id still counts.
    @ViewBuilder
    private func assignmentRows(
        _ title: String,
        keywords: [String],
        label: (String) -> String,
        kind: DirectoryReference.Kind
    ) -> some View {
        if !keywords.isEmpty {
            let values = keywords.map { token -> String in
                ConditionalAccessVocabulary.isDirectoryId(token)
                    ? name(DirectoryReference(kind: kind, id: token))
                    : label(token)
            }
            row(title, values.joined(separator: "\n"))
        }
    }

    // MARK: conditions

    @ViewBuilder
    private var conditionsSection: some View {
        let c = policy.conditions
        let hasAny = !(c.platforms?.includePlatforms.isEmpty ?? true)
            || !(c.locations?.includeLocations.isEmpty ?? true)
            || !c.clientAppTypes.isEmpty
            || !c.signInRiskLevels.isEmpty
            || !c.userRiskLevels.isEmpty
            || c.devices?.deviceFilter != nil
        if hasAny {
            Section("Conditions") {
                if let platforms = c.platforms, !platforms.includePlatforms.isEmpty {
                    row("Platforms", platforms.includePlatforms.map(ConditionalAccessVocabulary.platformLabel).joined(separator: ", "))
                    if !platforms.excludePlatforms.isEmpty {
                        row("Exclude platforms", platforms.excludePlatforms.map(ConditionalAccessVocabulary.platformLabel).joined(separator: ", "))
                    }
                }
                if let locations = c.locations, !locations.includeLocations.isEmpty {
                    assignmentRows("Locations", keywords: locations.includeLocations, label: ConditionalAccessVocabulary.locationLabel, kind: .location)
                    assignmentRows("Exclude locations", keywords: locations.excludeLocations, label: ConditionalAccessVocabulary.locationLabel, kind: .location)
                }
                if !c.clientAppTypes.isEmpty {
                    row("Client apps", c.clientAppTypes.map(ConditionalAccessVocabulary.clientAppLabel).joined(separator: "\n"))
                }
                if !c.signInRiskLevels.isEmpty {
                    row("Sign-in risk", c.signInRiskLevels.map(ConditionalAccessVocabulary.riskLabel).joined(separator: ", "))
                }
                if !c.userRiskLevels.isEmpty {
                    row("User risk", c.userRiskLevels.map(ConditionalAccessVocabulary.riskLabel).joined(separator: ", "))
                }
                if let filter = c.devices?.deviceFilter {
                    row("Device filter (" + filter.mode + ")", filter.rule, monospaced: true)
                }
            }
        }
    }

    // MARK: controls

    @ViewBuilder
    private var grantSection: some View {
        if let grant = policy.grantControls {
            Section {
                if !grant.builtInControls.isEmpty {
                    row(grant.builtInControls.count > 1 ? "Require " + (grant.operator == "AND" ? "all of" : "one of") : "Require",
                        grant.builtInControls.map(ConditionalAccessVocabulary.grantControlLabel).joined(separator: "\n"))
                }
                if let strength = grant.authenticationStrength?.displayName {
                    row("Authentication strength", strength)
                }
                if !grant.termsOfUse.isEmpty {
                    row("Terms of use", grant.termsOfUse.count == 1 ? "1 agreement" : "\(grant.termsOfUse.count) agreements")
                }
                if !grant.customAuthenticationFactors.isEmpty {
                    row("Custom controls", grant.customAuthenticationFactors.joined(separator: ", "))
                }
            } header: {
                Text("Grant")
            }
        } else {
            Section("Grant") {
                Text("No grant controls. Session controls only.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var sessionSection: some View {
        if let session = policy.sessionControls {
            Section("Session") {
                if let frequency = session.signInFrequency, frequency.isEnabled == true {
                    if frequency.frequencyInterval == "everyTime" {
                        row("Sign-in frequency", "Every time")
                    } else if let value = frequency.value, let unit = frequency.type {
                        row("Sign-in frequency", "Every \(value) \(unit)")
                    }
                }
                if let browser = session.persistentBrowser, browser.isEnabled == true, let mode = browser.mode {
                    row("Persistent browser session", mode == "always" ? "Always persist" : "Never persist")
                }
                if session.applicationEnforcedRestrictions?.isEnabled == true {
                    row("App-enforced restrictions", "On")
                }
                if let cas = session.cloudAppSecurity, cas.isEnabled == true {
                    row("Defender for Cloud Apps", cas.cloudAppSecurityType ?? "On")
                }
                if session.disableResilienceDefaults == true {
                    row("Resilience defaults", "Disabled")
                }
            }
        }
    }

    // MARK: who changed this

    private var changesSection: some View {
        Section {
            if let changes = model.changes {
                if changes.isEmpty {
                    Text("No audit entries for this policy in the retained window.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(changes) { change in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(change.activity)
                                .font(.subheadline.weight(.medium))
                            if let actor = change.actor {
                                Text(actor)
                                    .font(Brand.data(13))
                            }
                            HStack(spacing: 6) {
                                Text(absolute(change.at))
                                if change.result == "failure" {
                                    Text("Failed")
                                        .font(.caption2.weight(.medium))
                                        .foregroundStyle(.orange)
                                }
                            }
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 2)
                    }
                }
            } else if model.isLoadingChanges {
                HStack { ProgressView(); Text("Reading the audit log…").padding(.leading, 6) }
            } else if let error = model.changesError {
                Text(error).font(.footnote).foregroundStyle(.secondary)
                if model.changesNeedConsent, let requestChangesConsent {
                    Button {
                        Task {
                            isRequestingConsent = true
                            consentMessage = await requestChangesConsent()
                            isRequestingConsent = false
                            if consentMessage == nil { await model.loadChanges() }
                        }
                    } label: {
                        HStack {
                            if isRequestingConsent { ProgressView().padding(.trailing, 6) }
                            Text(isRequestingConsent ? "Requesting…" : "Request permission")
                        }
                    }
                    .disabled(isRequestingConsent)
                    if let consentMessage {
                        Text(consentMessage).font(.footnote).foregroundStyle(.secondary)
                    }
                }
                Button("Try again") { Task { await model.loadChanges() } }
            } else {
                Button("Who changed this") { Task { await model.loadChanges() } }
            }
        } header: {
            Text("Changes")
        } footer: {
            if model.changes == nil && !model.isLoadingChanges && model.changesError == nil {
                Text("Reads your organization's directory audit log for entries that touched this policy. Asks for audit-log permission the first time.")
            }
        }
    }

    private var identitySection: some View {
        Section("Policy") {
            DataRow(label: "Policy ID", value: policy.id)
        }
    }

    // MARK: helpers

    private func row(_ label: String, _ value: String, monospaced: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label.uppercased())
                .font(Brand.fieldLabel)
                .foregroundStyle(.secondary)
            Text(value)
                .font(monospaced ? Brand.data(13) : .body)
                .textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }

    private func absolute(_ date: Date?) -> String {
        guard let date else { return "Unknown" }
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}

#Preview("Conditional Access list (demo)") {
    NavigationStack {
        ConditionalAccessListView(
            model: ConditionalAccessListModel(provider: DemoConditionalAccessProvider(latency: .milliseconds(1))),
            isDemo: true,
            selection: .constant(nil))
    }
}

#Preview("Policy detail (demo)") {
    NavigationStack {
        ConditionalAccessDetailView(
            model: ConditionalAccessDetailModel(
                policy: DemoConditionalAccessProvider.policies(now: Date())[4],
                provider: DemoConditionalAccessProvider(latency: .milliseconds(1))),
            name: { DemoConditionalAccessProvider.names[$0.id] ?? ConditionalAccessVocabulary.shortId($0.id) },
            isDemo: true)
    }
}
