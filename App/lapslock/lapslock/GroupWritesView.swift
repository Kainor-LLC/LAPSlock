import SwiftUI
import ActionGateKit
import GroupWritesKit
import PlatformSecurity
import PrivilegedAccessKit
import ManagedConfigKit

// Group membership. Spec section 3.10, phase 3 step G. The detail page for a person's
// groups in People: the groups they are directly in, each with its badges and Remove where
// the rules allow, and Add to a group with a search. The rules are GroupWritePolicy in the
// kit; this screen only shows them. Every change is reviewed first (member count, badges,
// what the group grants); one that needs the typed name gets Face ID and the countdown
// with Undo and Send now, and is cancelled if the page goes, like every destructive write.

@MainActor
@Observable
final class PersonGroupsModel {
    struct Pending: Identifiable, Equatable {
        let kind: GroupWriteKind
        let group: DirectoryGroup
        let decision: GroupWriteDecision
        let facts: GroupFacts
        var id: String { kind.rawValue + ":" + group.id }
    }

    private(set) var groups: [DirectoryGroup] = []
    private(set) var loading = true
    private(set) var loadError: String?
    private(set) var facts: [String: GroupFacts] = [:]
    /// What is typed. The directory is searched once typing pauses.
    var searchText = "" {
        didSet { if searchText != oldValue { scheduleSearch() } }
    }
    private(set) var results: [DirectoryGroup] = []
    private(set) var searching = false
    private(set) var searchedText = ""
    var reviewing: Pending?
    var typing: Pending?
    var typedName = ""
    private(set) var undoing: Pending?
    private(set) var undoRemaining = 0
    private(set) var working: String?
    private(set) var note: String?
    private(set) var errorMessage: String?
    private(set) var pendingChallenge: (action: WriteAction, pending: Pending, challenge: ClaimsChallenge)?
    private(set) var lastEntry: ShiftLogEntry?
    /// The role check made when the review sheet opened, for the change it shows. Nil
    /// while it runs and when it says go ahead.
    private(set) var reviewRoleCheck: (id: String, outcome: ActionOutcome)?

    let member: GroupMember
    let policy: GroupWritePolicy
    private let provider: any GroupWritesProviding
    @ObservationIgnored private var context: GroupWriteContext?
    @ObservationIgnored private var countdown: UndoCountdown?
    @ObservationIgnored private var debounceTask: Task<Void, Never>?
    @ObservationIgnored private var searchTask: Task<Void, Never>?
    /// Facts are read for the rows on screen, `factsWidth` groups at a time, rather than
    /// for every group at once: a person in 300 groups was 900 reads in one burst
    /// (OPTIMIZATION-PLAN.md, step G).
    static let factsWidth = 6
    @ObservationIgnored private var factsWaiting: [DirectoryGroup] = []
    @ObservationIgnored private var factsAsked: Set<String> = []
    @ObservationIgnored private var factsRunning = 0

    init(member: GroupMember, provider: any GroupWritesProviding, policy: GroupWritePolicy) {
        self.member = member
        self.provider = provider
        self.policy = policy
    }

    deinit { debounceTask?.cancel() }

    private func scheduleSearch() {
        debounceTask?.cancel()
        debounceTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled, let self else { return }
            self.search(self.searchText)
        }
    }

    private var pendingKey: String { "groups:" + member.userId }
    private var strict: Bool { ManagedConfigStore.shared.config.confirmationLevel == .strict }

    func load() async {
        loading = true
        defer { loading = false }
        let ctx = await provider.context(administrativeUnit: policy.administrativeUnit)
        context = ctx
        pumpFacts()
        do {
            groups = try await provider.groups(of: member)
            loadError = nil
        } catch {
            loadError = "Couldn't list this person's groups."
        }
        lastEntry = await provider.lastLogEntry(userId: member.userId)
    }

    /// A row came on screen: its group's facts are read when there is room.
    func wantFacts(_ group: DirectoryGroup) {
        guard facts[group.id] == nil, !factsAsked.contains(group.id) else { return }
        factsAsked.insert(group.id)
        factsWaiting.append(group)
        pumpFacts()
    }

    /// A row left the screen before its turn: its reads are not made.
    func dropFacts(_ group: DirectoryGroup) {
        guard let index = factsWaiting.firstIndex(where: { $0.id == group.id }) else { return }
        factsWaiting.remove(at: index)
        factsAsked.remove(group.id)
    }

    private func pumpFacts() {
        guard let context else { return }
        while factsRunning < Self.factsWidth, !factsWaiting.isEmpty {
            let group = factsWaiting.removeFirst()
            factsRunning += 1
            PerfProbe.mark("groupFacts", "running " + String(factsRunning) + ", waiting " + String(factsWaiting.count))
            Task { [weak self, provider] in
                let found = await provider.facts(for: group, in: context)
                guard let self else { return }
                self.facts[group.id] = found
                self.factsRunning -= 1
                self.pumpFacts()
            }
        }
    }

    private func search(_ text: String) {
        searchTask?.cancel()
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 2 else {
            results = []
            searchedText = ""
            return
        }
        searchTask = Task { [weak self] in
            guard let self else { return }
            searching = true
            defer { searching = false }
            let found = (try? await provider.search(trimmed)) ?? []
            guard !Task.isCancelled else { return }
            let current = Set(groups.map(\.id))
            results = found.filter { !current.contains($0.id) }
            searchedText = trimmed
        }
    }

    var trimmedSearch: String { searchText.trimmingCharacters(in: .whitespacesAndNewlines) }

    func decision(_ group: DirectoryGroup, adding: Bool) -> GroupWriteDecision? {
        facts[group.id].map { policy.decide(group, $0, adding: adding) }
    }

    func badges(_ group: DirectoryGroup) -> [GroupBadge] {
        facts[group.id].map { policy.badges(group, $0) } ?? []
    }

    func tapped(_ kind: GroupWriteKind, _ group: DirectoryGroup) {
        guard working == nil, undoing == nil, let found = facts[group.id] else { return }
        let decided = policy.decide(group, found, adding: kind == .add)
        guard decided.isAllowed else { return }
        clearMessages()
        let pending = Pending(kind: kind, group: group, decision: decided, facts: found)
        reviewing = pending
        // The role check runs as the sheet opens, so "activate first" comes before the
        // typed name and Face ID. The check just before sending stays.
        reviewRoleCheck = nil
        let action = kind.action(group: group, member: member, decision: decided, strict: strict)
        Task { [weak self, provider] in
            guard let outcome = await provider.checkRoles(action) else { return }
            guard let self, self.reviewing?.id == pending.id else { return }
            self.reviewRoleCheck = (pending.id, outcome)
        }
    }

    /// What the review sheet says instead of letting the change go on, when its role
    /// check found the role eligible but not active.
    func roleNote(_ pending: Pending) -> String? {
        guard let check = reviewRoleCheck, check.id == pending.id, case .needsActivation = check.outcome else { return nil }
        return "Your groups role isn't active. Activate it in Privileged Access first, then come back to this change."
    }

    func tier(_ pending: Pending) -> ActionTier { pending.decision.tier.effective(strict: strict) }

    /// The review sheet's confirm. The destructive tier goes on to the typed name.
    func reviewed(_ pending: Pending) {
        reviewing = nil
        if tier(pending) == .destructive {
            typedName = ""
            typing = pending
        } else {
            Task { await send(pending) }
        }
    }

    func typedNameMatches(_ pending: Pending) -> Bool {
        typedName.trimmingCharacters(in: .whitespacesAndNewlines).caseInsensitiveCompare(pending.group.name) == .orderedSame
    }

    /// Face ID, then the countdown with Undo and Send now, then the change.
    func typedConfirmed(_ pending: Pending) async {
        typing = nil
        guard typedNameMatches(pending) else { return }
        switch await BiometricGate().authenticate(for: .groupChange(adding: pending.kind == .add, member: member.label, group: pending.group.name)) {
        case .authenticated: break
        case .unavailable(let reason): errorMessage = reason; return
        default: errorMessage = "Not confirmed. Nothing was sent."; return
        }
        let countdown = UndoCountdown(key: pendingKey, seconds: DeviceActionsModel.undoSeconds)
        self.countdown = countdown
        undoing = pending
        let proceed = await countdown.run { @MainActor [weak self] left in self?.undoRemaining = left }
        undoing = nil
        self.countdown = nil
        if proceed {
            await send(pending)
        } else {
            note = pending.kind.title + " cancelled. Nothing was sent."
        }
    }

    func undo() {
        guard let countdown else { return }
        Task { await countdown.undo() }
    }

    func sendNow() {
        guard let countdown else { return }
        Task { await countdown.sendNow() }
    }

    func continueSignIn() async {
        guard let waiting = pendingChallenge else { return }
        pendingChallenge = nil
        working = waiting.pending.group.id
        defer { working = nil }
        handle(await provider.resume(waiting.action, satisfying: waiting.challenge), waiting.pending, waiting.action)
        lastEntry = await provider.lastLogEntry(userId: member.userId)
    }

    private func send(_ pending: Pending) async {
        working = pending.group.id
        defer { working = nil }
        let action = pending.kind.action(group: pending.group, member: member, decision: pending.decision, strict: strict)
        handle(await provider.run(action), pending, action)
        lastEntry = await provider.lastLogEntry(userId: member.userId)
    }

    private func handle(_ outcome: ActionOutcome, _ pending: Pending, _ action: WriteAction) {
        switch outcome {
        case .requested:
            note = action.successCopy + (pending.kind == .add ? " Access can take a few minutes to follow." : "")
            // Graph's lists catch up in a few seconds; the page shows the change now.
            if pending.kind == .add {
                groups = (groups + [pending.group]).sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
                results.removeAll { $0.id == pending.group.id }
            } else {
                groups.removeAll { $0.id == pending.group.id }
            }
        case .needsActivation:
            errorMessage = "Your groups role isn't active. Activate it in Privileged Access, then try again."
        case .notAuthorized:
            errorMessage = "Your account can't change this group. Groups Administrator, scoped to the group's administrative unit, or ownership of the group, is needed."
        case .challenged(let challenge):
            pendingChallenge = (action, pending, challenge)
            errorMessage = "Microsoft wants a fresh sign-in step before changing this group."
        case .failed(let failure):
            errorMessage = failure.description
        }
    }

    private func clearMessages() {
        note = nil
        errorMessage = nil
        pendingChallenge = nil
    }

    func closed() {
        let key = pendingKey
        Task { _ = await PendingActions.shared.cancel(key) }
    }

    /// The rules in words, under the list.
    var policySummary: String {
        switch policy.mode {
        case .none:
            return "Your organization has turned off group changes in this app."
        case .tagged:
            return "Changes allowed to groups in " + policy.administrativeUnit
                + (policy.prefix.map { ", groups whose names start " + $0 } ?? "")
                + ", and groups you own. Role-assignable, dynamic, PIM, synced and mail groups are never changed here, and a group a Conditional Access policy names is left alone."
        case .all:
            return "Changes allowed to any group your role covers. Role-assignable, dynamic, PIM, synced and mail groups are never changed here; a group a Conditional Access policy names needs its name typed back."
        }
    }
}

// MARK: - the page

struct PersonGroupsView: View {
    @StateModel private var model: PersonGroupsModel
    @Environment(\.scenePhase) private var scenePhase

    init(make: @escaping () -> PersonGroupsModel) {
        _model = StateModel(wrappedValue: make())
    }

    var body: some View {
        let _ = PerfProbe.body("PersonGroupsView")
        List {
            if model.note != nil || model.errorMessage != nil || model.pendingChallenge != nil {
                Section {
                    if let note = model.note { Text(note).font(.footnote) }
                    if let error = model.errorMessage { Text(error).font(.footnote).foregroundStyle(.red) }
                    if model.pendingChallenge != nil {
                        Button("Continue sign-in") { Task { await model.continueSignIn() } }
                    }
                }
            }
            Section {
                if model.loading && model.groups.isEmpty {
                    HStack(spacing: 8) { ProgressView(); Text("Reading their groups").font(.footnote).foregroundStyle(.secondary) }
                } else if let error = model.loadError {
                    Text(error).font(.footnote).foregroundStyle(.secondary)
                } else if model.groups.isEmpty {
                    Text("Not directly in any group.").font(.footnote).foregroundStyle(.secondary)
                } else {
                    ForEach(model.groups) { group in
                        GroupRow(group: group, badges: model.badges(group), decision: model.decision(group, adding: false),
                                 kind: .remove, working: model.working == group.id, busy: model.working != nil || model.undoing != nil) {
                            model.tapped(.remove, group)
                        }
                        .onAppear { model.wantFacts(group) }
                        .onDisappear { model.dropFacts(group) }
                    }
                }
            } header: {
                Text("Groups")
            } footer: {
                if let entry = model.lastEntry {
                    Text("Last from this app: " + entry.actionTitle + ", " + entry.targetLabel + ", " + entry.outcome)
                }
            }
            Section {
                TextField("Search groups by name", text: $model.searchText)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if model.searching || (model.trimmedSearch.count >= 2 && model.searchedText != model.trimmedSearch) {
                    HStack(spacing: 8) { ProgressView(); Text("Searching…").font(.footnote).foregroundStyle(.secondary) }
                } else if model.trimmedSearch.count >= 2 && model.results.isEmpty {
                    Text("No other group matches.").font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(model.results) { group in
                    GroupRow(group: group, badges: model.badges(group), decision: model.decision(group, adding: true),
                             kind: .add, working: model.working == group.id, busy: model.working != nil || model.undoing != nil) {
                        model.tapped(.add, group)
                    }
                    .onAppear { model.wantFacts(group) }
                    .onDisappear { model.dropFacts(group) }
                }
            } header: {
                Text("Add to a Group")
            } footer: {
                Text(model.policySummary)
            }
        }
        .navigationTitle(model.member.label)
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .bottom) {
            if let pending = model.undoing {
                UndoBar(title: pending.kind.title, detail: pending.group.name, spokenAction: pending.kind.title,
                        remaining: model.undoRemaining, floating: true, sendNow: { model.sendNow() }, undo: { model.undo() })
            }
        }
        .sheet(item: $model.reviewing) { pending in
            GroupReviewSheet(model: model, pending: pending)
        }
        .sheet(item: $model.typing) { pending in
            GroupTypedNameSheet(model: model, pending: pending)
        }
        .task { await model.load() }
        .onDisappear { model.closed() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { Task { await PendingActions.shared.cancelAll() } }
        }
    }
}

private struct GroupRow: View {
    let group: DirectoryGroup
    let badges: [GroupBadge]
    let decision: GroupWriteDecision?
    let kind: GroupWriteKind
    let working: Bool
    let busy: Bool
    let action: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(group.name)
                if !badges.isEmpty {
                    Text(badges.map(\.label).joined(separator: " · "))
                        .font(.caption)
                        .foregroundStyle(badges.contains(where: \.isBlocking) ? Color.orange : Color.secondary)
                }
                if let reason = decision?.blockedReason {
                    Text(reason).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if working {
                ProgressView()
            } else if decision == nil {
                ProgressView().controlSize(.small).accessibilityLabel("Checking this group")
            } else if decision?.isAllowed == true {
                Button(kind == .add ? "Add" : "Remove", role: kind == .remove ? .destructive : nil, action: action)
                    .buttonStyle(.bordered)
                    .disabled(busy)
                    .accessibilityLabel((kind == .add ? "Add to " : "Remove from ") + group.name)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

/// Before any change: who, which group, how many members, what it grants, and the warnings.
private struct GroupReviewSheet: View {
    let model: PersonGroupsModel
    let pending: PersonGroupsModel.Pending
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("Person", value: model.member.label)
                    LabeledContent("Group", value: pending.group.name)
                    if let count = pending.facts.memberCount {
                        LabeledContent("Members now", value: String(count))
                    }
                    if !pending.decision.badges.isEmpty {
                        LabeledContent("Badges", value: pending.decision.badges.map(\.label).joined(separator: ", "))
                    }
                    if let description = pending.group.description, !description.isEmpty {
                        LabeledContent("About", value: description)
                    }
                    AwayTenantNote()
                }
                if !pending.decision.warnings.isEmpty {
                    Section("Before You Confirm") {
                        ForEach(pending.decision.warnings, id: \.self) { warning in
                            Label(warning, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.callout)
                        }
                    }
                }
                if let note = model.roleNote(pending) {
                    Section {
                        Label(note, systemImage: "person.badge.key").font(.callout)
                    }
                }
                Section {
                    Button(pending.kind == .add ? "Add to group" : "Remove from group", role: pending.kind == .remove ? .destructive : nil) {
                        model.reviewed(pending)
                    }
                    .disabled(model.roleNote(pending) != nil)
                } footer: {
                    Text(model.tier(pending) == .destructive
                         ? "Next: the group's name typed back, Face ID, and a moment to undo."
                         : "Made as you, with your role, and recorded in your tenant's audit log and the shift log.")
                }
            }
            .navigationTitle(pending.kind == .add ? "Add to Group" : "Remove from Group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
        // Full height: the confirm button sits below the warnings and must not be clipped.
        .presentationDetents([.large])
    }
}

private struct GroupTypedNameSheet: View {
    @Bindable var model: PersonGroupsModel
    let pending: PersonGroupsModel.Pending
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Type the group's name to confirm. " + pending.decision.warnings.joined(separator: " "))
                    AwayTenantNote()
                } header: {
                    Text(pending.kind.title)
                }
                Section {
                    TextField(pending.group.name, text: $model.typedName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } footer: {
                    Text("Then Face ID, and a few seconds to undo.")
                }
            }
            .navigationTitle(pending.group.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue") { Task { await model.typedConfirmed(pending) } }
                        .disabled(!model.typedNameMatches(pending))
                }
            }
        }
        .presentationDetents([.medium, .large])
    }
}
