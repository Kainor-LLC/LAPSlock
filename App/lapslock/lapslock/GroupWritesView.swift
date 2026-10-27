import SwiftUI
import Combine
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
final class PersonGroupsModel: ObservableObject {
    struct Pending: Identifiable, Equatable {
        let kind: GroupWriteKind
        let group: DirectoryGroup
        let decision: GroupWriteDecision
        let facts: GroupFacts
        var id: String { kind.rawValue + ":" + group.id }
    }

    @Published private(set) var groups: [DirectoryGroup] = []
    @Published private(set) var loading = true
    @Published private(set) var loadError: String?
    @Published private(set) var facts: [String: GroupFacts] = [:]
    @Published var searchText = ""
    @Published private(set) var results: [DirectoryGroup] = []
    @Published private(set) var searching = false
    @Published private(set) var searchedText = ""
    @Published var reviewing: Pending?
    @Published var typing: Pending?
    @Published var typedName = ""
    @Published private(set) var undoing: Pending?
    @Published private(set) var undoRemaining = 0
    @Published private(set) var working: String?
    @Published private(set) var note: String?
    @Published private(set) var errorMessage: String?
    @Published private(set) var pendingChallenge: (action: WriteAction, pending: Pending, challenge: ClaimsChallenge)?
    @Published private(set) var lastEntry: ShiftLogEntry?

    let member: GroupMember
    let policy: GroupWritePolicy
    private let provider: any GroupWritesProviding
    private var context: GroupWriteContext?
    private var undoWindow: UndoWindow?
    private var cancellables = Set<AnyCancellable>()
    private var searchTask: Task<Void, Never>?

    init(member: GroupMember, provider: any GroupWritesProviding, policy: GroupWritePolicy) {
        self.member = member
        self.provider = provider
        self.policy = policy
        $searchText
            .removeDuplicates()
            .debounce(for: .milliseconds(300), scheduler: DispatchQueue.main)
            .sink { [weak self] text in self?.search(text) }
            .store(in: &cancellables)
    }

    private var pendingKey: String { "groups:" + member.userId }
    private var strict: Bool { ManagedConfigStore.read().confirmationLevel == .strict }

    func load() async {
        loading = true
        defer { loading = false }
        let ctx = await provider.context(administrativeUnit: policy.administrativeUnit)
        context = ctx
        do {
            groups = try await provider.groups(of: member)
            loadError = nil
        } catch {
            loadError = "Couldn't list this person's groups."
        }
        await loadFacts(groups)
        lastEntry = await provider.lastLogEntry(userId: member.userId)
    }

    private func loadFacts(_ list: [DirectoryGroup]) async {
        guard let context else { return }
        let missing = list.filter { facts[$0.id] == nil }
        await withTaskGroup(of: (String, GroupFacts).self) { group in
            for item in missing {
                group.addTask { [provider] in (item.id, await provider.facts(for: item, in: context)) }
            }
            for await (id, found) in group { facts[id] = found }
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
            await loadFacts(results)
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
        reviewing = Pending(kind: kind, group: group, decision: decided, facts: found)
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
        switch await BiometricGate().authenticate(deviceName: nil) {
        case .authenticated: break
        case .unavailable(let reason): errorMessage = reason; return
        default: errorMessage = "Not confirmed. Nothing was sent."; return
        }
        let window = UndoWindow()
        let seconds = DeviceActionsModel.undoSeconds
        undoWindow = window
        undoing = pending
        undoRemaining = seconds
        await PendingActions.shared.register(window, for: pendingKey)
        let started = Date()
        let ticker = Task { @MainActor [weak self] in
            while let self, self.undoing != nil {
                self.undoRemaining = max(0, seconds - Int(Date().timeIntervalSince(started)))
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        let proceed = await window.wait(seconds: seconds)
        ticker.cancel()
        await PendingActions.shared.finished(pendingKey)
        undoing = nil
        undoWindow = nil
        if proceed {
            await send(pending)
        } else {
            note = pending.kind.title + " cancelled. Nothing was sent."
        }
    }

    func undo() {
        guard let window = undoWindow else { return }
        Task { await window.cancel() }
    }

    func sendNow() {
        guard let window = undoWindow else { return }
        Task { await window.proceedNow() }
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
    @StateObject private var model: PersonGroupsModel
    @Environment(\.scenePhase) private var scenePhase

    init(make: @escaping () -> PersonGroupsModel) {
        _model = StateObject(wrappedValue: make())
    }

    var body: some View {
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
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(pending.kind.title).font(.body.weight(.semibold))
                        Text(pending.group.name).font(.caption).lineLimit(2)
                        Text("Sending in \(model.undoRemaining) s").font(.caption).foregroundStyle(.secondary).monospacedDigit()
                    }
                    Spacer()
                    Button { model.sendNow() } label: { Text("Send now").padding(8) }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Send " + pending.kind.title.lowercased() + " now")
                    Button { model.undo() } label: { Text("Undo").font(.body.weight(.bold)).padding(.horizontal, 16).padding(.vertical, 8) }
                        .buttonStyle(.borderedProminent)
                        .accessibilityLabel("Undo " + pending.kind.title.lowercased())
                }
                .accessibilityElement(children: .contain)
                .padding(.horizontal, 16).padding(.vertical, 8)
                .background(.regularMaterial)
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
    @ObservedObject var model: PersonGroupsModel
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
                Section {
                    Button(pending.kind == .add ? "Add to group" : "Remove from group", role: pending.kind == .remove ? .destructive : nil) {
                        model.reviewed(pending)
                    }
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
    @ObservedObject var model: PersonGroupsModel
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
