import SwiftUI
import SignInTriageKit
import UserActionsKit
import DeviceActionsKit
import GroupWritesKit

// A person's page (DIGEST-AND-PEOPLE-PLAN.md, step L): the People module's detail column,
// pushed over the directory on iPhone and beside it on iPad. Their account at a glance,
// their actions, leaver checklist and groups, and their recent sign-ins with two filters.
// Each of those opens on this page's own stack, so Back returns to the person, not to the
// directory.

/// What the person's page opens.
enum PersonPage: Hashable {
    case actions
    case leaver
    case groups
    case signIn(String)
}

/// The detail column for People: the person's page, with what it opens pushed on top.
/// Built again for each person, so nothing of one person's stays on the next one's page.
struct PersonColumn: View {
    let user: DirectoryUser
    let model: SignInTriageModel
    let people: PeopleColumns

    @State private var path: [PersonPage] = []
    /// Bumped on the way back from what changes the account, so the lines read it again.
    @State private var snapshotTick = 0

    var body: some View {
        NavigationStack(path: $path) {
            PersonView(
                user: user,
                model: model,
                requestConsent: people.requestConsent,
                actionsAvailable: people.makeUserActions != nil,
                groupsAvailable: people.makeGroups != nil,
                snapshot: people.snapshot,
                snapshotTick: snapshotTick)
            .navigationDestination(for: PersonPage.self) { page in
                destination(page)
            }
        }
        .onChange(of: path) { old, new in
            // Back from the actions, the checklist or the groups: what was done shows in
            // the account lines.
            if old.dropFirst(new.count).contains(where: { !$0.isSignIn }) { snapshotTick += 1 }
        }
    }

    @ViewBuilder
    private func destination(_ page: PersonPage) -> some View {
        switch page {
        case .actions, .leaver:
            if let makeUserActions = people.makeUserActions, let upn = user.userPrincipalName {
                let target = UserActionTarget(userId: user.id, userPrincipalName: upn, displayName: user.displayName)
                PersonActionsPage(
                    make: { makeUserActions(target) },
                    mode: page == .leaver ? .leaver : .actions,
                    makeDeviceActions: people.makeDeviceActions)
            }
        case .groups:
            if let makeGroups = people.makeGroups {
                let member = GroupMember(userId: user.id, label: user.displayName ?? user.userPrincipalName ?? user.id)
                PersonGroupsView(make: { makeGroups(member) })
            }
        case .signIn(let id):
            if let event = model.signIn(id) {
                SignInDetailView(event: event, glossary: model.glossary)
            }
        }
    }
}

private extension PersonPage {
    var isSignIn: Bool {
        if case .signIn = self { return true }
        return false
    }
}

/// Actions and the leaver checklist, one page with the switch between them in its title bar.
private struct PersonActionsPage: View {
    let make: () -> UserActionsModel
    @State var mode: PersonActionsView.Mode
    let makeDeviceActions: ((DeviceActionTarget) -> DeviceActionsModel)?

    var body: some View {
        PersonActionsView(make: make, mode: $mode, makeDeviceActions: makeDeviceActions)
    }
}

struct PersonView: View {
    let user: DirectoryUser
    @Bindable var model: SignInTriageModel
    var requestConsent: (() async -> String?)?
    /// User actions are on: Actions, the leaver checklist and the account lines.
    let actionsAvailable: Bool
    /// Group changes are on: the Groups row.
    let groupsAvailable: Bool
    /// The person's state at a glance. Nil when user actions are off.
    var snapshot: ((UserActionTarget) async -> PersonSnapshot)?
    let snapshotTick: Int

    @State private var personSnapshot: PersonSnapshot?
    @State private var refreshTick = 0
    @State private var consentMessage: String?

    var body: some View {
        List {
            personSection
            filterSection
            signInsSection
        }
        .navigationTitle(user.displayName ?? user.userPrincipalName ?? "Person")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .task(id: String(snapshotTick) + "#" + String(refreshTick)) { await loadSnapshot() }
        .refreshable {
            refreshTick += 1
            await model.refreshSignIns()
        }
    }

    private var isGuest: Bool { DirectoryEntry(user).isGuest }

    private var target: UserActionTarget? {
        guard let upn = user.userPrincipalName else { return nil }
        return UserActionTarget(userId: user.id, userPrincipalName: upn, displayName: user.displayName)
    }

    private func loadSnapshot() async {
        guard let snapshot, let target else { personSnapshot = nil; return }
        let fresh = await snapshot(target)
        guard !Task.isCancelled else { return }
        personSnapshot = fresh
    }

    /// Who they are, then their actions, leaver checklist and groups, then their account at
    /// a glance. The links come before the account lines so they stay where they are: the
    /// lines arrive a moment later, and above the links they pushed them down by about 160
    /// points, under a tap already on its way.
    private var personSection: some View {
        Section {
            HStack(spacing: 8) {
                Text(user.userPrincipalName ?? user.mail ?? user.id)
                    .font(Brand.data(13))
                    .textSelection(.enabled)
                    .lineLimit(2)
                if isGuest {
                    Spacer(minLength: 8)
                    Text("Guest")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.16), in: Capsule())
                }
            }
            if actionsAvailable {
                NavigationLink(value: PersonPage.actions) {
                    Label("Actions", systemImage: "person.badge.shield.checkmark")
                }
                NavigationLink(value: PersonPage.leaver) {
                    Label("Leaver Checklist", systemImage: "checklist")
                }
            }
            if groupsAvailable {
                NavigationLink(value: PersonPage.groups) {
                    Label("Groups", systemImage: "person.2.square.stack")
                }
            }
            if snapshot == nil {
                EmptyView()
            } else if let snap = personSnapshot {
                let lines: [(String, String, Bool)] = [
                    snap.signInLine.map { ($0, snap.accountEnabled == false ? "nosign" : "checkmark.circle", snap.accountEnabled == false) },
                    snap.riskLine.map { ($0, "exclamationmark.triangle", snap.isRisky) },
                    snap.methodsLine.map { ($0, "key", false) },
                    snap.devicesLine.map { ($0, "laptopcomputer", false) }
                ].compactMap { $0 }
                ForEach(lines, id: \.0) { line in
                    Label(line.0, systemImage: line.1)
                        .font(.footnote)
                        .foregroundStyle(line.2 ? Color.orange : Color.secondary)
                }
            } else {
                HStack(spacing: 8) { ProgressView(); Text("Reading their account").font(.footnote).foregroundStyle(.secondary) }
            }
        } header: {
            Text(user.displayName ?? user.userPrincipalName ?? "")
        }
    }

    private var filterSection: some View {
        Section {
            Toggle("Failures only", isOn: $model.failuresOnly)
            Toggle("Last 24 hours", isOn: $model.last24Hours)
        } header: {
            Text("Sign-ins")
        } footer: {
            Text("Interactive sign-ins, newest first. Up to 20.")
        }
    }

    @ViewBuilder
    private var signInsSection: some View {
        Section {
            if model.isLoadingSignIns && model.signIns.isEmpty {
                HStack(spacing: 8) { ProgressView(); Text("Reading the sign-in log…").font(.footnote).foregroundStyle(.secondary) }
            } else if let error = model.signInsError {
                Label {
                    Text(error).font(.footnote)
                } icon: {
                    Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                }
                if model.lastFailureWasConsent, let requestConsent {
                    ConsentRequestButton(request: requestConsent) { refusal in
                        consentMessage = refusal
                        if refusal == nil { model.reloadSignIns() }
                    }
                    if let consentMessage {
                        Text(consentMessage).font(.footnote).foregroundStyle(.secondary)
                    }
                } else {
                    Button("Try again") { model.reloadSignIns() }
                }
            } else if model.signIns.isEmpty {
                Text(model.failuresOnly ? "No failed sign-ins in this window." : "No sign-ins in this window.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(model.signIns) { event in
                    NavigationLink(value: PersonPage.signIn(event.id)) {
                        SignInRow(event: event, glossary: model.glossary)
                    }
                }
            }
        }
    }
}
