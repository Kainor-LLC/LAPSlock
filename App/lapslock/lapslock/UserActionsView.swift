import SwiftUI
import ActionGateKit
import UserActionsKit
import CredentialKit
import PlatformSecurity
import PrivilegedAccessKit
import ManagedConfigKit
import DeviceActionsKit

// User actions. Spec section 3.5. The detail page for a person in People.
//
// A sheet that owns its model for as long as it is up, so no redraw can replace it
// mid-countdown (the phase 3 step D lesson). Revoke, block, allow, confirm compromised and
// dismiss risk confirm once; removing every sign-in method is the destructive tier, the
// sign-in address typed back, Face ID, ten seconds to undo. The Temporary Access Pass is
// issued on the credential path: Face ID first, the pass held only in memory, shown with a
// timer and a clipboard that clears itself, wiped when the sheet goes or the app leaves the
// foreground, and never logged.

@MainActor
@Observable
final class UserActionsModel {
    private(set) var working: UserActionKind?
    private(set) var note: String?
    private(set) var errorMessage: String?
    private(set) var eligibleForActivation: [EligibleAccess] = []
    private(set) var pendingChallenge: (kind: UserActionKind, challenge: ClaimsChallenge)?
    private(set) var lastEntry: ShiftLogEntry?
    private(set) var wipeResult: AuthenticationWipeResult?
    var confirming: UserActionKind?
    var destructive: UserActionKind?
    var typedUPN = ""
    private(set) var undoing: UserActionKind?
    private(set) var undoRemaining = 0
    /// The pass, while on screen. Masked text only ever leaves this through the copy button.
    /// For the leaver checklist: what each user action came to, and what was skipped.
    private(set) var results: [UserActionKind: LeaverStepStatus] = [:]
    var skipped: Set<LeaverStep> = []
    var deviceOutcomes: [String: String] = [:]
    private(set) var devices: [UserDevice] = []
    private(set) var devicesError: String?
    private(set) var devicesLoaded = false
    private(set) var passVisible = false
    private(set) var passSecondsLeft = 0
    private var pass: SensitiveValue?
    @ObservationIgnored private var copied: String?
    @ObservationIgnored private var countdown: UndoCountdown?

    let target: UserActionTarget
    private let provider: any UserActionsProviding
    private let tapIssuer: any TemporaryAccessPassIssuing
    static let passVisibleSeconds = 60

    init(target: UserActionTarget, provider: any UserActionsProviding, tapIssuer: any TemporaryAccessPassIssuing) {
        self.target = target
        self.provider = provider
        self.tapIssuer = tapIssuer
    }

    var kinds: [UserActionKind] { UserActionKind.allCases }

    func load() async {
        lastEntry = await provider.lastLogEntry(userId: target.userId)
    }

    func loadDevices() async {
        guard !devicesLoaded else { return }
        defer { devicesLoaded = true }
        do {
            devices = try await provider.devices(of: target)
            devicesError = nil
        } catch {
            devicesError = "Couldn't list this person's devices."
        }
    }

    func status(of step: LeaverStep) -> LeaverStepStatus {
        if skipped.contains(step) { return .skipped }
        if let kind = step.action { return results[kind] ?? .pending }
        if step == .devices {
            if devices.isEmpty && devicesError == nil { return .pending }
            return deviceOutcomes.isEmpty ? .pending : .done(deviceOutcomes.count == 1 ? "1 device" : "\(deviceOutcomes.count) devices")
        }
        return .pending
    }

    func summary() -> String {
        LeaverSummary.text(
            person: target,
            statuses: LeaverStep.allCases.map { ($0, status(of: $0)) },
            devices: deviceOutcomes.sorted { $0.key < $1.key }.map { ($0.key, $0.value) },
            at: Date())
    }

    func tapped(_ kind: UserActionKind) {
        guard working == nil, undoing == nil else { return }
        let strict = ManagedConfigStore.read().confirmationLevel == .strict
        switch kind.tier.effective(strict: strict) {
        case .none, .confirm:
            confirming = kind
        case .destructive:
            typedUPN = ""
            destructive = kind
        }
        checkRolesAhead(kind)
    }

    /// The role check, started as the confirmation opens (OPTIMIZATION-PLAN.md, step G).
    /// A role that is eligible but not active closes the confirmation and offers activation
    /// before the typed address and Face ID. The checks made when the change is sent stay.
    private func checkRolesAhead(_ kind: UserActionKind) {
        Task { [weak self, provider, target] in
            let outcome = await provider.checkRoles(kind, on: target)
            guard let outcome, case .needsActivation = outcome,
                  let self, self.confirming == kind || self.destructive == kind else { return }
            self.confirming = nil
            self.destructive = nil
            self.clearMessages()
            self.handle(outcome, kind: kind)
        }
    }

    func confirmed(_ kind: UserActionKind) {
        confirming = nil
        Task {
            if kind == .issueTemporaryAccessPass {
                await issuePass()
            } else if kind == .authenticationWipe {
                await wipe(challenge: nil)
            } else {
                await run(kind)
            }
        }
    }

    var typedUPNMatches: Bool {
        typedUPN.trimmingCharacters(in: .whitespacesAndNewlines).caseInsensitiveCompare(target.userPrincipalName) == .orderedSame
    }

    /// Face ID, then ten seconds with Undo, then the sequence, only while this sheet is up.
    func destructiveConfirmed(_ kind: UserActionKind) async {
        destructive = nil
        guard typedUPNMatches else { return }
        clearMessages()
        guard await faceID() else { return }
        let countdown = UndoCountdown(key: target.userId, seconds: DeviceActionsModel.undoSeconds)
        self.countdown = countdown
        undoing = kind
        let proceed = await countdown.run { @MainActor [weak self] left in self?.undoRemaining = left }
        undoing = nil
        self.countdown = nil
        if proceed {
            if kind == .authenticationWipe { await wipe(challenge: nil) } else { await run(kind) }
        } else {
            note = kind.title + " cancelled. Nothing was sent."
        }
    }

    func undo() {
        guard let countdown else { return }
        Task { await countdown.undo() }
    }

    /// Ends the wait and sends, for an admin who is sure.
    func sendNow() {
        guard let countdown else { return }
        Task { await countdown.sendNow() }
    }

    func continueSignIn() async {
        guard let pending = pendingChallenge else { return }
        pendingChallenge = nil
        if pending.kind == .authenticationWipe {
            await wipe(challenge: pending.challenge)
        } else {
            working = pending.kind
            defer { working = nil }
            handle(await provider.resume(pending.kind, on: target, satisfying: pending.challenge), kind: pending.kind)
            lastEntry = await provider.lastLogEntry(userId: target.userId)
        }
    }

    private func run(_ kind: UserActionKind) async {
        working = kind
        clearMessages()
        defer { working = nil }
        handle(await provider.run(kind, on: target), kind: kind)
        lastEntry = await provider.lastLogEntry(userId: target.userId)
    }

    private func wipe(challenge: ClaimsChallenge?) async {
        working = .authenticationWipe
        clearMessages()
        defer { working = nil }
        let result = await provider.authenticationWipe(target, satisfying: challenge)
        wipeResult = result
        if let outcome = result.outcome {
            handle(outcome, kind: .authenticationWipe)
        }
        lastEntry = await provider.lastLogEntry(userId: target.userId)
    }

    // MARK: - the Temporary Access Pass

    private func issuePass() async {
        clearMessages()
        if let gate = await provider.checkRoles(.issueTemporaryAccessPass, on: target) {
            handle(gate, kind: .issueTemporaryAccessPass)
            return
        }
        guard await faceID() else { return }
        working = .issueTemporaryAccessPass
        defer { working = nil }
        do {
            let issued = try await tapIssuer.issue(userId: target.userId, lifetimeMinutes: 60)
            pass = issued.pass
            passVisible = true
            passSecondsLeft = Self.passVisibleSeconds
            note = "Temporary Access Pass issued: one use, valid for \(issued.lifetimeMinutes) minutes."
            await provider.logOffGate(.issueTemporaryAccessPass, on: target, outcome: .requested(requestId: nil))
            startPassTimer()
        } catch let error as CredentialError {
            await provider.logOffGate(.issueTemporaryAccessPass, on: target, outcome: .failed(.transport(status: 0)))
            switch error {
            case .notAuthorized:   errorMessage = "Your account can't issue a pass. It needs Authentication Administrator or Privileged Authentication Administrator."
            case .consentRequired: errorMessage = "This organization hasn't granted permission to issue a Temporary Access Pass."
            default:               errorMessage = "Couldn't issue a pass. Nothing was created that you can see; check the person's methods in Entra."
            }
        } catch {
            errorMessage = "Couldn't issue a pass."
        }
        lastEntry = await provider.lastLogEntry(userId: target.userId)
    }

    private func startPassTimer() {
        Task { @MainActor [weak self] in
            while let self, self.passVisible, self.passSecondsLeft > 0 {
                try? await Task.sleep(for: .seconds(1))
                self.passSecondsLeft -= 1
            }
            self?.hidePass()
        }
    }

    func passText() -> String {
        guard passVisible, let pass else { return "" }
        return pass.withValue { $0 }
    }

    func copyPass() {
        guard passVisible, let pass else { return }
        pass.withValue { value in
            _ = SecureClipboard.copyCredential(value)
            copied = value
        }
    }

    /// Wipes the pass from memory. The clipboard keeps its own expiry; leaving the sheet
    /// clears it too if it still holds the pass.
    func hidePass() {
        passVisible = false
        pass?.wipe()
        pass = nil
    }

    func closed() {
        hidePass()
        if let copied { SecureClipboard.clearIfHolding(copied) }
        copied = nil
        // The person's countdown and any device countdown started from the checklist.
        Task { await PendingActions.shared.cancelAll() }
    }

    // MARK: - helpers

    private func faceID() async -> Bool {
        switch await BiometricGate().authenticate(deviceName: nil) {
        case .authenticated: return true
        case .unavailable(let reason): errorMessage = reason; return false
        default: errorMessage = "Not confirmed. Nothing was sent."; return false
        }
    }

    private func clearMessages() {
        note = nil
        errorMessage = nil
        eligibleForActivation = []
        pendingChallenge = nil
    }

    private func handle(_ outcome: ActionOutcome, kind: UserActionKind) {
        switch outcome {
        case .requested:
            results[kind] = .done(kind.successCopy)
            if kind == .authenticationWipe, let result = wipeResult {
                var text = "Removed: " + (result.removed.isEmpty ? "nothing" : result.removed.joined(separator: ", ")) + "."
                if !result.kept.isEmpty { text += " Kept: " + result.kept.joined(separator: ", ") + "." }
                if !result.failed.isEmpty { text += " Could not remove: " + result.failed.joined(separator: ", ") + "." }
                note = text
            } else {
                note = kind.successCopy
            }
        case .needsActivation(let eligible):
            eligibleForActivation = eligible
            errorMessage = "Your role for this isn't active. Activate it, then try again."
            results[kind] = .failed("role not active")
        case .notAuthorized(let eligible):
            eligibleForActivation = eligible
            errorMessage = eligible.isEmpty
                ? "Your account can't do this to this person. Admins can only be changed by a higher role."
                : "Your account can't do this yet. Activate an eligible role, then try again."
            results[kind] = .failed("not authorized")
        case .challenged(let challenge):
            pendingChallenge = (kind, challenge)
            errorMessage = "Microsoft wants a fresh sign-in step before changing this person's account."
        case .failed(let failure):
            errorMessage = failure.description
            results[kind] = .failed(failure.description)
        }
    }
}

/// A person's actions and leaver checklist, the detail column of People. Keyed by the
/// person, so switching between the two views keeps one model and its countdown, and
/// choosing another person or a sign-in replaces it, which cancels anything pending.
struct PersonActionsView: View {
    @StateModel private var model: UserActionsModel
    var activate: (() -> Void)?
    /// Device actions for the leaver checklist's devices step; nil when they are off.
    var makeDeviceActions: ((DeviceActionTarget) -> DeviceActionsModel)? = nil
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.awayTenant) private var awayTenant
    @Binding var mode: Mode

    enum Mode: String, CaseIterable, Identifiable {
        case actions, leaver
        var id: String { rawValue }
        var label: String { self == .actions ? "Actions" : "Leaver Checklist" }
    }

    init(make: @escaping () -> UserActionsModel, mode: Binding<Mode>, activate: (() -> Void)? = nil, makeDeviceActions: ((DeviceActionTarget) -> DeviceActionsModel)? = nil) {
        _model = StateModel(wrappedValue: make())
        _mode = mode
        self.activate = activate
        self.makeDeviceActions = makeDeviceActions
    }

    var body: some View {
        NavigationStack {
            List {
                if model.passVisible { passSection }
                if mode == .leaver {
                    leaverSections
                } else {
                Section {
                    ForEach(model.kinds) { kind in
                        Button {
                            model.tapped(kind)
                        } label: {
                            HStack {
                                Label(kind.title, systemImage: kind.symbol)
                                Spacer()
                                if model.working == kind { ProgressView() }
                            }
                        }
                        .disabled(model.working != nil || model.undoing != nil)
                    }
                    if let note = model.note {
                        Label(note, systemImage: "checkmark.circle").font(.footnote).foregroundStyle(.secondary)
                    }
                    if let error = model.errorMessage {
                        Text(error).font(.footnote).foregroundStyle(.red)
                    }
                    if !model.eligibleForActivation.isEmpty, let activate {
                        Button { activate() } label: {
                            Label("Activate your role", systemImage: "person.badge.key").font(.footnote.weight(.medium))
                        }
                    }
                    if model.pendingChallenge != nil {
                        Button { Task { await model.continueSignIn() } } label: {
                            Label("Continue sign-in", systemImage: "person.crop.circle.badge.checkmark").font(.footnote.weight(.medium))
                        }
                    }
                    if let entry = model.lastEntry {
                        Text("Last from this app: " + entry.actionTitle + ", " + entry.outcome)
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } header: {
                    Text(model.target.label)
                } footer: {
                    Text("Each action is made as you, with your role, and recorded in your tenant's audit log by Microsoft and in the shift log here. A Temporary Access Pass is never written to the shift log or anywhere else.")
                }
                }
            }
            .task(id: mode) { if mode == .leaver { await model.loadDevices() } }
            // The countdown sits above the bottom edge so the list does not jump while it runs.
            .safeAreaInset(edge: .bottom) {
                if let pending = model.undoing {
                    UndoBar(title: pending.title, spokenAction: pending.title, remaining: model.undoRemaining, floating: true,
                            sendNow: { model.sendNow() }, undo: { model.undo() })
                }
            }
            .navigationTitle("User Actions")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                // In the title bar, so the checklist starts at the top of the sheet.
                ToolbarItem(placement: .principal) {
                    Picker("View", selection: $mode) {
                        ForEach(Mode.allCases) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .fixedSize()
                }
                if mode == .leaver {
                    // Always reachable, however long the checklist runs.
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            UIPasteboard.general.string = model.summary()
                            summaryCopied = true
                        } label: {
                            Label(summaryCopied ? "Summary copied" : "Copy summary", systemImage: summaryCopied ? "checkmark" : "doc.on.clipboard")
                                .labelStyle(.titleAndIcon)
                        }
                        .accessibilityHint("What was done, skipped and left, with the time, for the ticket. No credentials.")
                    }
                }
            }
            .confirmationDialog(model.confirming.map(\.title) ?? "",
                                isPresented: Binding(get: { model.confirming != nil }, set: { if !$0 { model.confirming = nil } }),
                                titleVisibility: .visible) {
                if let kind = model.confirming {
                    Button(kind.title) { model.confirmed(kind) }
                    Button("Cancel", role: .cancel) { model.confirming = nil }
                }
            } message: {
                if let kind = model.confirming { Text(confirmationMessage(kind.confirmation, awayTenant: awayTenant)) }
            }
            .sheet(item: $model.destructive) { kind in
                typedUPNSheet(kind)
            }
        }
        .privacyCover(isProtected: model.passVisible)
        .task { await model.load() }
        .onDisappear { model.closed() }
        .onChange(of: scenePhase) { _, phase in
            if phase != .active { model.hidePass() }
            if phase == .background { Task { await PendingActions.shared.cancelAll() } }
        }
    }

    // MARK: - leaver checklist

    @ViewBuilder
    private var leaverSections: some View {
        Section {
            ForEach([LeaverStep.blockSignIn, .revokeSessions, .removeMethods]) { step in
                leaverActionRow(step)
            }
        } header: {
            Text("Leaver Checklist for " + model.target.label)
        } footer: {
            Text("In order, each with its usual confirmation. Skip what does not apply; everything you do is in the shift log and the tenant audit log.")
        }
        Section {
            if !model.devicesLoaded && model.devicesError == nil {
                HStack(spacing: 8) { ProgressView(); Text("Finding their devices").font(.footnote).foregroundStyle(.secondary) }
            } else if !model.devices.isEmpty, let makeDeviceActions {
                ForEach(model.devices) { device in
                    LeaverDeviceRow(device: device, make: makeDeviceActions) { outcome in
                        model.deviceOutcomes[device.label] = outcome
                    }
                }
            } else if makeDeviceActions == nil {
                Text("Turn on device actions in Settings to retire or wipe from here.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else if let error = model.devicesError {
                Text(error).font(.footnote).foregroundStyle(.secondary)
            } else {
                Text("No devices list this person as their primary user.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            skipToggle(.devices)
        } header: {
            Text("Retire or Wipe Their Devices")
        } footer: {
            Text(LeaverStep.devices.detail)
        }
        Section {
            ForEach([LeaverStep.mailbox, .privilegedAccess]) { step in
                VStack(alignment: .leading, spacing: 4) {
                    if let url = step.portal {
                        Link(destination: url) { Label(step.title, systemImage: "arrow.up.right.square") }
                    }
                    Text(step.detail).font(.caption).foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("In the Admin Centers")
        }
    }

    @State private var summaryCopied = false

    private func leaverActionRow(_ step: LeaverStep) -> some View {
        let status = model.status(of: step)
        return HStack(alignment: .top, spacing: 12) {
            statusIcon(status)
            VStack(alignment: .leading, spacing: 2) {
                Text(step.title).font(.body.weight(.medium))
                Text(step.detail).font(.caption).foregroundStyle(.secondary)
                if case .failed(let why) = status {
                    Text(why).font(.caption).foregroundStyle(.red)
                }
            }
            Spacer()
            if let kind = step.action {
                if case .pending = status {
                    Menu {
                        Button(kind.title) { model.tapped(kind) }
                        Button("Skip") { model.skipped.insert(step) }
                    } label: {
                        Text(model.working == kind ? "Working" : "Run")
                    }
                    .disabled(model.working != nil || model.undoing != nil)
                } else if case .skipped = status {
                    Button("Undo skip") { model.skipped.remove(step) }.buttonStyle(.borderless)
                } else if case .failed = status {
                    Button("Retry") { model.tapped(kind) }.buttonStyle(.borderless)
                }
            }
        }
        .padding(.vertical, 2)
    }

    private func skipToggle(_ step: LeaverStep) -> some View {
        Toggle("Skip this step", isOn: Binding(
            get: { model.skipped.contains(step) },
            set: { if $0 { model.skipped.insert(step) } else { model.skipped.remove(step) } }))
            .font(.footnote)
    }

    private func statusIcon(_ status: LeaverStepStatus) -> some View {
        let (name, color): (String, Color) = {
            switch status {
            case .pending: return ("circle", .secondary)
            case .done:    return ("checkmark.circle.fill", .green)
            case .skipped: return ("arrow.uturn.forward.circle", .secondary)
            case .failed:  return ("exclamationmark.circle.fill", .red)
            }
        }()
        return Image(systemName: name).foregroundStyle(color).accessibilityLabel(status.word)
    }

    private var passSection: some View {
        Section {
            Text(model.passText())
                .font(.title2.monospaced().weight(.semibold))
                .textSelection(.disabled)
                .accessibilityLabel("Temporary Access Pass")
                // Read out character by character, as a password is, so a VoiceOver user
                // can pass it on exactly.
                .accessibilityValue(Text(model.passText()).speechSpellsOutCharacters())
            HStack {
                Button { model.copyPass() } label: { Label("Copy", systemImage: "doc.on.doc") }
                Spacer()
                Button(role: .destructive) { model.hidePass() } label: { Label("Hide", systemImage: "eye.slash") }
            }
            .buttonStyle(.borderless)
        } header: {
            Text("Temporary Access Pass")
        } footer: {
            Text("Hides in \(model.passSecondsLeft) s. Give it to the person over a channel you trust; it is not shown again. The clipboard clears itself.")
        }
    }

    private func typedUPNSheet(_ kind: UserActionKind) -> some View {
        NavigationStack {
            Form {
                Section {
                    Text(kind.confirmation)
                    AwayTenantNote()
                } header: { Text(kind.title) }
                Section {
                    TextField(model.target.userPrincipalName, text: $model.typedUPN)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                        .autocorrectionDisabled()
                        .font(.body.monospaced())
                } header: {
                    Text("Type the Sign-in Address to Continue")
                } footer: {
                    Text("Then Face ID, then ten seconds in which you can undo, or send right away.")
                }
            }
            .navigationTitle(kind.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { model.destructive = nil } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue", role: .destructive) { Task { await model.destructiveConfirmed(kind) } }
                        .disabled(!model.typedUPNMatches)
                }
            }
        }
        .presentationDetents([.medium, .large])
    }
}

/// One of the person's devices in the leaver checklist: Retire and Wipe through the device
/// actions' own flow, with their ownership rules, typed name, Face ID and countdown.
struct LeaverDeviceRow: View {
    let device: UserDevice
    @StateModel private var model: DeviceActionsModel
    let report: (String) -> Void
    @State private var appeared = Date()
    @Environment(\.awayTenant) private var awayTenant

    init(device: UserDevice, make: @escaping (DeviceActionTarget) -> DeviceActionsModel, report: @escaping (String) -> Void) {
        self.device = device
        self.report = report
        let platform: DeviceActionTarget.Platform = {
            let os = (device.operatingSystem ?? "").lowercased()
            if os.contains("windows") { return .windows }
            if os.contains("mac") { return .macOS }
            if os.contains("ios") || os.contains("ipad") { return .iOS }
            if os.contains("android") { return .android }
            return .other
        }()
        let target = DeviceActionTarget(managedDeviceId: device.id, deviceName: device.label, platform: platform,
                                        ownerType: device.managedDeviceOwnerType, hasEntraIdentity: device.hasEntraIdentity)
        _model = StateModel(wrappedValue: make(target))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(device.label).font(.body.monospaced())
                Spacer()
                Text(DeviceRecord.words(device.managedDeviceOwnerType) ?? "").font(.caption).foregroundStyle(.secondary)
            }
            if let pending = model.undoing {
                HStack {
                    Text(pending.title + ", sending in \(model.undoRemaining) s").font(.caption).monospacedDigit()
                    Spacer()
                    Button("Send now") { model.sendNow() }.buttonStyle(.borderless)
                    Button("Undo") { model.undo() }.buttonStyle(.borderedProminent)
                }
                .accessibilityElement(children: .contain)
            } else {
                HStack(spacing: 16) {
                    ForEach([DeviceActionKind.retire, .wipe]) { kind in
                        let reason = model.reason(for: kind)
                        Button(kind.title) { model.tapped(kind) }
                            .buttonStyle(.bordered)
                            .disabled(reason != nil || model.working != nil)
                            .accessibilityHint(reason ?? kind.confirmation)
                    }
                    if let reason = model.reason(for: .wipe) {
                        Text(reason).font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            if let note = model.note { Text(note).font(.caption).foregroundStyle(.secondary) }
            if let error = model.errorMessage { Text(error).font(.caption).foregroundStyle(.red) }
        }
        .padding(.vertical, 4)
        .task { await model.load() }
        .onChange(of: model.lastEntry) { _, entry in
            // Only a retire or wipe made from this checklist counts, not the device's history.
            guard let entry, entry.at >= appeared,
                  [DeviceActionKind.retire.actionId, DeviceActionKind.wipe.actionId].contains(entry.actionId) else { return }
            report(entry.actionTitle.lowercased() + " " + entry.outcome)
        }
        .confirmationDialog(model.confirming.map(\.title) ?? "",
                            isPresented: Binding(get: { model.confirming != nil }, set: { if !$0 { model.confirming = nil } }),
                            titleVisibility: .visible) {
            if let kind = model.confirming {
                Button(kind.title) { model.confirmed(kind) }
                Button("Cancel", role: .cancel) { model.confirming = nil }
            }
        } message: {
            if let kind = model.confirming { Text(confirmationMessage(kind.confirmation, awayTenant: awayTenant)) }
        }
        .sheet(item: $model.destructive) { kind in
            DestructiveActionSheet(model: model, kind: kind)
        }
    }
}
