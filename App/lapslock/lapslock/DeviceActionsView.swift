import SwiftUI
import Combine
import ActionGateKit
import DeviceActionsKit
import PrivilegedAccessKit
import InventoryKit
import CredentialKit
import ManagedConfigKit
import PlatformSecurity

// Device actions on the device screen. Spec section 3.3 and section 4.
//
// Two sections under the credentials: Management, the record fields the list does not
// carry and whatever Intune still has in flight, and Actions, one row per action with a
// reason when it does not apply. Sync fires on the tap; the rest confirm. Every outcome
// is one of the gate's: requested, activate a role first, not authorized with activation
// offered, another sign-in step, or a typed failure. The last shift log line for the
// device sits under the actions so the admin sees what they already asked for.

@MainActor
final class DeviceActionsModel: ObservableObject {
    @Published private(set) var record: DeviceRecord?
    @Published private(set) var isLoadingRecord = false
    @Published private(set) var recordError: String?
    @Published private(set) var working: DeviceActionKind?
    @Published private(set) var note: String?
    @Published private(set) var errorMessage: String?
    @Published private(set) var eligibleForActivation: [EligibleAccess] = []
    @Published private(set) var pendingChallenge: (kind: DeviceActionKind, challenge: ClaimsChallenge)?
    @Published private(set) var lastEntry: ShiftLogEntry?
    @Published var confirming: DeviceActionKind?
    /// The destructive tier's first step: the sheet asking for the device name.
    @Published var destructive: DeviceActionKind?
    @Published var typedName = ""
    /// The ten seconds between confirming and sending, with what is pending.
    @Published private(set) var undoing: DeviceActionKind?
    @Published private(set) var undoRemaining = 0
    private var undoWindow: UndoWindow?

    private(set) var target: DeviceActionTarget
    private let provider: any DeviceActionsProviding

    init(target: DeviceActionTarget, provider: any DeviceActionsProviding) {
        self.target = target
        self.provider = provider
    }

    /// Every action, less retire and wipe when the organization switched those off.
    var kinds: [DeviceActionKind] {
        let config = ManagedConfigStore.read()
        return DeviceActionKind.allCases.filter { !$0.isDestructive || !config.isDisabled("destructiveActions") }
    }

    func reason(for kind: DeviceActionKind) -> String? {
        kind.unavailableReason(for: target)
    }

    func load() async {
        isLoadingRecord = true
        recordError = nil
        defer { isLoadingRecord = false }
        lastEntry = await provider.lastLogEntry(managedDeviceId: target.managedDeviceId)
        guard !target.managedDeviceId.isEmpty else { return }
        do {
            let fetched = try await provider.record(managedDeviceId: target.managedDeviceId)
            record = fetched
            target.ownerType = fetched.managedDeviceOwnerType
        } catch {
            recordError = Self.describe(error)
        }
    }

    /// The tap. Sync runs; anything else asks first.
    func tapped(_ kind: DeviceActionKind) {
        guard reason(for: kind) == nil, working == nil else { return }
        // An organization's strict policy moves every tier up one.
        let strict = ManagedConfigStore.read().confirmationLevel == .strict
        switch kind.tier.effective(strict: strict) {
        case .none:
            Task { await run(kind) }
        case .confirm:
            confirming = kind
        case .destructive:
            typedName = ""
            destructive = kind
        }
    }

    /// The name typed back matches, ignoring case and the spaces around it.
    var typedNameMatches: Bool {
        typedName.trimmingCharacters(in: .whitespacesAndNewlines).caseInsensitiveCompare(target.deviceName) == .orderedSame
    }

    /// The destructive tier's second and third steps: the app lock asked again, even if it
    /// just passed, then ten seconds in which one tap undoes it. Only then the one send.
    func destructiveConfirmed(_ kind: DeviceActionKind) async {
        destructive = nil
        guard typedNameMatches else { return }
        errorMessage = nil
        note = nil
        switch await BiometricGate().authenticate(deviceName: target.deviceName) {
        case .authenticated:
            break
        case .unavailable(let reason):
            errorMessage = reason
            return
        default:
            errorMessage = "Not confirmed. Nothing was sent."
            return
        }
        let window = UndoWindow()
        let seconds = Self.undoSeconds
        undoWindow = window
        undoing = kind
        undoRemaining = seconds
        await PendingActions.shared.register(window, for: target.managedDeviceId)
        let started = Date()
        let ticker = Task { @MainActor [weak self] in
            while let self, self.undoing != nil {
                self.undoRemaining = max(0, seconds - Int(Date().timeIntervalSince(started)))
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        let proceed = await window.wait(seconds: seconds)
        ticker.cancel()
        await PendingActions.shared.finished(target.managedDeviceId)
        undoing = nil
        undoWindow = nil
        if proceed {
            await run(kind)
        } else {
            note = kind.title + " cancelled. Nothing was sent."
        }
    }

    func undo() {
        guard let window = undoWindow else { return }
        Task { await window.cancel() }
    }

    /// Ten seconds, or longer in a DEBUG build launched with `-LAPSlockUndoSeconds N` so a
    /// slow automated pass can act inside the window. Never shorter than ten.
    static var undoSeconds: Int {
        #if DEBUG
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "-LAPSlockUndoSeconds"), i + 1 < args.count, let n = Int(args[i + 1]) {
            return max(UndoWindow.standardSeconds, n)
        }
        #endif
        return UndoWindow.standardSeconds
    }

    func confirmed(_ kind: DeviceActionKind) {
        confirming = nil
        Task { await run(kind) }
    }

    func run(_ kind: DeviceActionKind) async {
        working = kind
        note = nil
        errorMessage = nil
        eligibleForActivation = []
        pendingChallenge = nil
        defer { working = nil }
        await handle(await provider.run(kind, on: target), kind: kind)
    }

    /// The person's tap after a challenge, never automatic.
    func continueSignIn() async {
        guard let pending = pendingChallenge else { return }
        working = pending.kind
        pendingChallenge = nil
        defer { working = nil }
        await handle(await provider.resume(pending.kind, on: target, satisfying: pending.challenge), kind: pending.kind)
    }

    private func handle(_ outcome: ActionOutcome, kind: DeviceActionKind) async {
        switch outcome {
        case .requested:
            note = kind.successCopy
            lastEntry = await provider.lastLogEntry(managedDeviceId: target.managedDeviceId)
            if let fetched = try? await provider.record(managedDeviceId: target.managedDeviceId) { record = fetched }
        case .needsActivation(let eligible):
            eligibleForActivation = eligible
            errorMessage = "Your role for this isn't active. Activate it, then try again."
        case .notAuthorized(let eligible):
            eligibleForActivation = eligible
            errorMessage = eligible.isEmpty
                ? "Your account can't do this. It needs a role such as Intune Administrator."
                : "Your account can't do this yet. Activate an eligible role, then try again."
        case .challenged(let challenge):
            pendingChallenge = (kind, challenge)
            errorMessage = "Your organization requires another sign-in step for this action."
        case .failed(let failure):
            errorMessage = failure.description
        }
        if !outcome.isRequested {
            lastEntry = await provider.lastLogEntry(managedDeviceId: target.managedDeviceId)
        }
    }

    static func describe(_ error: Error) -> String {
        guard let e = error as? DeviceActionsError else { return "Couldn't read the management record." }
        switch e {
        case .consentRequired: return "This organization hasn't granted permission to read device management records."
        case .notAuthorized:   return "Your account can't read this device's management record."
        case .transport(let status): return "Microsoft Graph returned an error (\(status)) reading the record."
        case .decodeFailure:   return "Microsoft Graph returned a record the app couldn't read."
        case .cancelled:       return "Cancelled."
        }
    }
}

/// Owns the actions model for as long as the device screen is up, so a redraw above it
/// never replaces the model mid-countdown. Leaving the screen, or the app going to the
/// background, during the countdown cancels it: an action is sent only while its Undo is
/// on screen.
struct DeviceActionsContainer: View {
    @StateObject private var model: DeviceActionsModel
    var activate: (() -> Void)?
    @Environment(\.scenePhase) private var scenePhase

    init(make: @escaping () -> DeviceActionsModel, activate: (() -> Void)?) {
        _model = StateObject(wrappedValue: make())
        self.activate = activate
    }

    var body: some View {
        DeviceActionsSections(model: model, activate: activate)
            .task { await model.load() }
            // Not onDisappear here: a section in a List disappears when it scrolls off
            // screen, which is no reason to cancel. The device screen going away is, and
            // that cancels through PendingActions, see DeviceDetailView.
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { Task { await PendingActions.shared.cancelAll() } }
            }
    }
}

/// Both sections, for the device screen's List.
struct DeviceActionsSections: View {
    @ObservedObject var model: DeviceActionsModel
    /// Opens the PIM activation sheet. Nil where PIM is not opted in.
    var activate: (() -> Void)? = nil

    var body: some View {
        managementSection
        actionsSection
    }

    private var managementSection: some View {
        Section("Management") {
            if model.isLoadingRecord && model.record == nil {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Reading the management record…").font(.footnote).foregroundStyle(.secondary)
                }
            } else if let record = model.record {
                if let owner = DeviceRecord.words(record.managedDeviceOwnerType) {
                    LabeledContent("Ownership", value: owner)
                }
                if let enrollment = DeviceRecord.words(record.deviceEnrollmentType) {
                    LabeledContent("Enrollment", value: enrollment)
                }
                if let agent = DeviceRecord.words(record.managementAgent) {
                    LabeledContent("Managed by", value: agent)
                }
                if let profile = record.enrollmentProfileName, !profile.isEmpty {
                    LabeledContent("Enrollment profile", value: profile)
                }
                ForEach(record.pendingActions) { pending in
                    LabeledContent(pending.title + " pending", value: relative(pending.startDateTime))
                }
            } else if let error = model.recordError {
                Text(error).font(.footnote).foregroundStyle(.secondary)
            } else {
                Text("Not managed by Intune.").font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    private var actionsSection: some View {
        Section {
            if let pending = model.undoing {
                undoRow(pending)
            }
            ForEach(model.kinds) { kind in
                actionRow(kind)
            }
            if let note = model.note {
                Label(note, systemImage: "checkmark.circle")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if let error = model.errorMessage {
                Text(error).font(.footnote).foregroundStyle(.red)
            }
            if !model.eligibleForActivation.isEmpty, let activate {
                Button {
                    activate()
                } label: {
                    Label("Activate your role", systemImage: "person.badge.key")
                        .font(.footnote.weight(.medium))
                }
            }
            if model.pendingChallenge != nil {
                Button {
                    Task { await model.continueSignIn() }
                } label: {
                    Label("Continue sign-in", systemImage: "person.crop.circle.badge.checkmark")
                        .font(.footnote.weight(.medium))
                }
                .disabled(model.working != nil)
            }
            if let entry = model.lastEntry {
                Text("Last from this app: " + entry.actionTitle + ", " + entry.outcome + ", " + relative(entry.at))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Actions")
        } footer: {
            Text("Each action is queued by Intune and runs at the device's next check-in. Every request is written to the shift log in Settings, and to your tenant's audit log by Microsoft. If a role has to be activated first, the app offers it, before the call when it can read your roles and after Microsoft refuses when it cannot.")
        }
        .confirmationDialog(
            model.confirming.map(\.title) ?? "",
            isPresented: Binding(get: { model.confirming != nil }, set: { if !$0 { model.confirming = nil } }),
            titleVisibility: .visible
        ) {
            if let kind = model.confirming {
                Button(kind.title) { model.confirmed(kind) }
                Button("Cancel", role: .cancel) { model.confirming = nil }
            }
        } message: {
            if let kind = model.confirming {
                Text(kind.confirmation)
            }
        }
        .sheet(item: $model.destructive) { kind in
            DestructiveActionSheet(model: model, kind: kind)
        }
    }

    private func undoRow(_ kind: DeviceActionKind) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(kind.title + " " + model.target.deviceName)
                    .font(.body.weight(.semibold))
                Text("Sending in \(model.undoRemaining) s")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            Spacer()
            Button {
                model.undo()
            } label: {
                Text("Undo")
                    .font(.body.weight(.bold))
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityLabel("Undo " + kind.title)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private func actionRow(_ kind: DeviceActionKind) -> some View {
        let reason = model.reason(for: kind)
        Button {
            model.tapped(kind)
        } label: {
            HStack {
                Label(kind.title, systemImage: kind.symbol)
                Spacer()
                if model.working == kind {
                    ProgressView()
                } else if let reason {
                    Text(reason)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                }
            }
        }
        .disabled(reason != nil || model.working != nil || model.undoing != nil)
        .foregroundStyle(reason == nil ? .primary : .secondary)
        .accessibilityLabel(kind.title)
        .accessibilityHint(reason ?? kind.confirmation)
    }

    private func relative(_ date: Date?) -> String {
        guard let date else { return "" }
        // "in 0s" is what the formatter says for a moment ago, clock skew included.
        if abs(date.timeIntervalSinceNow) < 60 { return "just now" }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

/// Shown instead of the actions when the Settings toggle is off.
struct DeviceActionsDisabledSection: View {
    /// The organization switched device actions off in its app configuration policy, so
    /// there is no Settings switch to point at.
    var turnedOffByOrganization = ManagedConfigStore.read().isDisabled("deviceActions")

    var body: some View {
        Section {
            Label {
                if turnedOffByOrganization {
                    Text("Your organization has turned off device actions in this app. Sync, restart, lock, locate and key rotation stay in the Intune admin center.")
                } else {
                    Text("Sync, restart, lock, locate and BitLocker key rotation are off until you turn on **Allow device actions** in Settings. Turning it on asks your organization for permission to modify devices; leaving it off keeps this app read-only.")
                }
            } icon: {
                Image(systemName: "lock.shield")
            }
            .font(.footnote)
        } header: {
            Text("Actions")
        }
    }
}

extension DeviceActionTarget {
    /// The inventory summary, as plain values for the actions module.
    init(summary: ManagedDeviceSummary) {
        let platform: Platform
        switch summary.platform {
        case .windows: platform = .windows
        case .macOS:   platform = .macOS
        default:
            let raw = (summary.operatingSystemRaw ?? "").lowercased()
            if raw.contains("ios") || raw.contains("ipad") { platform = .iOS }
            else if raw.contains("android") { platform = .android }
            else { platform = .other }
        }
        self.init(managedDeviceId: summary.id, deviceName: summary.deviceName, platform: platform, ownerType: nil)
    }
}

/// The destructive tier's first step: what the action does, in full, and the device's name
/// typed back before anything else can happen.
struct DestructiveActionSheet: View {
    @ObservedObject var model: DeviceActionsModel
    let kind: DeviceActionKind
    @Environment(\.dismiss) private var dismiss
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(kind.confirmation)
                } header: {
                    Text(kind.title + " " + model.target.deviceName)
                }
                Section {
                    TextField(model.target.deviceName, text: $model.typedName)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                        .focused($focused)
                        .font(.body.monospaced())
                } header: {
                    Text("Type the Device Name to Continue")
                } footer: {
                    Text("Then Face ID, then ten seconds in which you can undo before anything is sent.")
                }
            }
            .navigationTitle(kind.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue", role: .destructive) {
                        Task { await model.destructiveConfirmed(kind) }
                    }
                    .disabled(!model.typedNameMatches)
                }
            }
            .onAppear { focused = true }
        }
        .presentationDetents([.medium, .large])
    }
}
