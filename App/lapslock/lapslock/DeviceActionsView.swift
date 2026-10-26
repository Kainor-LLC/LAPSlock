import SwiftUI
import Combine
import ActionGateKit
import DeviceActionsKit
import PrivilegedAccessKit
import InventoryKit
import CredentialKit

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

    private(set) var target: DeviceActionTarget
    private let provider: any DeviceActionsProviding

    init(target: DeviceActionTarget, provider: any DeviceActionsProviding) {
        self.target = target
        self.provider = provider
    }

    var kinds: [DeviceActionKind] { DeviceActionKind.allCases }

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
        if kind.tier == .none {
            Task { await run(kind) }
        } else {
            confirming = kind
        }
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
            Text("Each action is queued by Intune and runs at the device's next check-in. Every request is written to the shift log in Settings, and to your tenant's audit log by Microsoft.")
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
        .disabled(reason != nil || model.working != nil)
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
    var body: some View {
        Section {
            Label {
                Text("Sync, restart, lock, locate and BitLocker key rotation are off until you turn on **Allow device actions** in Settings. Turning it on asks your organization for permission to modify devices; leaving it off keeps this app read-only.")
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
