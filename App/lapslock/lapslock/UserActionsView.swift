import SwiftUI
import Combine
import ActionGateKit
import UserActionsKit
import CredentialKit
import PlatformSecurity
import PrivilegedAccessKit
import ManagedConfigKit

// User actions. Spec section 3.5. Opened from the person in Sign-in Triage.
//
// A sheet that owns its model for as long as it is up, so no redraw can replace it
// mid-countdown (the phase 3 step D lesson). Revoke, block, allow, confirm compromised and
// dismiss risk confirm once; removing every sign-in method is the destructive tier, the
// sign-in address typed back, Face ID, ten seconds to undo. The Temporary Access Pass is
// issued on the credential path: Face ID first, the pass held only in memory, shown with a
// timer and a clipboard that clears itself, wiped when the sheet goes or the app leaves the
// foreground, and never logged.

@MainActor
final class UserActionsModel: ObservableObject {
    @Published private(set) var working: UserActionKind?
    @Published private(set) var note: String?
    @Published private(set) var errorMessage: String?
    @Published private(set) var eligibleForActivation: [EligibleAccess] = []
    @Published private(set) var pendingChallenge: (kind: UserActionKind, challenge: ClaimsChallenge)?
    @Published private(set) var lastEntry: ShiftLogEntry?
    @Published private(set) var wipeResult: AuthenticationWipeResult?
    @Published var confirming: UserActionKind?
    @Published var destructive: UserActionKind?
    @Published var typedUPN = ""
    @Published private(set) var undoing: UserActionKind?
    @Published private(set) var undoRemaining = 0
    /// The pass, while on screen. Masked text only ever leaves this through the copy button.
    @Published private(set) var passVisible = false
    @Published private(set) var passSecondsLeft = 0
    private var pass: SensitiveValue?
    private var copied: String?
    private var undoWindow: UndoWindow?

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
        let window = UndoWindow()
        let seconds = DeviceActionsModel.undoSeconds
        undoWindow = window
        undoing = kind
        undoRemaining = seconds
        await PendingActions.shared.register(window, for: target.userId)
        let started = Date()
        let ticker = Task { @MainActor [weak self] in
            while let self, self.undoing != nil {
                self.undoRemaining = max(0, seconds - Int(Date().timeIntervalSince(started)))
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        let proceed = await window.wait(seconds: seconds)
        ticker.cancel()
        await PendingActions.shared.finished(target.userId)
        undoing = nil
        undoWindow = nil
        if proceed {
            if kind == .authenticationWipe { await wipe(challenge: nil) } else { await run(kind) }
        } else {
            note = kind.title + " cancelled. Nothing was sent."
        }
    }

    func undo() {
        guard let window = undoWindow else { return }
        Task { await window.cancel() }
    }

    /// Ends the wait and sends, for an admin who is sure.
    func sendNow() {
        guard let window = undoWindow else { return }
        Task { await window.proceedNow() }
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

    func sheetClosed() {
        hidePass()
        if let copied { SecureClipboard.clearIfHolding(copied) }
        copied = nil
        Task { await PendingActions.shared.cancel(target.userId) }
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
        case .notAuthorized(let eligible):
            eligibleForActivation = eligible
            errorMessage = eligible.isEmpty
                ? "Your account can't do this to this person. Admins can only be changed by a higher role."
                : "Your account can't do this yet. Activate an eligible role, then try again."
        case .challenged(let challenge):
            pendingChallenge = (kind, challenge)
            errorMessage = "Microsoft wants a fresh sign-in step before changing this person's account."
        case .failed(let failure):
            errorMessage = failure.description
        }
    }
}

struct UserActionsSheet: View {
    @StateObject private var model: UserActionsModel
    var activate: (() -> Void)?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    init(make: @escaping () -> UserActionsModel, activate: (() -> Void)? = nil) {
        _model = StateObject(wrappedValue: make())
        self.activate = activate
    }

    var body: some View {
        NavigationStack {
            List {
                if model.passVisible { passSection }
                Section {
                    if let pending = model.undoing { undoRow(pending) }
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
            .navigationTitle("User Actions")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
            }
            .confirmationDialog(model.confirming.map(\.title) ?? "",
                                isPresented: Binding(get: { model.confirming != nil }, set: { if !$0 { model.confirming = nil } }),
                                titleVisibility: .visible) {
                if let kind = model.confirming {
                    Button(kind.title) { model.confirmed(kind) }
                    Button("Cancel", role: .cancel) { model.confirming = nil }
                }
            } message: {
                if let kind = model.confirming { Text(kind.confirmation) }
            }
            .sheet(item: $model.destructive) { kind in
                typedUPNSheet(kind)
            }
        }
        .privacyCover(isProtected: model.passVisible)
        .interactiveDismissDisabled(model.undoing != nil)
        .task { await model.load() }
        .onDisappear { model.sheetClosed() }
        .onChange(of: scenePhase) { _, phase in
            if phase != .active { model.hidePass() }
            if phase == .background { Task { await PendingActions.shared.cancelAll() } }
        }
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

    private func undoRow(_ kind: UserActionKind) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(kind.title).font(.body.weight(.semibold))
                Text("Sending in \(model.undoRemaining) s").font(.caption).foregroundStyle(.secondary).monospacedDigit()
            }
            Spacer()
            Button { model.sendNow() } label: {
                Text("Send now").padding(.horizontal, 8).padding(.vertical, 8)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Send " + kind.title + " now")
            Button { model.undo() } label: {
                Text("Undo").font(.body.weight(.bold)).padding(.horizontal, 16).padding(.vertical, 8)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityLabel("Undo " + kind.title)
        }
        .padding(.vertical, 4)
        // Both buttons reachable: a list row otherwise exposes only one of them.
        .accessibilityElement(children: .contain)
    }

    private func typedUPNSheet(_ kind: UserActionKind) -> some View {
        NavigationStack {
            Form {
                Section { Text(kind.confirmation) } header: { Text(kind.title) }
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
