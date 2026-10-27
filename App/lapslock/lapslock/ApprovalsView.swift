import SwiftUI
import Combine
import ActionGateKit
import ApprovalsKit
import ManagedConfigKit
import PlatformSecurity

// PIM approvals, phase 4 step A: the Approvals tab of Privileged Access. Content column:
// requests waiting for the signed-in admin's decision, newest first. Detail column: one
// request with who, what, for how long, their justification and ticket, and Approve or Deny
// with a justification of your own. Each decision is a write through the gate, confirmed
// first, with Face ID too when the organization asks for strict confirmation. The Apple
// Watch will ask the phone to do exactly this, through the same model.

@MainActor
final class ApprovalsModel: ObservableObject {
    @Published private(set) var pending: [PendingApproval] = []
    @Published private(set) var loading = false
    @Published private(set) var loaded = false
    @Published private(set) var errorMessage: String?
    @Published private(set) var deciding: String?
    @Published private(set) var notes: [String: String] = [:]
    @Published private(set) var failures: [String: String] = [:]
    @Published private(set) var decided: [PendingApproval] = []

    private let provider: any ApprovalsProviding

    init(provider: any ApprovalsProviding) {
        self.provider = provider
    }

    func approval(_ id: String) -> PendingApproval? {
        pending.first { $0.id == id } ?? decided.first { $0.id == id }
    }

    func load() async {
        loading = true
        defer { loading = false; loaded = true }
        do {
            pending = try await provider.pending()
            errorMessage = nil
        } catch let error as ApprovalsError {
            errorMessage = error.message
        } catch {
            errorMessage = ApprovalsError.unavailable.message
        }
    }

    var strict: Bool { ManagedConfigStore.read().confirmationLevel == .strict }

    /// Sends the decision. Face ID first under strict confirmation. Returns true when sent.
    @discardableResult
    func decide(_ approval: PendingApproval, _ decision: ApprovalDecision, justification: String) async -> Bool {
        guard deciding == nil else { return false }
        failures[approval.id] = nil
        if strict {
            switch await BiometricGate().authenticate(deviceName: nil) {
            case .authenticated: break
            case .unavailable(let reason): failures[approval.id] = reason; return false
            default: failures[approval.id] = "Not confirmed. Nothing was sent."; return false
            }
        }
        deciding = approval.id
        defer { deciding = nil }
        let outcome = await provider.decide(approval, decision, justification: justification.trimmingCharacters(in: .whitespacesAndNewlines))
        switch outcome {
        case .requested:
            notes[approval.id] = decision == .approve
                ? "Approved. " + approval.requester + " can activate once every approver has agreed."
                : "Denied. " + approval.requester + " is told it was denied."
            pending.removeAll { $0.id == approval.id }
            decided.append(approval)
            return true
        case .needsActivation, .notAuthorized:
            failures[approval.id] = "Microsoft refused: your account isn't an approver for this request, or the role's policy changed."
        case .challenged:
            failures[approval.id] = "Microsoft wants a fresh sign-in step. Approve this one in the Entra admin center."
        case .failed(let failure):
            if case .refused(let reason) = failure { failures[approval.id] = reason } else { failures[approval.id] = failure.description }
        }
        return false
    }
}

extension PendingApproval {
    var requestedText: String? {
        requested.map { $0.formatted(.relative(presentation: .named)) }
    }
}

// MARK: - content column

struct ApprovalsListView: View {
    @ObservedObject var model: ApprovalsModel
    let isDemo: Bool
    @Binding var selection: String?

    var body: some View {
        List(selection: $selection) {
            Section {
                if model.loading && !model.loaded {
                    HStack(spacing: 8) { ProgressView(); Text("Reading PIM requests").font(.footnote).foregroundStyle(.secondary) }
                } else if let error = model.errorMessage {
                    Label(error, systemImage: "exclamationmark.triangle").font(.footnote).foregroundStyle(.orange)
                } else if model.pending.isEmpty {
                    Text("Nothing is waiting for your approval.").foregroundStyle(.secondary)
                } else {
                    ForEach(model.pending) { approval in
                        NavigationLink(value: approval.id) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(approval.requester).font(.body.weight(.medium))
                                Text(approval.targetLabel).font(.subheadline)
                                Text([approval.durationText, approval.requestedText.map { "asked " + $0 }].compactMap { $0 }.joined(separator: " · "))
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 2)
                            .accessibilityElement(children: .combine)
                        }
                    }
                }
            } header: {
                Text("Waiting for You")
            } footer: {
                Text("Requests to activate a role or a PIM group where you are an approver. Your decision is recorded in the tenant's audit log as you.")
            }
        }
        .refreshable { await model.load() }
        .task { if !model.loaded { await model.load() } }
    }
}

// MARK: - detail column

struct ApprovalDetailView: View {
    @ObservedObject var model: ApprovalsModel
    let approval: PendingApproval
    @State private var justification = ""
    @State private var confirming: ApprovalDecision?
    @Environment(\.awayTenant) private var awayTenant

    private var isPending: Bool { model.pending.contains { $0.id == approval.id } }
    private var justificationOK: Bool { justification.trimmingCharacters(in: .whitespacesAndNewlines).count >= 3 }

    var body: some View {
        Form {
            Section {
                LabeledContent("Who", value: approval.requester)
                if let upn = approval.requesterUPN { LabeledContent("Account", value: upn) }
                LabeledContent(approval.kind == .role ? "Role" : "Group", value: approval.target)
                if let access = approval.access { LabeledContent("As", value: access) }
                if let duration = approval.durationText { LabeledContent("For", value: duration) }
                if let asked = approval.requestedText { LabeledContent("Asked", value: asked) }
                if let ticket = approval.ticket { LabeledContent("Ticket", value: ticket) }
            } header: {
                Text("Request")
            }
            Section("Their Justification") {
                Text(approval.justification ?? "None given.")
                    .foregroundStyle(approval.justification == nil ? .secondary : .primary)
            }
            if let note = model.notes[approval.id] {
                Section { Label(note, systemImage: "checkmark.circle").foregroundStyle(.green) }
            }
            if let failure = model.failures[approval.id] {
                Section { Label(failure, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.footnote) }
            }
            if isPending {
                Section {
                    TextField("Your reason, for the audit log", text: $justification, axis: .vertical)
                        .lineLimit(2...4)
                    HStack(spacing: 12) {
                        Button {
                            confirming = .approve
                        } label: {
                            Text("Approve").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        Button(role: .destructive) {
                            confirming = .deny
                        } label: {
                            Text("Deny").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                    }
                    .disabled(!justificationOK || model.deciding != nil)
                    if model.deciding == approval.id {
                        HStack(spacing: 8) { ProgressView(); Text("Sending").font(.footnote).foregroundStyle(.secondary) }
                    }
                } header: {
                    Text("Your Decision")
                } footer: {
                    Text("A reason of at least three characters is required, as in the portal. " + (model.strict ? "Your organization also asks for Face ID." : ""))
                }
            }
        }
        .navigationTitle(approval.requester)
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog(confirming.map { $0.title + " " + approval.requester + "?" } ?? "",
                            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
                            titleVisibility: .visible) {
            if let decision = confirming {
                Button(decision.title, role: decision == .deny ? .destructive : nil) {
                    Task { await model.decide(approval, decision, justification: justification) }
                }
                Button("Cancel", role: .cancel) { confirming = nil }
            }
        } message: {
            Text(confirmationMessage(approval.requester + " for " + approval.targetLabel + (approval.durationText.map { ", " + $0 } ?? "") + ".",
                                     awayTenant: awayTenant))
        }
    }
}
