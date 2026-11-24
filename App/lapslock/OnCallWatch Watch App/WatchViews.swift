import SwiftUI
import WatchBridgeKit

struct WatchHomeView: View {
    let model: WatchModel

    var body: some View {
        NavigationStack {
            List {
                if let glance = model.glance {
                    if glance.tenant.isEmpty {
                        Text(glance.problem ?? "Sign in on your iPhone.").foregroundStyle(.secondary)
                    } else {
                        header(glance)
                        approvalsSection(glance)
                        rolesSection(glance)
                        healthSection(glance)
                    }
                } else {
                    Text("Open TenantKeep on your iPhone once, then come back.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section {
                    Button {
                        Task { await model.refresh() }
                    } label: {
                        Label(model.sending ? "Updating" : "Update now", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.sending)
                    if let reply = model.lastReply, reply.outcome != .done {
                        Text(reply.message).font(.footnote).foregroundStyle(.orange)
                    }
                }
            }
            .navigationTitle("TenantKeep")
        }
    }

    @ViewBuilder
    private func header(_ glance: WatchGlance) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 2) {
                Text(glance.tenant).font(.headline).lineLimit(1)
                // A relative date style keeps time on its own. Formatted once, the line said
                // "1 second ago" until the next glance arrived.
                Text("Updated \(glance.updatedAt, style: .relative) ago")
                    .font(.caption2).foregroundStyle(.secondary)
                if glance.isDemo { Text("Demo data").font(.caption2).foregroundStyle(.orange) }
                if let problem = glance.problem { Text(problem).font(.caption2).foregroundStyle(.orange) }
            }
        }
    }

    @ViewBuilder
    private func approvalsSection(_ glance: WatchGlance) -> some View {
        Section("Approvals") {
            if glance.approvals.isEmpty {
                Text("Nothing waiting").foregroundStyle(.secondary)
            }
            ForEach(glance.approvals) { approval in
                NavigationLink {
                    WatchApprovalView(model: model, approval: approval)
                } label: {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(approval.requester).font(.body.weight(.medium)).lineLimit(1)
                        Text(approval.target).font(.caption2).foregroundStyle(.secondary).lineLimit(2)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func rolesSection(_ glance: WatchGlance) -> some View {
        Section("My Roles") {
            if glance.activeRoles.isEmpty {
                Text("None active").foregroundStyle(.secondary)
            }
            ForEach(glance.activeRoles) { role in
                VStack(alignment: .leading, spacing: 1) {
                    Text(role.name).lineLimit(2)
                    if let end = role.endsAt {
                        Text(timerInterval: Date()...max(Date(), end), countsDown: true)
                            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                    } else {
                        Text("Permanent").font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            if !glance.eligible.isEmpty {
                NavigationLink {
                    WatchActivateListView(model: model, eligible: glance.eligible)
                } label: {
                    Label("Activate", systemImage: "key.horizontal")
                }
            }
        }
    }

    @ViewBuilder
    private func healthSection(_ glance: WatchGlance) -> some View {
        Section("Tenant") {
            metric("Degraded services", glance.health.degradedServices)
            metric("Open incidents", glance.health.openIncidents)
            metric("Expiring in 30 days", glance.health.expiringSoon)
            if let score = glance.health.secureScorePercent {
                LabeledContent("Secure Score", value: String(score) + "%")
            }
        }
    }

    @ViewBuilder
    private func metric(_ title: String, _ value: Int?) -> some View {
        if let value {
            LabeledContent(title, value: String(value))
                .foregroundStyle(value > 0 ? Color.orange : Color.primary)
        }
    }
}

struct WatchApprovalView: View {
    let model: WatchModel
    let approval: WatchGlance.Approval
    @State private var reason = ""
    @State private var result: WatchReply?
    /// The decision waiting for its second tap: true to approve, false to deny.
    @State private var confirming: Bool?
    /// Set on the tap that sends, before anything waits, so a second tap cannot send twice.
    @State private var deciding = false

    var body: some View {
        List {
            Section {
                Text(approval.requester).font(.headline)
                Text(approval.target)
                if let duration = approval.duration { Text("For " + duration).font(.caption).foregroundStyle(.secondary) }
            }
            Section("Their Reason") {
                Text(approval.reason ?? "None given.").font(.caption)
            }
            if result?.outcome != .done {
                Section("Your Reason") {
                    TextField("Say or type a reason", text: $reason)
                    // A second tap confirms, as the phone's sheet does: the two sit side by
                    // side on a small screen (second review, R2-23).
                    Button("Approve") { confirming = true }
                        .tint(.green)
                        .disabled(deciding || model.sending || reason.trimmingCharacters(in: .whitespaces).count < WatchRequest.minimumReason)
                    Button("Deny", role: .destructive) { confirming = false }
                        .disabled(deciding || model.sending || reason.trimmingCharacters(in: .whitespaces).count < WatchRequest.minimumReason)
                }
            }
            WatchResultSection(sending: model.sending, result: result)
        }
        .navigationTitle("Approval")
        .confirmationDialog(confirming == false ? "Deny " + approval.requester + "?" : "Approve " + approval.requester + "?",
                            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
                            titleVisibility: .visible) {
            if let approve = confirming {
                Button(approve ? "Approve" : "Deny", role: approve ? nil : .destructive) { decide(approve) }
                Button("Cancel", role: .cancel) { confirming = nil }
            }
        }
    }

    private func decide(_ approve: Bool) {
        confirming = nil
        guard !deciding else { return }
        deciding = true
        Task {
            result = await model.send(.decide(approvalId: approval.id, approve: approve, reason: reason))
            // One that went through is not offered again. One that did not may be, after the
            // person has checked: the reply says when the phone may have sent it.
            if result?.outcome != .done { deciding = false }
        }
    }
}

struct WatchActivateListView: View {
    let model: WatchModel
    let eligible: [WatchGlance.Eligible]

    var body: some View {
        List(eligible) { item in
            NavigationLink {
                WatchActivateView(model: model, item: item)
            } label: {
                // One width for both symbols: the group symbol is wider and ran into its name.
                Label {
                    Text(item.name)
                } icon: {
                    Image(systemName: item.isGroup ? "person.2" : "person.badge.key")
                        .frame(width: 26)
                }
            }
        }
        .navigationTitle("Activate")
    }
}

struct WatchActivateView: View {
    let model: WatchModel
    let item: WatchGlance.Eligible
    @State private var reason = ""
    @State private var hours = 1
    @State private var result: WatchReply?

    var body: some View {
        List {
            Section { Text(item.name).font(.headline) }
            if result?.outcome != .done {
                Section {
                    TextField("Say or type why", text: $reason)
                    Picker("For", selection: $hours) {
                        ForEach(Array(WatchRequest.hours), id: \.self) { h in
                            Text(h == 1 ? "1 hour" : String(h) + " hours").tag(h)
                        }
                    }
                    .pickerStyle(.navigationLink)
                    Button("Activate") {
                        Task { result = await model.send(.activate(eligibleId: item.id, reason: reason, hours: hours)) }
                    }
                    .disabled(model.sending || reason.trimmingCharacters(in: .whitespaces).count < WatchRequest.minimumReason)
                }
            }
            WatchResultSection(sending: model.sending, result: result)
            Section {
                Text("Your iPhone sends it, with your organization's policy. A ticket number or a fresh sign-in means finishing on the phone.")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Activate")
    }
}

/// Under the buttons, where the eye already is: sending, then the phone's answer.
struct WatchResultSection: View {
    let sending: Bool
    let result: WatchReply?

    var body: some View {
        if sending {
            Section {
                HStack(spacing: 6) { ProgressView(); Text("Asking your iPhone").font(.footnote) }
            }
        } else if let result {
            Section {
                Text(result.message).font(.footnote)
                    .foregroundStyle(result.outcome == .done ? Color.green : Color.orange)
            }
        }
    }
}
