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
                Text("Updated " + glance.updatedAt.formatted(.relative(presentation: .named)))
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
                    Button("Approve") { decide(true) }
                        .tint(.green)
                        .disabled(model.sending || reason.trimmingCharacters(in: .whitespaces).count < WatchRequest.minimumReason)
                    Button("Deny", role: .destructive) { decide(false) }
                        .disabled(model.sending || reason.trimmingCharacters(in: .whitespaces).count < WatchRequest.minimumReason)
                }
            }
            WatchResultSection(sending: model.sending, result: result)
        }
        .navigationTitle("Approval")
    }

    private func decide(_ approve: Bool) {
        Task { result = await model.send(.decide(approvalId: approval.id, approve: approve, reason: reason)) }
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
                Label(item.name, systemImage: item.isGroup ? "person.3" : "person.badge.key")
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
