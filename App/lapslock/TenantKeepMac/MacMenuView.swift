import SwiftUI
import AuthKit
import InventoryKit
import PrivilegedAccessKit

struct MacMenuView: View {
    let model: MacModel
    @State private var tab: Tab

    init(model: MacModel, initialTab: Tab = .devices) {
        self.model = model
        _tab = State(initialValue: initialTab)
    }

    enum Tab: String, CaseIterable, Identifiable {
        case devices, roles, pulse
        var id: String { rawValue }
        var label: String {
            switch self {
            case .devices: return "Devices"
            case .roles:   return "Roles"
            case .pulse:   return "Pulse"
            }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if model.mode != .signedOut {
                Picker("View", selection: $tab) {
                    ForEach(Tab.allCases) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                Group {
                    switch tab {
                    case .devices: MacDevicesView(model: model)
                    case .roles:   MacRolesView(model: model)
                    case .pulse:   MacPulseView(model: model)
                    }
                }
                .frame(minHeight: 260, alignment: .top)
            }
            if let message = model.message {
                Text(message).font(.caption).foregroundStyle(.orange)
            }
            Divider()
                .onAppear { model.menuOpened() }
            HStack {
                if model.mode != .signedOut {
                    Button("Refresh") { Task { await model.refreshAll() } }
                    Button(model.mode == .demo ? "Leave demo" : "Sign out") { Task { await model.signOut() } }
                }
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
            .buttonStyle(.borderless)
            .font(.callout)
        }
        .padding(14)
        .frame(width: 380)
    }

    @ViewBuilder
    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("TenantKeep On-Call").font(.headline)
            switch model.mode {
            case .signedOut:
                Text("Sign in with your work account. The same account and the same rules as on your iPhone.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button(model.busy ? "Signing in…" : "Sign in") { Task { await model.signIn() } }
                        .disabled(model.busy)
                        .keyboardShortcut(.defaultAction)
                    Button("Try the demo") { model.enterDemo() }
                }
            case .demo, .live:
                if let account = model.account {
                    Text(account.username).font(.caption).foregroundStyle(.secondary)
                }
                if model.mode == .demo {
                    Text("Demo data, not connected to a tenant").font(.caption).foregroundStyle(.orange)
                } else if let problem = model.sessionProblem {
                    Label(problem, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                } else if let checked = model.sessionCheckedAt {
                    Label("Session good, checked " + checked.formatted(.relative(presentation: .named)), systemImage: "checkmark.seal")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct MacDevicesView: View {
    @Bindable var model: MacModel
    @State private var expanded: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            TextField("Device, person, serial or model", text: $model.query)
                .task { await model.devicesTabOpened() }
                .textFieldStyle(.roundedBorder)
            if model.devicesLoading && model.devices.isEmpty {
                ProgressView("Reading devices").controlSize(.small)
            } else if let error = model.devicesError {
                Text(error).font(.caption).foregroundStyle(.orange)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(model.results, id: \.id) { device in
                        VStack(alignment: .leading, spacing: 2) {
                            Button {
                                expanded = expanded == device.id ? nil : device.id
                            } label: {
                                HStack {
                                    Text(device.deviceName).font(.body.monospaced())
                                    Spacer()
                                    Text(device.complianceState ?? "").font(.caption2).foregroundStyle(device.complianceState == "compliant" ? Color.secondary : Color.orange)
                                }
                            }
                            .buttonStyle(.plain)
                            Text([device.userDisplayName ?? device.userPrincipalName, device.operatingSystemRaw, device.osVersion].compactMap { $0 }.joined(separator: " · "))
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            if expanded == device.id {
                                Group {
                                    if let serial = device.serialNumber { Text("Serial " + serial).textSelection(.enabled) }
                                    if let model = device.model { Text([device.manufacturer, model].compactMap { $0 }.joined(separator: " ")) }
                                    if let synced = device.lastSyncDateTime { Text("Last check-in " + synced.formatted(.relative(presentation: .named))) }
                                    Text("Passwords and recovery keys are revealed in the full app, with Touch ID, never in the menu bar.")
                                        .foregroundStyle(.secondary)
                                }
                                .font(.caption)
                            }
                        }
                        Divider()
                    }
                }
            }
            .frame(maxHeight: 260)
            if !model.query.isEmpty && model.results.isEmpty && !model.devicesLoading {
                Text("No device matches.").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct MacRolesView: View {
    let model: MacModel
    @State private var selected: EligibleAccess?
    @State private var justification = ""
    @State private var duration = ActivationRequest.defaultDuration
    @State private var outcome: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if model.rolesLoading {
                ProgressView("Reading eligible roles").controlSize(.small)
            } else if let error = model.rolesError {
                Text(error).font(.caption).foregroundStyle(.secondary)
            } else if model.eligible.isEmpty {
                Text("Nothing eligible to activate.").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(model.eligible, id: \.id) { access in
                Button {
                    selected = access
                    outcome = nil
                } label: {
                    HStack {
                        Image(systemName: selected?.id == access.id ? "largecircle.fill.circle" : "circle")
                        Text(access.displayName ?? "Eligible access")
                    }
                }
                .buttonStyle(.plain)
            }
            if let access = selected {
                Divider()
                TextField("Justification, for your tenant's audit log", text: $justification)
                    .textFieldStyle(.roundedBorder)
                Picker("For", selection: $duration) {
                    ForEach(ActivationRequest.durations, id: \.iso) { Text($0.label).tag($0.iso) }
                }
                Button(model.busy ? "Activating…" : "Activate " + (access.displayName ?? "")) {
                    Task { outcome = await model.activate(access, justification: justification, duration: duration) }
                }
                .disabled(model.busy || justification.trimmingCharacters(in: .whitespaces).count < 3)
                if let outcome { Text(outcome).font(.caption) }
            }
        }
    }
}

struct MacPulseView: View {
    let model: MacModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let error = model.pulseError {
                Text(error).font(.caption).foregroundStyle(.secondary)
            } else if model.degraded.isEmpty {
                Label("All services operational", systemImage: "checkmark.circle").foregroundStyle(.green)
            } else {
                Label(model.degraded.count == 1 ? "1 service degraded" : String(model.degraded.count) + " services degraded",
                      systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                ForEach(model.degraded, id: \.self) { Text($0).font(.caption) }
            }
            if let expiring = model.expiringSoon {
                LabeledContent("Expiring in 30 days", value: String(expiring))
            }
            if let score = model.secureScorePercent {
                LabeledContent("Secure Score", value: String(score) + "%")
            }
        }
    }
}

#Preview("Menu, demo") {
    MacMenuView(model: MacModel(demo: true))
}
