import SwiftUI
import NotificationsKit

// Settings, Notifications. Spec section 3.11.
//
// One switch per organization the admin works in, and under each a switch per kind. Off by
// default. The first switch turned on asks iOS for permission to notify, at that moment and
// not before. The break-glass accounts live here, per organization. The two limits of a
// phone-only design are stated under the switches, not buried.

struct NotificationTenant: Identifiable, Equatable {
    let id: String
    let label: String
}

@MainActor
@Observable
final class NotificationsSettingsModel {
    private(set) var preferences = NotificationPreferences()
    var permissionMessage: String?
    /// Shown under the field it is about, per organization.
    var upnMessage: [String: String] = [:]
    var newUPN: [String: String] = [:]

    let tenants: [NotificationTenant]
    @ObservationIgnored private let store: any NotificationPreferencesStoring
    @ObservationIgnored private var loaded = false

    /// Reads nothing: Settings builds one of these on every redraw and keeps the first, so
    /// the Keychain read waits for `loadIfNeeded`, once, when the section appears.
    init(tenants: [NotificationTenant], store: any NotificationPreferencesStoring) {
        self.tenants = tenants
        self.store = store
    }

    func loadIfNeeded() {
        guard !loaded else { return }
        loaded = true
        preferences = (try? store.load()) ?? NotificationPreferences()
    }

    func prefs(for tenant: NotificationTenant) -> TenantAlertPreferences {
        preferences.tenant(tenant.id) ?? TenantAlertPreferences(tenantId: tenant.id, label: tenant.label)
    }

    func setEnabled(_ on: Bool, for tenant: NotificationTenant) async {
        if on {
            guard await AlertsRunner.requestAuthorization() else {
                permissionMessage = "Notifications are turned off for TenantKeep in iOS Settings. Turn them on there, then come back."
                return
            }
            permissionMessage = nil
        }
        var value = prefs(for: tenant)
        value.enabled = on
        value.label = tenant.label
        value.paused = false
        save(value)
    }

    func setKind(_ kind: AlertKind, on: Bool, for tenant: NotificationTenant) {
        var value = prefs(for: tenant)
        if on { value.kinds.insert(kind) } else { value.kinds.remove(kind) }
        save(value)
    }

    func addUPN(for tenant: NotificationTenant) {
        let typed = newUPN[tenant.id] ?? ""
        var value = prefs(for: tenant)
        let cleaned = TenantAlertPreferences.cleanUPNs(value.breakGlassUPNs + [typed])
        guard cleaned.count > value.breakGlassUPNs.count else {
            upnMessage[tenant.id] = typed.isEmpty ? nil : "That doesn't look like a sign-in address, or it's already listed."
            return
        }
        value.breakGlassUPNs = cleaned
        newUPN[tenant.id] = ""
        upnMessage[tenant.id] = nil
        save(value)
    }

    func removeUPN(_ upn: String, for tenant: NotificationTenant) {
        var value = prefs(for: tenant)
        value.breakGlassUPNs.removeAll { $0 == upn }
        save(value)
    }

    func preview(label: String) async {
        guard await AlertsRunner.requestAuthorization() else {
            permissionMessage = "Notifications are turned off for TenantKeep in iOS Settings. Turn them on there, then come back."
            return
        }
        await AlertsRunner.postPreview(label: label)
    }

    private func save(_ value: TenantAlertPreferences) {
        // Never write over what is stored with defaults the section has not read yet.
        loadIfNeeded()
        preferences.upsert(value)
        try? store.save(preferences)
        AlertsRunner.scheduleIfNeeded()
    }
}

struct NotificationsSettingsSection: View {
    @State private var model: NotificationsSettingsModel
    let isPro: Bool
    let isDemo: Bool
    var openPlans: (() -> Void)?

    init(model: NotificationsSettingsModel, isPro: Bool, isDemo: Bool, openPlans: (() -> Void)? = nil) {
        _model = State(initialValue: model)
        self.isPro = isPro
        self.isDemo = isDemo
        self.openPlans = openPlans
    }

    var body: some View {
        Group { content }
            .onAppear { model.loadIfNeeded() }
    }

    @ViewBuilder
    private var content: some View {
        if !isPro && !isDemo {
            Section {
                Text("Notifications are part of Pro: service health, Message Center deadlines, break-glass sign-ins, expiring credentials, Secure Score, Conditional Access changes and security incidents, per organization.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Notifications")
            }
        } else {
            ForEach(model.tenants) { tenant in
                tenantSection(tenant)
            }
            Section {
                Button {
                    Task { await model.preview(label: model.tenants.first?.label ?? "Your organization") }
                } label: {
                    Label("Preview a notification", systemImage: "bell.badge")
                }
                if let message = model.permissionMessage {
                    Text(message).font(.footnote).foregroundStyle(.red)
                }
            } footer: {
                Text("iOS decides when TenantKeep checks, usually every few minutes to every few tens of minutes, and not at all in Low Power Mode. A Conditional Access sign-in frequency policy on your account can stop the checks; when it does, you get one notification asking you to sign in again, and checking resumes when you do. Notifications name the kind and the organization, never a person, a title or a policy.")
            }
        }
    }

    private func tenantSection(_ tenant: NotificationTenant) -> some View {
        let prefs = model.prefs(for: tenant)
        return Section {
            Toggle(isOn: Binding(
                get: { prefs.enabled },
                set: { on in Task { await model.setEnabled(on, for: tenant) } })) {
                Text("Notify me")
            }
            if prefs.enabled && prefs.paused {
                Label("Paused until you sign in again", systemImage: "pause.circle")
                    .font(.footnote)
                    .foregroundStyle(.orange)
            }
            if prefs.enabled {
                ForEach(AlertKind.allCases) { kind in
                    Toggle(isOn: Binding(
                        get: { prefs.kinds.contains(kind) },
                        set: { model.setKind(kind, on: $0, for: tenant) })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(kind.title)
                            Text(kind.detail).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if prefs.kinds.contains(.breakGlassSignIn) {
                    breakGlassRows(tenant, prefs: prefs)
                }
            }
        } header: {
            Text(tenant.label)
        }
    }

    @ViewBuilder
    private func breakGlassRows(_ tenant: NotificationTenant, prefs: TenantAlertPreferences) -> some View {
        ForEach(prefs.breakGlassUPNs, id: \.self) { upn in
            HStack {
                Text(upn).font(.subheadline.monospaced())
                Spacer()
                Button(role: .destructive) {
                    model.removeUPN(upn, for: tenant)
                } label: {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Remove " + upn)
            }
        }
        HStack {
            TextField("Break-glass account", text: Binding(
                get: { model.newUPN[tenant.id] ?? "" },
                set: { model.newUPN[tenant.id] = $0 }))
                .textInputAutocapitalization(.never)
                .keyboardType(.emailAddress)
                .autocorrectionDisabled()
                .onSubmit { model.addUPN(for: tenant) }
            Button("Add") { model.addUPN(for: tenant) }
                .disabled((model.newUPN[tenant.id] ?? "").isEmpty)
        }
        if let message = model.upnMessage[tenant.id] {
            Text(message).font(.footnote).foregroundStyle(.red)
        }
        Text("The sign-in addresses of your emergency access accounts. Any interactive sign-in by one of them sends a notification with sound that can break through Focus.")
            .font(.caption)
            .foregroundStyle(.secondary)
    }
}
