import SwiftUI
import ManagedConfigKit
import GroupWritesKit

/// Every write TenantKeep can make, each off until it is turned on here, with its permission
/// asked for at the toggle. Role activation and the macOS answer sit with them.
struct SettingsActionsPage: View {
    @Bindable var settings: AppSettings
    let isDemo: Bool
    /// Requests consent for the device write scopes. Returns nil on success, or a message.
    let requestDeviceActionsConsent: () async -> String?
    /// Requests consent for the user action scopes. Nil in demo.
    var requestUserActionsConsent: (() async -> String?)? = nil
    /// Requests consent for the group membership scopes. Nil in demo.
    var requestGroupWritesConsent: (() async -> String?)? = nil
    /// Requests consent for the PIM activation scopes. Nil in demo.
    var requestPrivilegedConsent: (() async -> String?)? = nil
    /// Opens the activation sheet, injected so Settings need not know about Graph.
    var privilegedSheet: (() -> PrivilegedAccessView)? = nil

    @State private var isRequestingConsent = false
    @State private var consentError: String?
    @State private var isRequestingPrivilegedConsent = false
    @State private var privilegedConsentError: String?
    @State private var showingPrivilegedSheet = false
    private let managed = ManagedConfigStore.shared

    var body: some View {
        Form {
            deviceActionsSection
            userActionsSection
            groupWritesSection
            privilegedAccessSection
            macOSSection
        }
        .navigationTitle("Actions and Permissions")
        // On the page, not the Section: a Section re-renders on every form state change,
        // which dismissed the sheet the instant it opened.
        .sheet(isPresented: $showingPrivilegedSheet) {
            if let privilegedSheet { privilegedSheet() }
        }
    }

    // MARK: - device actions

    @ViewBuilder
    private var deviceActionsSection: some View {
        if managed.config.isDisabled("deviceActions") {
            Section {
                Text("Your organization has turned off device actions in this app.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Device Actions")
            }
        } else {
            deviceActionsToggleSection
        }
    }

    private var deviceActionsToggleSection: some View {
        Section {
            Toggle("Allow device actions", isOn: Binding(
                get: { settings.deviceActionsEnabled },
                set: { newValue in
                    if newValue {
                        // Ask for consent NOW, at the moment of the decision, rather than
                        // later when the admin is standing at a broken machine. Finding
                        // out your org blocked the permission should not happen mid-repair.
                        Task { await enableDeviceActions() }
                    } else {
                        settings.deviceActionsEnabled = false
                        consentError = nil
                    }
                }
            ))
            .disabled(isRequestingConsent)

            if isRequestingConsent {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Requesting permission…").font(.footnote).foregroundStyle(.secondary)
                }
            }

            if let consentError {
                Text(consentError)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Device Actions")
        } footer: {
            Text("""
                Off by default. Turning this on asks Microsoft Entra ID for permission to \
                **modify** devices in your tenant, not just read them; your administrator \
                may need to approve it. It adds sync, restart, remote lock, locate and \
                BitLocker key rotation to every device screen. Each action asks before it \
                fires, is queued by Intune, and is written to the shift log.

                Leaving it off means TenantKeep only ever requests read access.
                """)
        }
    }

    // MARK: - user actions

    @State private var userActionsError: String?
    @State private var isRequestingUserActions = false

    @ViewBuilder
    private var userActionsSection: some View {
        if managed.config.isDisabled("userActions") {
            Section {
                Text("Your organization has turned off user actions in this app.")
                    .font(.footnote).foregroundStyle(.secondary)
            } header: {
                Text("User Actions")
            }
        } else {
            Section {
                Toggle("Allow user actions", isOn: Binding(
                    get: { settings.userActionsEnabled },
                    set: { newValue in
                        if newValue { Task { await enableUserActions() } } else {
                            settings.userActionsEnabled = false
                            userActionsError = nil
                        }
                    }))
                    .disabled(isRequestingUserActions)
                if isRequestingUserActions {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("Requesting permission…").font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if let userActionsError {
                    Text(userActionsError).font(.footnote).foregroundStyle(.red)
                }
            } header: {
                Text("User Actions")
            } footer: {
                Text("""
                    Off by default. Turning this on asks Microsoft Entra ID for permission to \
                    sign people out, block and allow sign-in, remove their sign-in methods, \
                    issue a Temporary Access Pass, and, on Entra ID P2, mark risk. They appear \
                    on a person's page in People, with their leaver checklist. Each asks before it is \
                    sent; removing sign-in methods asks for the address typed back.
                    """)
            }
        }
    }

    private func enableUserActions() async {
        userActionsError = nil
        guard let requestUserActionsConsent else {
            settings.userActionsEnabled = true
            userActionsError = "Demo mode: no permission was actually requested."
            return
        }
        isRequestingUserActions = true
        defer { isRequestingUserActions = false }
        if let error = await requestUserActionsConsent() {
            settings.userActionsEnabled = false
            userActionsError = error
        } else {
            settings.userActionsEnabled = true
        }
    }

    // MARK: - group changes

    @State private var groupWritesError: String?
    @State private var isRequestingGroupWrites = false
    @State private var confirmingAllGroups = false

    @ViewBuilder
    private var groupWritesSection: some View {
        let config = managed.config
        if config.isDisabled("groupWrites") || (config.appliedKeys.contains("groupWrite.scope") && config.groupWriteScope == .none) {
            Section {
                Text("Your organization has turned off group changes in this app.")
                    .font(.footnote).foregroundStyle(.secondary)
            } header: {
                Text("Group Changes")
            }
        } else {
            Section {
                Toggle("Allow group changes", isOn: Binding(
                    get: { settings.groupWritesEnabled },
                    set: { newValue in
                        if newValue { Task { await enableGroupWrites() } } else {
                            settings.groupWritesEnabled = false
                            groupWritesError = nil
                        }
                    }))
                    .disabled(isRequestingGroupWrites)
                if isRequestingGroupWrites {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("Requesting permission…").font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if let groupWritesError {
                    Text(groupWritesError).font(.footnote).foregroundStyle(.red)
                }
                if settings.groupWritesEnabled {
                    if config.appliedKeys.contains("groupWrite.scope") {
                        LabeledContent("Which groups", value: config.groupWriteScope == .all ? "All, set by your organization" : "Helpdesk, set by your organization")
                    } else {
                        Picker("Which groups", selection: Binding(
                            get: { settings.groupWriteMode },
                            set: { mode in
                                if mode == .all { confirmingAllGroups = true } else { settings.groupWriteMode = .tagged }
                            })) {
                            Text("Helpdesk").tag(GroupWriteMode.tagged)
                            Text("All").tag(GroupWriteMode.all)
                        }
                        // On the row that asks, not the Section: a Section's modifiers are
                        // copied onto each of its rows, and the copies race to present.
                        .alert("Allow changes to any group?", isPresented: $confirmingAllGroups) {
                            Button("Allow all groups", role: .destructive) { settings.groupWriteMode = .all }
                            Button("Keep helpdesk groups", role: .cancel) {}
                        } message: {
                            Text("Your role still limits what you can change. Role-assignable, dynamic, PIM, synced and mail groups stay off limits, and a group a Conditional Access policy names needs its name typed back.")
                        }
                    }
                }
            } header: {
                Text("Group Changes")
            } footer: {
                Text(groupWritesFooter)
            }
        }
    }

    private var groupWritesFooter: String {
        let policy = settings.groupWritePolicy
        let helpdesk = "groups in the " + policy.administrativeUnit + " administrative unit" + (policy.prefix.map { ", groups whose names start " + $0 } ?? "") + ", and groups you own"
        return "Off by default. Turning this on asks Microsoft Entra ID for permission to change group membership, never the groups themselves. "
            + "Helpdesk means " + helpdesk + ". It appears as Groups on a person's page in People, and every change shows what the group grants before it is sent."
    }

    private func enableGroupWrites() async {
        groupWritesError = nil
        guard let requestGroupWritesConsent else {
            settings.groupWritesEnabled = true
            groupWritesError = "Demo mode: no permission was actually requested."
            return
        }
        isRequestingGroupWrites = true
        defer { isRequestingGroupWrites = false }
        if let error = await requestGroupWritesConsent() {
            settings.groupWritesEnabled = false
            groupWritesError = error
        } else {
            settings.groupWritesEnabled = true
        }
    }

    private func enableDeviceActions() async {
        consentError = nil
        if isDemo {
            // No real tenant to consent against; let the toggle work so the UI is
            // explorable, and say so plainly.
            settings.deviceActionsEnabled = true
            consentError = "Demo mode: no permission was actually requested."
            return
        }
        isRequestingConsent = true
        defer { isRequestingConsent = false }

        if let error = await requestDeviceActionsConsent() {
            settings.deviceActionsEnabled = false
            consentError = error
        } else {
            settings.deviceActionsEnabled = true
        }
    }

    // MARK: - privileged access

    /// Just-in-time role activation, behind an opt-in toggle.
    ///
    /// Same shape as the rotation toggle above, and the same reason: the permission this
    /// asks for, requesting a privilege escalation, reads worse on a consent screen than
    /// reading a password does. A customer who never turns it on never sees it requested.
    ///
    /// The button appears only once the toggle is on, because offering an action whose
    /// permission has not been granted just produces a failure the user cannot act on.
    @ViewBuilder
    private var privilegedAccessSection: some View {
        if requestPrivilegedConsent != nil {
            Section {
                Toggle("Allow role activation", isOn: Binding(
                    get: { settings.privilegedActivationEnabled },
                    set: { newValue in
                        if newValue {
                            // Ask at the moment of the decision, like rotation. Discovering
                            // your organization blocked it while standing at a broken
                            // machine is the wrong time to find out.
                            Task { await enablePrivilegedActivation() }
                        } else {
                            settings.privilegedActivationEnabled = false
                            privilegedConsentError = nil
                        }
                    }
                ))
                .disabled(isRequestingPrivilegedConsent)

                if settings.privilegedActivationEnabled, privilegedSheet != nil {
                    Button {
                        showingPrivilegedSheet = true
                    } label: {
                        Label("Activate a role now", systemImage: "person.badge.key")
                    }
                }

                if let privilegedConsentError {
                    Text(privilegedConsentError)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Privileged Access")
            } footer: {
                Text("""
                    If your role is eligible through Privileged Identity Management rather than permanently assigned, TenantKeep can activate it here instead of sending you to the portal.

                    This asks Microsoft for permission to request activation of your own eligible roles, never anyone else's. Leave it off and that permission is never requested.

                    This switch is your preference; the permission itself is granted per organization. Signing in to a different one asks again, and the activation screen offers it there when needed.
                    """)
            }
        }
    }

    private func enablePrivilegedActivation() async {
        privilegedConsentError = nil
        guard let requestPrivilegedConsent else { return }

        if isDemo {
            settings.privilegedActivationEnabled = true
            privilegedConsentError = "Demo mode: no permission was actually requested."
            return
        }

        isRequestingPrivilegedConsent = true
        defer { isRequestingPrivilegedConsent = false }

        if let error = await requestPrivilegedConsent() {
            settings.privilegedActivationEnabled = false
            privilegedConsentError = error
        } else {
            settings.privilegedActivationEnabled = true
        }
    }

    // MARK: - macOS

    /// Shown DISABLED rather than hidden. A hidden toggle is dead code nobody remembers,
    /// and an admin wondering "why can't I see Mac passwords?" deserves an answer instead
    /// of an absence. When Microsoft ships an API, this becomes live.
    private var macOSSection: some View {
        Section {
            Toggle("macOS local admin passwords", isOn: .constant(false))
                .disabled(true)
        } header: {
            Text("macOS")
        } footer: {
            Text("""
                Unavailable. Microsoft doesn't currently offer an API for reading macOS \
                local administrator passwords. Intune keeps them encrypted on its own \
                service, and only the admin center can display them. TenantKeep will enable \
                this automatically if that changes.

                Rotation schedules for macOS devices are still shown where Microsoft \
                returns them.
                """)
        }
    }
}
