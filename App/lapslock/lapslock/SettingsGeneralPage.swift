import SwiftUI
import ManagedConfigKit

/// Appearance, the app lock and, with a session, names in the device list.
struct SettingsGeneralPage: View {
    @Bindable var settings: AppSettings
    let isDemo: Bool
    let hasSession: Bool
    /// Requests consent to read users' display names. Nil in demo.
    var requestUserNamesConsent: (() async -> String?)? = nil

    @State private var isRequestingNamesConsent = false
    @State private var namesConsentError: String?
    private let managed = ManagedConfigStore.shared

    var body: some View {
        Form {
            appearanceSection
            appLockSection
            if hasSession {
                userNamesSection
            }
        }
        .navigationTitle("General")
    }

    // MARK: - appearance

    private var appearanceSection: some View {
        Section("Appearance") {
            Picker("Theme", selection: $settings.appearance) {
                ForEach(AppearancePreference.allCases) { pref in
                    Text(pref.label).tag(pref)
                }
            }
            .pickerStyle(.segmented)
        }
    }

    // MARK: - app lock

    /// Holds the whole app behind Face ID.
    ///
    /// Unlike the other toggles this asks Microsoft for nothing, it is entirely local, so
    /// there is no consent prompt and no new permission on anybody's consent screen.
    private var appLockSection: some View {
        Section {
            if managed.config.appLockRequired {
                LabeledContent("Require Face ID to open TenantKeep", value: "Required")
                Text("Your organization requires the app lock.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Toggle("Require Face ID to open TenantKeep", isOn: $settings.appLockEnabled)
            }
        } header: {
            Text("App Lock")
        } footer: {
            Text(managed.config.appLockRequired ? """
                Separate from the check before each password reveal, which always runs. This \
                one protects the device list itself, and your organization requires it.

                TenantKeep re-locks after a few minutes in the background, not instantly, so \
                switching to Microsoft Authenticator and back does not ask twice.
                """ : """
                Off by default. Separate from the check before each password reveal, which \
                always runs. This one protects the device list itself: hostnames, primary \
                users and compliance state are worth something to an attacker even with no \
                password on screen.

                TenantKeep re-locks after a few minutes in the background, not instantly, so \
                switching to Microsoft Authenticator and back does not ask twice.
                """)
        }
    }

    // MARK: - user names

    /// Display names for device rows, behind an opt-in toggle.
    ///
    /// Intune often leaves `userDisplayName` empty, so rows show the UPN. Filling the gap
    /// means reading user objects from Entra, which puts `User.ReadBasic.All` on the
    /// customer's consent screen, a password app asking to read the user list. That is a
    /// choice for the customer, so it has the same shape as rotation: off by default, consent
    /// requested at the moment of the decision, and the footer says exactly what it adds.
    private var userNamesSection: some View {
        Section {
            Toggle("Show user names", isOn: Binding(
                get: { settings.userNamesEnabled },
                set: { newValue in
                    if newValue {
                        Task { await enableUserNames() }
                    } else {
                        settings.userNamesEnabled = false
                        namesConsentError = nil
                    }
                }
            ))
            .disabled(isRequestingNamesConsent)

            if isRequestingNamesConsent {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Requesting permission…").font(.footnote).foregroundStyle(.secondary)
                }
            }

            if let namesConsentError {
                Text(namesConsentError)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Device List")
        } footer: {
            Text("""
                Off by default. Intune often leaves a device's primary user as a sign-in \
                address rather than a name. Turning this on looks the name up in Microsoft \
                Entra ID, which adds one permission to what TenantKeep requests from your \
                organization: reading basic user profiles (User.ReadBasic.All). Names are \
                kept in memory for this session and never stored.

                Leaving it off means TenantKeep never reads your user directory.
                """)
        }
    }

    private func enableUserNames() async {
        namesConsentError = nil
        if isDemo {
            settings.userNamesEnabled = true
            namesConsentError = "Demo mode: no permission was actually requested."
            return
        }
        guard let requestUserNamesConsent else { return }
        isRequestingNamesConsent = true
        defer { isRequestingNamesConsent = false }

        if let error = await requestUserNamesConsent() {
            settings.userNamesEnabled = false
            namesConsentError = error
        } else {
            settings.userNamesEnabled = true
        }
    }
}
