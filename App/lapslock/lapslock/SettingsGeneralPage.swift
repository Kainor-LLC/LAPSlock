import SwiftUI
import ManagedConfigKit
import RelayKit
import PlatformSecurity

/// Appearance, the app lock and, with a session, Intune app protection and names in the
/// device list.
struct SettingsGeneralPage: View {
    @Bindable var settings: AppSettings
    let isDemo: Bool
    let hasSession: Bool
    /// Requests consent to read users' display names. Nil in demo.
    var requestUserNamesConsent: (() async -> String?)? = nil
    /// Signs in to the App Protection registration and asks Intune for a policy. Nil in demo.
    var turnOnAppProtection: (() async -> String?)? = nil

    @Environment(\.confirmMethod) private var confirm
    @State private var isRequestingNamesConsent = false
    @State private var namesConsentError: String?
    @State private var isTurningOnProtection = false
    @State private var protectionError: String?
    private let managed = ManagedConfigStore.shared
    private let protection = AppProtection.shared

    var body: some View {
        Form {
            appearanceSection
            appLockSection
            if hasSession, !isDemo {
                appProtectionSection
            }
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
                LabeledContent("Require \(confirm.name) to open TenantKeep", value: "Required")
                Text("Your organization requires the app lock.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Toggle("Require \(confirm.name) to open TenantKeep", isOn: $settings.appLockEnabled)
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

    // MARK: - Intune app protection

    /// What the organization's Intune policy is doing to the app, and the way in when the
    /// app could not tell by itself that the organization approved it.
    ///
    /// Shown to everyone who is signed in, so an administrator can see at a glance that no
    /// policy applies. Turning it on is the same step the app takes unasked for an
    /// organization that approved TenantKeep App Protection for everyone.
    private var appProtectionSection: some View {
        Section {
            switch protection.state {
            case .managed:
                LabeledContent("Policy", value: "Applied")
                LabeledContent("Notifications", value: notificationsLine)
                LabeledContent("Apple Watch", value: protection.watchWithheld == nil ? "Allowed" : "Kept on iPhone")
            case .notTargeted:
                LabeledContent("Policy", value: "None for you")
            case .checking:
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Asking Intune…").font(.footnote).foregroundStyle(.secondary)
                }
            case .notLicensed:
                LabeledContent("Policy", value: "No Intune licence")
                Text("Intune answered that your account has no Intune licence, so no policy can apply to it. Your administrator assigns one in the Microsoft 365 admin center.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                askButton("Check again")
            case .idle, .needsSignIn:
                askButton("Turn on")
            case .failed(let code):
                Text("Intune did not apply a policy (status \(code)).")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                askButton("Try again")
            }

            if let protectionError {
                Text(protectionError)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Intune App Protection")
        } footer: {
            Text(protection.state == .managed ? """
                Your organization's Intune app protection policy applies to TenantKeep on \
                this device. It can require a PIN, limit copying out of the app, and remove \
                what the app holds.
                """ : """
                For organizations that protect apps with Microsoft Intune. Turning this on \
                signs you in to TenantKeep App Protection, which your organization approves \
                separately, and asks Intune whether a policy applies to you. With no policy, \
                nothing changes.
                """)
        }
    }

    private var notificationsLine: String {
        switch protection.notificationDetail {
        case .full:           return "Shown in full"
        case .withoutDetails: return "Without details"
        case .none:           return "Off"
        }
    }

    /// Signs in to the App Protection registration when that is still needed, and asks
    /// Intune again either way.
    @ViewBuilder
    private func askButton(_ title: LocalizedStringKey) -> some View {
        Button(title) { Task { await turnOnProtection() } }
            .disabled(isTurningOnProtection || turnOnAppProtection == nil)
        if isTurningOnProtection {
            HStack(spacing: 8) {
                ProgressView()
                Text("Asking Intune…").font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    private func turnOnProtection() async {
        guard let turnOnAppProtection else { return }
        protectionError = nil
        isTurningOnProtection = true
        defer { isTurningOnProtection = false }
        protectionError = await turnOnAppProtection()
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
