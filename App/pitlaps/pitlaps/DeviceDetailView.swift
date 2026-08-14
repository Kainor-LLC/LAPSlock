import SwiftUI
import UIKit
import Combine
import AuthKit
import CredentialKit
import InventoryKit
import PlatformSecurity

// Build Spec §6 — device detail and the credential reveal.
//
// This screen is where every piece of the foundation converges, in a strict order:
//
//   1. capabilities decide what is even offered (no dead buttons)
//   2. biometric gate must pass BEFORE any network call for a password
//   3. the password arrives as a SensitiveValue and is rendered, never stored as String
//   4. a bounded visible window auto-hides and wipes
//   5. backgrounding, screen recording, or a screenshot revokes immediately
//   6. copying is local-only and expires
//
// The ordering in (2) is deliberate: gate first, then fetch. Fetching first and gating
// the display would mean a Graph read (and an audit event in the customer's tenant)
// for a reveal the admin never completed.

@MainActor
final class DeviceDetailModel: ObservableObject {
    // Displayed state
    @Published var metadata: CredentialMetadata?
    @Published var isLoadingMetadata = false
    @Published var revealState: RevealState = .masked
    @Published var secondsRemaining = 0
    @Published var progress: Double = 0
    @Published var errorMessage: String?
    @Published var statusNote: String?
    @Published var isWorking = false
    @Published var isCaptured = false

    let device: ManagedDeviceSummary
    let capabilities: CredentialCapabilities
    private let provider: any LocalAdminCredentialProviding
    private let gate: BiometricGate
    private let session: RevealSession
    let isDemo: Bool

    /// The live credential. Held only while visible; wiped by the session's onWipe.
    private var secret: SensitiveValue?
    /// Kept solely so the clipboard can be cleared if it still holds this value.
    private var lastCopiedValue: String?

    init(
        device: ManagedDeviceSummary,
        provider: any LocalAdminCredentialProviding,
        isDemo: Bool,
        visibleDuration: TimeInterval = 60
    ) {
        self.device = device
        self.provider = provider
        self.capabilities = provider.capabilities
        self.isDemo = isDemo
        self.gate = BiometricGate()
        self.session = RevealSession(visibleDuration: visibleDuration)

        // The single wiring that matters most: when the window ends for ANY reason,
        // the bytes are overwritten and the clipboard is cleared.
        self.session.onWipe = { [weak self] in
            guard let self else { return }
            self.secret?.wipe()
            self.secret = nil
            if let copied = self.lastCopiedValue {
                SecureClipboard.clearIfHolding(copied)
                self.lastCopiedValue = nil
            }
        }
    }

    var revealedSecret: SensitiveValue? {
        session.isVisible ? secret : nil
    }

    // MARK: - metadata

    func loadMetadata() async {
        guard capabilities.supportsMetadata, device.revealBlockedReason == nil else { return }
        isLoadingMetadata = true
        defer { isLoadingMetadata = false }
        do {
            metadata = try await provider.metadata(for: device.credentialTarget)
        } catch {
            // Metadata failing is not worth an alarming error: the reveal path can still
            // work. Note it quietly.
            statusNote = Self.metadataNote(for: error)
        }
    }

    // MARK: - reveal

    func reveal() async {
        errorMessage = nil
        statusNote = nil

        // Structural blocks first — no gate, no network, just an explanation.
        if let blocked = device.revealBlockedReason {
            errorMessage = blocked
            return
        }
        guard capabilities.supportsReveal else {
            errorMessage = capabilities.unavailabilityReason
                ?? "Revealing passwords isn't available for this device."
            return
        }
        // Refuse while the screen is being recorded or mirrored.
        if isCaptured {
            errorMessage = RevealRevocation.screenRecording.message
            return
        }

        // STEP 1: the gate. Before any network call.
        let availability = gate.availability()
        guard availability.canAuthenticate else {
            errorMessage = BiometricPolicy.noAuthConfiguredMessage
            return
        }

        isWorking = true
        defer { isWorking = false }

        switch await gate.authenticate(deviceName: device.deviceName) {
        case .authenticated:
            break
        case .cancelledByUser, .fallbackDismissed:
            return                          // silent: the user chose not to proceed
        case .failed:
            errorMessage = "That didn't match. Try again."
            return
        case .unavailable(let reason):
            errorMessage = reason
            return
        }

        // STEP 2: fetch, only now that identity is confirmed.
        do {
            let credential = try await provider.reveal(for: device.credentialTarget)
            secret = credential.secret
            if metadata == nil {
                metadata = CredentialMetadata(
                    accountName: credential.accountName,
                    lastBackupDateTime: credential.backupDateTime,
                    lastRotationDateTime: credential.backupDateTime
                )
            }
            session.reveal()
            syncSessionState()
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    // MARK: - session lifecycle

    func tick() {
        session.tick()
        syncSessionState()
    }

    func hideNow() {
        session.mask()
        syncSessionState()
    }

    func revoke(_ reason: RevealRevocation) {
        session.revoke(reason)
        syncSessionState()
    }

    func leaveScreen() {
        session.reset()
        syncSessionState()
    }

    private func syncSessionState() {
        revealState = session.state
        secondsRemaining = session.secondsRemaining
        progress = session.progress
    }

    // MARK: - copy

    /// The username is not secret, so it copies without the expiring-clipboard
    /// treatment the password gets — an admin often needs it on the clipboard for
    /// longer than 90 seconds while working through a logon prompt.
    func copyUsername(_ name: String) {
        UIPasteboard.general.string = name
        statusNote = "Username copied."
    }

    func copyPassword() {
        guard let secret, session.isVisible else { return }
        secret.withValue { value in
            SecureClipboard.copyCredential(value)
            lastCopiedValue = value
        }
        statusNote = SecureClipboard.copyConfirmation()
    }

    // MARK: - rotate

    func rotate() async {
        guard capabilities.supportsRotate else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            try await provider.rotate(for: device.credentialTarget)
            statusNote = "Rotation requested. The device applies it on its next check-in."
            hideNow()
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    var portalURL: URL? { provider.portalURL(for: device.credentialTarget) }

    // MARK: - error copy (§8)

    static func describe(_ error: Error) -> String {
        guard let e = error as? CredentialError else {
            return "Something went wrong retrieving the password. Try again."
        }
        switch e {
        case .consentRequired:
            return "Your session expired. Sign in again to continue."
        case .notAuthorized:
            return "You're signed in, but your account doesn't hold a role that can read local administrator passwords. Cloud Device Administrator is the least-privileged role that can — and it can be activated just-in-time through Privileged Identity Management."
        case .notLapsEnabled:
            return "No LAPS password is stored for this device. Check that a Windows LAPS policy targets it and that the device has checked in since the policy applied."
        case .throttled(let retryAfter):
            if let retryAfter {
                return "Microsoft Graph is rate limiting this tenant. Try again in about \(Int(retryAfter)) seconds."
            }
            return "Microsoft Graph is rate limiting this tenant. Wait a moment and try again."
        case .serviceUnavailable:
            return "Microsoft isn't responding right now. This is on their side — try again shortly."
        case .transport(let status):
            return "The request failed (HTTP \(status)). Check your connection and try again."
        case .emptyCredentialSet:
            return "This device has a LAPS record but no stored password yet. It'll appear after the device backs one up."
        case .decodeFailure:
            return "Microsoft Graph returned a password in a format PitLAPS couldn't read. Please report this."
        case .missingIdentifier(let detail):
            return detail
        case .unsupportedOnPlatform(_, let reason):
            return reason
        }
    }

    static func metadataNote(for error: Error) -> String? {
        guard let e = error as? CredentialError else { return nil }
        switch e {
        case .serviceUnavailable:
            return "Microsoft isn't returning rotation details for this device right now."
        case .notLapsEnabled:
            return "No LAPS record for this device yet."
        default:
            return nil
        }
    }
}

// MARK: - view

struct DeviceDetailView: View {
    @StateObject var model: DeviceDetailModel
    @StateObject private var privacy = ScreenPrivacyMonitor()
    @Environment(\.scenePhase) private var scenePhase

    /// Drives the countdown. Half-second cadence so the label never appears to stall.
    private let ticker = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()

    var body: some View {
        List {
            credentialSection
            detailsSection
            if let note = model.statusNote {
                Section { Text(note).font(.footnote).foregroundStyle(.secondary) }
            }
        }
        .navigationTitle(model.device.deviceName)
        .navigationBarTitleDisplayMode(.inline)
        // Hide the whole screen from the app-switcher snapshot while a password is up.
        .privacyCover(isProtected: model.revealedSecret != nil)
        .onReceive(ticker) { _ in model.tick() }
        .onChange(of: scenePhase) { _, phase in
            // Revoke on anything other than active. The snapshot is taken during the
            // transition, so waiting for .background is too late.
            if phase != .active { model.revoke(.appBackgrounded) }
        }
        .task {
            privacy.onUnsafeCondition = { reason in model.revoke(reason) }
            privacy.start()
            model.isCaptured = privacy.isCaptured
            await model.loadMetadata()
        }
        .onChange(of: privacy.isCaptured) { _, captured in
            model.isCaptured = captured
        }
        .onDisappear {
            privacy.stop()
            model.leaveScreen()
        }
        .safeAreaInset(edge: .top) {
            if model.isDemo { DemoBanner() }
        }
    }

    // MARK: - credential

    @ViewBuilder
    private var credentialSection: some View {
        Section {
            if let secret = model.revealedSecret {
                RevealedCredentialCard(
                    secret: secret,
                    accountName: model.metadata?.accountName,
                    secondsRemaining: model.secondsRemaining,
                    progress: model.progress,
                    onCopyPassword: { model.copyPassword() },
                    onCopyUsername: { model.copyUsername($0) },
                    onHide: { model.hideNow() }
                )
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            } else {
                maskedCard
            }

            if let error = model.errorMessage {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Local administrator password")
        } footer: {
            credentialFooter
        }
    }

    @ViewBuilder
    private var maskedCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Explain the state that follows a hidden password, so it doesn't look lost.
            switch model.revealState {
            case .expired:
                Label("Hidden after 60 seconds", systemImage: "clock.badge.checkmark")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            case .revokedForSafety(let reason):
                Label(reason.message, systemImage: "eye.slash.fill")
                    .font(.footnote)
                    .foregroundStyle(reason == .screenshotTaken ? .orange : .secondary)
            case .masked, .revealed:
                EmptyView()
            }

            if let blocked = model.device.revealBlockedReason {
                explanation(blocked, icon: "info.circle")
            } else if !model.capabilities.supportsReveal {
                explanation(
                    model.capabilities.unavailabilityReason ?? "Not available for this device.",
                    icon: "info.circle"
                )
            } else if model.isCaptured {
                explanation(RevealRevocation.screenRecording.message, icon: "record.circle")
            } else {
                revealButton
            }
        }
        .padding(.vertical, 4)
    }

    private var revealButton: some View {
        Button {
            Task { await model.reveal() }
        } label: {
            HStack {
                Image(systemName: "faceid")
                Text(model.isWorking ? "Confirming…" : "Reveal password")
                    .fontWeight(.semibold)
                Spacer()
            }
            .padding(.vertical, 4)
        }
        .disabled(model.isWorking)
        .tint(Brand.signal)
    }

    private func explanation(_ text: String, icon: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundStyle(.secondary)
            Text(text).font(.footnote).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var credentialFooter: some View {
        VStack(alignment: .leading, spacing: 6) {
            if model.capabilities.supportsReveal && model.device.revealBlockedReason == nil {
                Text("Face ID confirms it's you before the password is retrieved. It hides again after 60 seconds.")
            }
            if let portal = model.portalURL, !model.capabilities.supportsReveal {
                Link("Open this device in Intune", destination: portal)
                    .font(.footnote.weight(.semibold))
            }
            if model.capabilities.usesBetaAPI && model.capabilities.supportsRotate {
                Text("Rotation uses a Microsoft preview API.")
            }
        }
    }

    // MARK: - details

    private var detailsSection: some View {
        Section("Device") {
            DataRow(label: "Name", value: model.device.deviceName)
            DataRow(label: "Platform", value: platformText, monospaced: false)
            osVersionRow
            DataRow(label: "Primary user", value: model.device.userPrincipalName)
            DataRow(label: "Model", value: model.device.model, monospaced: false)
            DataRow(label: "Serial", value: model.device.serialNumber)
            DataRow(label: "LAPS account", value: model.metadata?.accountName)
            DataRow(label: "Compliance", value: model.device.complianceState?.capitalized, monospaced: false)
            DataRow(label: "Last check-in", value: relative(model.device.lastSyncDateTime), monospaced: false)
            DataRow(label: "Last rotated", value: relative(model.metadata?.lastRotationDateTime), monospaced: false)
            DataRow(label: "Intune ID", value: model.device.id)
            DataRow(label: "Entra device ID", value: model.device.entraDeviceId ?? "None")

            if model.capabilities.supportsRotate {
                Button {
                    Task { await model.rotate() }
                } label: {
                    Label("Rotate password", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(model.isWorking)
            }
        }
    }

    /// Leads with the release name admins actually use, and keeps the build below it,
    /// because the build is what you need to verify a patch level. When the build is
    /// unknown to the table, this shows the raw version alone rather than guessing.
    @ViewBuilder
    private var osVersionRow: some View {
        if model.device.platform == .windows,
           let friendly = WindowsRelease.friendlyName(osVersion: model.device.osVersion) {
            HStack(alignment: .firstTextBaseline) {
                Text("OS VERSION")
                    .font(Brand.fieldLabel)
                    .foregroundStyle(.secondary)
                    .frame(width: 116, alignment: .leading)
                VStack(alignment: .leading, spacing: 2) {
                    Text(friendly)
                        .font(.subheadline)
                    if let raw = model.device.osVersion {
                        Text(raw)
                            .font(Brand.data(12))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
                Spacer(minLength: 0)
            }
        } else {
            DataRow(label: "OS version", value: model.device.osVersion)
        }
    }

    private var platformText: String {
        switch model.device.platform {
        case .windows: return "Windows"
        case .macOS: return "macOS"
        case .other: return model.device.operatingSystemRaw ?? "Other"
        }
    }

    private func relative(_ date: Date?) -> String? {
        guard let date else { return nil }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: date, relativeTo: Date())
    }
}

// MARK: - the revealed card (the signature moment)

/// The one place boldness is spent. Everything else on this screen is quiet.
///
/// The password is rendered INSIDE `withValue`, so the plaintext never becomes a stored
/// property. Text selection is deliberately off: selection would allow a copy that
/// bypasses the expiring, local-only clipboard path.
struct RevealedCredentialCard: View {
    let secret: SensitiveValue
    let accountName: String?
    let secondsRemaining: Int
    let progress: Double
    let onCopyPassword: () -> Void
    let onCopyUsername: (String) -> Void
    let onHide: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                usernameField
                Spacer(minLength: 12)
                countdown
            }

            passwordField

            HStack(spacing: 10) {
                Button(action: onCopyPassword) {
                    Label("Copy password", systemImage: "doc.on.doc")
                        .font(.subheadline.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.borderedProminent)
                .tint(Brand.signal)

                Button(action: onHide) {
                    Label("Hide", systemImage: "eye.slash")
                        .font(.subheadline.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)
                .tint(Brand.mist)
            }
        }
        .padding(18)
        .background(Brand.pitWall)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .padding(.vertical, 6)
    }

    /// The account name is half the credential — you cannot sign in with a password
    /// alone, and LAPS account names vary by policy (Administrator, LapsAdmin, a custom
    /// name). It gets its own labelled, copyable field rather than a caption.
    ///
    /// When Graph doesn't return one, say so. Guessing "Administrator" would be a
    /// plausible-looking wrong answer, which is worse than an honest gap.
    @ViewBuilder
    private var usernameField: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("USERNAME")
                .font(Brand.fieldLabel)
                .foregroundStyle(Brand.mist)
            if let accountName, !accountName.isEmpty {
                HStack(spacing: 8) {
                    Text(accountName)
                        .font(Brand.data(17, weight: .medium))
                        .foregroundStyle(.white)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                    Button {
                        onCopyUsername(accountName)
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .font(.footnote)
                            .foregroundStyle(Brand.mist)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Copy username")
                }
            } else {
                Text("Not provided by Microsoft")
                    .font(.footnote)
                    .foregroundStyle(Brand.mist)
            }
        }
    }

    /// The password. Rendered INSIDE `withValue`, so the plaintext never becomes a
    /// stored property. Selection is off: it would allow a copy that bypasses the
    /// expiring, local-only clipboard path.
    private var passwordField: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("PASSWORD")
                .font(Brand.fieldLabel)
                .foregroundStyle(Brand.mist)
            secret.withValue { value in
                Text(value)
                    .font(Brand.data(23, weight: .semibold))
                    .foregroundStyle(.white)
                    .textSelection(.disabled)
                    .minimumScaleFactor(0.6)
                    .lineLimit(2)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityLabel("Local administrator password")
            }
        }
    }

    /// The signature element: a pit-timer countdown. Functional first — an admin needs
    /// to know how long they have before it disappears mid-transcription.
    private var countdown: some View {
        ZStack {
            Circle()
                .stroke(Brand.mist.opacity(0.25), lineWidth: 3)
            Circle()
                .trim(from: 0, to: max(0.001, 1 - progress))
                .stroke(Brand.signal, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(secondsRemaining)")
                .font(Brand.data(15, weight: .semibold))
                .foregroundStyle(.white)
                .monospacedDigit()
        }
        .frame(width: 44, height: 44)
        .animation(.linear(duration: 0.5), value: progress)
        .accessibilityLabel("\(secondsRemaining) seconds until the password hides")
    }
}
