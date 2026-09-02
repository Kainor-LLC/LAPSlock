import SwiftUI
import UIKit
import Combine
import AuthKit
import CredentialKit
import InventoryKit
import PlatformSecurity
import DiagnosticsKit
import LicensingKit

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
    /// Account name for the CURRENT reveal only. Cleared on hide, expiry, and
    /// revocation, alongside the password.
    @Published var revealedAccountName: String?

    /// Which single secret is currently on screen. Only ever one: two credentials
    /// visible at once doubles exposure for no workflow benefit (at the machine you use
    /// one or the other), needs two countdowns, and complicates the wipe path.
    enum RevealedItem: Equatable {
        case none
        case lapsPassword
        case bitLockerKey(id: String)
    }
    @Published var revealedItem: RevealedItem = .none

    // BitLocker
    @Published var bitLockerKeys: [BitLockerKeyInfo] = []
    @Published var isLoadingKeys = false
    @Published var bitLockerListError: String?
    @Published var revealedKeyInfo: BitLockerKeyInfo?

    let device: ManagedDeviceSummary
    let capabilities: CredentialCapabilities
    private let provider: any LocalAdminCredentialProviding
    private let gate: BiometricGate
    private let session: RevealSession
    let isDemo: Bool
    /// Mirrors the Settings toggle. When false, rotation is neither offered nor possible.
    @Published var rotationEnabled: Bool

    /// The live credential. Held only while visible; wiped by the session's onWipe.
    private var secret: SensitiveValue?
    /// Kept solely so the clipboard can be cleared if it still holds this value.
    private var lastCopiedValue: String?
    /// Currently revealed BitLocker key, if any.
    private var bitLockerSecret: SensitiveValue?
    private let bitLocker: any BitLockerKeyProviding

    /// Free-tier reveal meter. Counts events only — LicensingKit cannot hold a credential,
    /// and `scripts/isolation-check.sh` fails the build if it ever imports CredentialKit.
    private let meter: RevealMeter
    /// Pro removes metering entirely. Wired to the entitlement check once that exists.
    let isPro: Bool
    /// Reveals left in the current window, for display BEFORE the user taps anything.
    @Published var remainingReveals: Int = 0

    init(
        device: ManagedDeviceSummary,
        provider: any LocalAdminCredentialProviding,
        bitLocker: any BitLockerKeyProviding,
        isDemo: Bool,
        rotationEnabled: Bool = false,
        visibleDuration: TimeInterval = 60,
        // Defaulted to nil rather than to a constructed meter: a default argument
        // expression is evaluated in a nonisolated context, and RevealMeter.init is
        // @MainActor. Building it in the body works because this class is @MainActor,
        // so the initializer is too. Previews and tests that pass nothing get a private
        // in-memory meter and never touch the Keychain.
        meter: RevealMeter? = nil,
        isPro: Bool = false
    ) {
        self.device = device
        self.provider = provider
        self.bitLocker = bitLocker
        self.capabilities = provider.capabilities
        self.isDemo = isDemo
        self.rotationEnabled = rotationEnabled
        self.gate = BiometricGate()
        self.session = RevealSession(visibleDuration: visibleDuration)
        let resolvedMeter = meter ?? RevealMeter(store: InMemoryRevealLedgerStore())
        self.meter = resolvedMeter
        self.isPro = isPro
        self.remainingReveals = resolvedMeter.remaining(isPro: isPro)

        // The single wiring that matters most: when the window ends for ANY reason,
        // the bytes are overwritten and the clipboard is cleared.
        self.session.onWipe = { [weak self] in
            guard let self else { return }
            self.secret?.wipe()
            self.secret = nil
            // The account name hides with the password. It is not secret in the way a
            // password is, but it IS reconnaissance: knowing the LAPS account name tells
            // an onlooker exactly which account to attack. It is also half the
            // credential, so leaving it on screen after Hide undercuts the point of
            // hiding. Both disappear together.
            self.revealedAccountName = nil
            self.bitLockerSecret?.wipe()
            self.bitLockerSecret = nil
            self.revealedKeyInfo = nil
            self.revealedItem = .none
            if let copied = self.lastCopiedValue {
                SecureClipboard.clearIfHolding(copied)
                self.lastCopiedValue = nil
            }
        }
    }

    var revealedSecret: SensitiveValue? {
        guard session.isVisible, revealedItem == .lapsPassword else { return nil }
        return secret
    }

    var revealedBitLockerSecret: SensitiveValue? {
        guard session.isVisible, case .bitLockerKey = revealedItem else { return nil }
        return bitLockerSecret
    }

    /// Clears any currently visible secret before a new reveal begins, so the
    /// one-at-a-time rule holds even if the user taps a second Reveal immediately.
    private func clearForNewReveal() {
        if session.isVisible { session.mask() }
        syncSessionState()
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

        // STEP 1: the free-tier meter, BEFORE the gate.
        //
        // The ordering is the whole point. Checking after the gate would make somebody
        // complete Face ID and only then learn they are out of reveals, which is exactly
        // the surprise-at-the-machine failure the free tier is designed to avoid. A
        // blocked reveal costs no authentication and no network call.
        if case .exhausted(let nextAvailable) = meter.check(deviceIdentifier: device.id, isPro: isPro) {
            errorMessage = Self.meterExhaustedMessage(nextAvailable: nextAvailable)
            return
        }

        // STEP 2: the gate. Before any network call.
        let availability = gate.availability()
        guard availability.canAuthenticate else {
            errorMessage = BiometricPolicy.noAuthConfiguredMessage
            return
        }

        clearForNewReveal()
        isWorking = true
        let started = Date()
        defer { isWorking = false }

        switch await gate.authenticate(deviceName: device.deviceName) {
        case .authenticated:
            break
        case .cancelledByUser, .fallbackDismissed:
            await Self.record(.biometricGate, .userCancelled, since: started)
            return                          // silent: the user chose not to proceed
        case .failed:
            errorMessage = "That didn't match. Try again."
            return
        case .unavailable(let reason):
            errorMessage = reason
            return
        }

        // STEP 2: fetch, only now that identity is confirmed.
        // Time the NETWORK call, not the human. Measuring from before the Face ID prompt
        // folded think-time into the duration and made Graph look slow.
        let fetchStarted = Date()
        do {
            let credential = try await provider.reveal(for: device.credentialTarget)
            secret = credential.secret
            revealedAccountName = credential.accountName
            if metadata == nil {
                // Note: accountName is deliberately NOT stored in metadata, which
                // persists past the reveal window. It lives only in revealedAccountName.
                metadata = CredentialMetadata(
                    accountName: nil,
                    lastBackupDateTime: credential.backupDateTime,
                    lastRotationDateTime: credential.backupDateTime
                )
            }
            revealedItem = .lapsPassword
            session.reveal()
            syncSessionState()
            // Charge only now. A cancelled prompt, a permission error or a network
            // failure must never cost a credit — the user pays for reveals that actually
            // produced a password, and nothing else.
            remainingReveals = meter.recordReveal(deviceIdentifier: device.id, isPro: isPro)
            await Self.record(.credentialReveal, .success,
                              endpoint: DiagnosticEndpoint.deviceLocalCredentials,
                              platform: device.platform, since: fetchStarted)
        } catch {
            errorMessage = Self.describe(error)
            await Self.record(.credentialReveal, Self.outcome(for: error),
                              endpoint: DiagnosticEndpoint.deviceLocalCredentials,
                              platform: device.platform, since: fetchStarted)
        }
    }

    // MARK: - BitLocker

    /// Loads key METADATA only — no key values, low-privilege scope. Safe before any gate.
    func loadBitLockerKeys() async {
        guard let entraDeviceId = device.entraDeviceId else { return }
        guard device.platform == .windows else { return }
        isLoadingKeys = true
        bitLockerListError = nil
        defer { isLoadingKeys = false }
        do {
            bitLockerKeys = try await bitLocker.keys(forEntraDeviceId: entraDeviceId)
        } catch {
            bitLockerListError = Self.describeBitLockerList(error)
        }
    }

    /// Reveals one recovery key. Same order as the password path: gate, then fetch.
    func revealBitLockerKey(_ info: BitLockerKeyInfo) async {
        errorMessage = nil
        statusNote = nil

        if isCaptured {
            errorMessage = RevealRevocation.screenRecording.message
            return
        }

        // Meter before the gate, same as the password path. LAPS passwords and BitLocker
        // keys draw on one shared allowance: both are a credential leaving the tenant, and
        // splitting them into two counters would be arbitrary from the admin's side.
        if case .exhausted(let nextAvailable) = meter.check(deviceIdentifier: device.id, isPro: isPro) {
            errorMessage = Self.meterExhaustedMessage(nextAvailable: nextAvailable)
            return
        }

        let availability = gate.availability()
        guard availability.canAuthenticate else {
            errorMessage = BiometricPolicy.noAuthConfiguredMessage
            return
        }

        clearForNewReveal()
        isWorking = true
        defer { isWorking = false }

        switch await gate.authenticate(deviceName: device.deviceName) {
        case .authenticated: break
        case .cancelledByUser, .fallbackDismissed: return
        case .failed:
            errorMessage = "That didn't match. Try again."
            return
        case .unavailable(let reason):
            errorMessage = reason
            return
        }

        let started = Date()
        do {
            let revealed = try await bitLocker.reveal(keyId: info.id, info: info)
            bitLockerSecret = revealed.secret
            revealedKeyInfo = info
            revealedItem = .bitLockerKey(id: info.id)
            session.reveal()
            syncSessionState()
            remainingReveals = meter.recordReveal(deviceIdentifier: device.id, isPro: isPro)
            await Self.record(.credentialReveal, .success,
                              endpoint: "/v1.0/informationProtection/bitlocker/recoveryKeys/{id}",
                              platform: device.platform, since: started)
        } catch {
            errorMessage = Self.describe(error)
            await Self.record(.credentialReveal, Self.outcome(for: error),
                              endpoint: "/v1.0/informationProtection/bitlocker/recoveryKeys/{id}",
                              platform: device.platform, since: started)
        }
    }

    /// Queues a BitLocker key rotation. Only reachable when Settings has rotation on.
    func rotateBitLockerKeys() async {
        guard rotationEnabled else { return }
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        do {
            try await bitLocker.rotateKeys(managedDeviceId: device.id)
            // "Requested", never "rotated": Intune queues the action and the device
            // applies it on its next check-in, which may be a while if it is offline.
            statusNote = "Rotation requested. The device generates a new key the next time it checks in with Intune, then you'll see the new key here."
            hideNow()
            await loadBitLockerKeys()
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    func copyBitLockerKey() {
        guard let bitLockerSecret, session.isVisible else { return }
        bitLockerSecret.withValue { value in
            SecureClipboard.copyCredential(value)
            lastCopiedValue = value
        }
        statusNote = SecureClipboard.copyConfirmation()
    }

    /// Error copy for the key LIST, which is a softer failure than a failed reveal —
    /// the rest of the screen still works.
    static func describeBitLockerList(_ error: Error) -> String? {
        guard let e = error as? CredentialError else { return "Couldn't load BitLocker recovery keys." }
        switch e {
        case .notAuthorized:
            return "Your account can't read BitLocker recovery keys. Cloud Device Administrator, Helpdesk Administrator, Security Reader, or Global Reader can."
        case .missingIdentifier(let detail):
            return detail
        case .consentRequired:
            return "Your session expired. Sign in again to continue."
        case .throttled:
            return "Microsoft Graph is rate limiting this tenant. Try again shortly."
        case .serviceUnavailable:
            return "Microsoft isn't responding right now. Try again shortly."
        default:
            return "Couldn't load BitLocker recovery keys."
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

    // MARK: - diagnostics

    /// Records an operation outcome. Typed fields only; the event type cannot carry a
    /// credential, a device name, or a response body.
    ///
    /// TODO before launch: capture Graph's `request-id` header. It is the most useful
    /// field for a Microsoft support case and the services don't surface it on their
    /// typed errors yet.
    static func record(
        _ op: DiagnosticOperation,
        _ outcome: DiagnosticOutcome,
        endpoint: String? = nil,
        platform: DevicePlatform? = nil,
        since started: Date
    ) async {
        await DiagnosticsRecorder.shared.record(
            op, outcome,
            endpointTemplate: endpoint,
            devicePlatform: platform?.rawValue,
            durationMs: Int(Date().timeIntervalSince(started) * 1000)
        )
    }

    static func outcome(for error: Error) -> DiagnosticOutcome {
        guard let e = error as? CredentialError else { return .unknown }
        switch e {
        case .consentRequired:        return .consentRequired
        case .notAuthorized:          return .notAuthorized
        case .notLapsEnabled:         return .notFound
        case .throttled:              return .throttled
        case .serviceUnavailable:     return .serviceUnavailable
        case .transport:              return .transportError
        case .emptyCredentialSet:     return .notFound
        case .decodeFailure:          return .decodeFailure
        case .missingIdentifier:      return .missingIdentifier
        case .unsupportedOnPlatform:  return .unsupportedOnPlatform
        }
    }

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
            return "Microsoft Graph returned a password in a format LAPSlock couldn't read. Please report this."
        case .missingIdentifier(let detail):
            return detail
        case .unsupportedOnPlatform(_, let reason):
            return reason
        }
    }

    // MARK: - free tier copy

    /// Shown once, when the allowance runs out. Not a nag: this audience is unusually
    /// allergic to being sold to, so it appears at the moment of the block and nowhere
    /// else.
    ///
    /// TODO when StoreKit products exist: append the upgrade action and let StoreKit
    /// supply the localized price. Never hardcode a price string — App Store pricing is
    /// per-storefront and a baked-in number will be wrong somewhere.
    static func meterExhaustedMessage(nextAvailable: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        let when = formatter.localizedString(for: nextAvailable, relativeTo: Date())
        return "You've used all your free reveals for now. The next one frees up \(when). "
            + "Pro removes the limit."
    }

    /// The count shown BEFORE the user taps, so nobody discovers the wall while standing
    /// at a broken machine. Nil for Pro, and nil at zero because the block message says
    /// it better at that point.
    var remainingRevealsNote: String? {
        guard !isPro, remainingReveals > 0 else { return nil }
        return remainingReveals == 1
            ? "1 free reveal left this month."
            : "\(remainingReveals) free reveals left this month."
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
            bitLockerSection
            detailsSection
            if let note = model.statusNote {
                Section { Text(note).font(.footnote).foregroundStyle(.secondary) }
            }
        }
        .navigationTitle(model.device.deviceName)
        .navigationBarTitleDisplayMode(.inline)
        // Without this the nav bar is transparent and scrolled content reads through it,
        // which looked like overlapping text at the top of the screen.
        .toolbarBackground(.visible, for: .navigationBar)
        // Hide the whole screen from the app-switcher snapshot while a password is up.
        .privacyCover(isProtected: model.revealedSecret != nil || model.revealedBitLockerSecret != nil)
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
            await model.loadBitLockerKeys()
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
                    accountName: model.revealedAccountName,
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
        .tint(Brand.accent)
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
                // Stated up front, never as a surprise. An admin who discovers the limit
                // while standing at a broken workstation taps reveal again, and every
                // extra tap is another audit event in the customer's tenant.
                if let note = model.remainingRevealsNote {
                    Text(note)
                }
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

    // MARK: - BitLocker

    @ViewBuilder
    private var bitLockerSection: some View {
        // Only Windows devices have BitLocker. Showing an empty section on a Mac would
        // just raise a question with no answer.
        if model.device.platform == .windows {
            Section {
                if !model.device.hasEntraDeviceIdentity {
                    explanation(
                        "This device isn't joined to Microsoft Entra ID, so no recovery keys are backed up to it.",
                        icon: "info.circle"
                    )
                } else if model.isLoadingKeys {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Loading recovery keys…").font(.footnote).foregroundStyle(.secondary)
                    }
                } else if let error = model.bitLockerListError {
                    explanation(error, icon: "exclamationmark.triangle")
                } else if model.bitLockerKeys.isEmpty {
                    explanation(
                        "No BitLocker recovery keys are backed up for this device. If the disk is encrypted, check that your policy escrows keys to Microsoft Entra ID.",
                        icon: "info.circle"
                    )
                } else {
                    ForEach(model.bitLockerKeys) { key in
                        bitLockerRow(key)
                    }
                    if model.rotationEnabled {
                        Button {
                            Task { await model.rotateBitLockerKeys() }
                        } label: {
                            Label("Rotate recovery keys", systemImage: "arrow.triangle.2.circlepath")
                        }
                        .disabled(model.isWorking)
                    }
                    // A tappable link belongs in the section body, not the footer, where
                    // it looked orphaned between two sections.
                    if let portal = model.portalURL {
                        Link(destination: portal) {
                            Label("Open this device in Intune", systemImage: "arrow.up.right.square")
                        }
                    }
                }
            } header: {
                Text("BitLocker recovery keys")
            } footer: {
                bitLockerFooter
            }
        }
    }

    @ViewBuilder
    private func bitLockerRow(_ key: BitLockerKeyInfo) -> some View {
        if case .bitLockerKey(let revealedId) = model.revealedItem,
           revealedId == key.id,
           let secret = model.revealedBitLockerSecret {
            RevealedRecoveryKeyCard(
                secret: secret,
                info: key,
                secondsRemaining: model.secondsRemaining,
                progress: model.progress,
                onCopy: { model.copyBitLockerKey() },
                onHide: { model.hideNow() }
            )
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
        } else {
            Button {
                Task { await model.revealBitLockerKey(key) }
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: key.volumeType == .operatingSystemVolume
                          ? "internaldrive.fill" : "externaldrive.fill")
                        .foregroundStyle(.secondary)
                        .frame(width: 24)
                    VStack(alignment: .leading, spacing: 2) {
                        // Accent, deliberately: a tinted title is how iOS signals an
                        // action row. The metadata beneath stays secondary so the row
                        // doesn't become a single block of orange.
                        Text(key.volumeType.displayName)
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(Brand.accent)
                        HStack(spacing: 6) {
                            // The prefix matches the key identifier BitLocker shows on
                            // the recovery screen, which is how you tell several keys apart.
                            Text("ID \(key.shortIdentifier)")
                                .font(Brand.data(11))
                            if let created = key.createdDateTime {
                                Text("· backed up \(relative(created) ?? "")")
                                    .font(.caption2)
                            }
                        }
                        .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 0)
                    Image(systemName: "faceid").foregroundStyle(Brand.accent)
                }
            }
            .buttonStyle(.plain)   // stops the tint bleeding onto the metadata line
            .disabled(model.isWorking || model.isCaptured)
        }
    }

    /// The upfront disclosure about what LAPSlock deliberately cannot do.
    @ViewBuilder
    private var bitLockerFooter: some View {
        VStack(alignment: .leading, spacing: 8) {
            if model.device.platform == .windows && model.device.hasEntraDeviceIdentity {
                Text("Face ID confirms it's you before a key is retrieved. Each retrieval is recorded in your tenant's audit log.")
            }
            // Stated plainly and always, not buried. LAPSlock asking for LESS than it
            // could is a feature worth naming, and an admin should learn the tradeoff
            // here rather than discovering it at a broken machine.
            Label {
                if model.rotationEnabled {
                    Text("Rotation is **on**. LAPSlock has permission to modify devices in this tenant. Rotation is queued and applies at the device's next Intune check-in.")
                } else {
                    Text("LAPSlock can read recovery keys but **can't rotate them**, because rotation needs permission to modify devices in your tenant and this app doesn't ask for that by default. Turn on **Allow BitLocker key rotation** in Settings to grant it, or rotate from the Intune admin center instead.")
                }
            } icon: {
                Image(systemName: model.rotationEnabled ? "lock.open" : "lock.shield")
            }
            .font(.footnote)
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
    @Environment(\.colorScheme) private var colorScheme
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
                    Label("Copy", systemImage: "doc.on.doc")
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.borderedProminent)
                .tint(Brand.accentOnField)

                Button(action: onHide) {
                    Label("Hide", systemImage: "eye.slash")
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)
                .tint(Brand.mist)
            }
        }
        .padding(18)
        .background(Brand.field)
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
        CountdownRing(secondsRemaining: secondsRemaining, progress: progress)
    }
}

// MARK: - revealed recovery key card

/// A BitLocker recovery key is 48 digits in eight hyphenated groups — far too long to
/// read as one line on a phone. It is chunked into two rows of four groups, which is how
/// people actually read them off a screen while typing into a recovery prompt.
///
/// Same guarantees as the password card: rendered inside `withValue` so the plaintext is
/// never a stored property, and selection disabled so a copy can't bypass the expiring,
/// local-only clipboard.
struct RevealedRecoveryKeyCard: View {
    @Environment(\.colorScheme) private var colorScheme
    let secret: SensitiveValue
    let info: BitLockerKeyInfo
    let secondsRemaining: Int
    let progress: Double
    let onCopy: () -> Void
    let onHide: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("RECOVERY KEY")
                        .font(Brand.fieldLabel)
                        .foregroundStyle(Brand.mist)
                    Text("\(info.volumeType.displayName) · ID \(info.shortIdentifier)")
                        .font(.caption)
                        .foregroundStyle(Brand.mist)
                }
                Spacer(minLength: 12)
                CountdownRing(secondsRemaining: secondsRemaining, progress: progress)
            }

            secret.withValue { value in
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Self.rows(from: value), id: \.self) { row in
                        Text(row)
                            .font(Brand.data(17, weight: .semibold))
                            .foregroundStyle(.white)
                            .textSelection(.disabled)
                            .minimumScaleFactor(0.7)
                            .lineLimit(1)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityLabel("BitLocker recovery key")
            }

            HStack(spacing: 10) {
                Button(action: onCopy) {
                    Label("Copy", systemImage: "doc.on.doc")
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.borderedProminent)
                .tint(Brand.accentOnField)

                Button(action: onHide) {
                    Label("Hide", systemImage: "eye.slash")
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)
                .tint(Brand.mist)
            }
        }
        .padding(18)
        .background(Brand.field)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .strokeBorder(Brand.cardBorder(for: colorScheme), lineWidth: 1)
        }
        .padding(.vertical, 6)
    }

    /// Splits a hyphenated key into rows of four groups. Falls back to one row for any
    /// format that doesn't match, rather than mangling it.
    static func rows(from key: String, groupsPerRow: Int = 4) -> [String] {
        let groups = key.split(separator: "-").map(String.init)
        guard groups.count > groupsPerRow else { return [key] }
        return stride(from: 0, to: groups.count, by: groupsPerRow).map { start in
            groups[start..<min(start + groupsPerRow, groups.count)].joined(separator: "-")
        }
    }
}

// MARK: - shared countdown

/// The signature element, shared by both credential cards: a pit-timer countdown.
///
/// Functional before decorative — an admin mid-transcription needs to know how long is
/// left before the value disappears.
struct CountdownRing: View {
    let secondsRemaining: Int
    let progress: Double

    var body: some View {
        ZStack {
            Circle().stroke(Brand.mist.opacity(0.25), lineWidth: 3)
            Circle()
                .trim(from: 0, to: max(0.001, 1 - progress))
                .stroke(Brand.accentOnField, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(secondsRemaining)")
                .font(Brand.data(15, weight: .semibold))
                .foregroundStyle(.white)
                .monospacedDigit()
        }
        .frame(width: 44, height: 44)
        .animation(.linear(duration: 0.5), value: progress)
        .accessibilityLabel("\(secondsRemaining) seconds until this hides")
    }
}
