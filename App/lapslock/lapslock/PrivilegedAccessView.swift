import SwiftUI
import PrivilegedAccessKit

// Just-in-time role activation.
//
// THE MOMENT THIS EXISTS FOR. An administrator taps reveal, gets "your account doesn't hold
// a role that can read local administrator passwords", and is standing at a broken machine.
// Before this screen the only route was: walk away, find a desktop, open the portal,
// activate, walk back. This closes that loop without leaving the bench.
//
// WRITTEN FOR SOMEBODY WHO CANNOT ASK FOR HELP. Like the tenant switcher, the end-to-end
// path depends on tenant policy nobody here can reproduce — approval requirements, MFA
// configuration, which roles are eligible — so failures have to explain themselves on
// screen.
//
// AND ONE RULE ABOVE THE REST: a PENDING approval must never look like success. If the
// tenant requires approval, activation creates a request and grants nothing. An
// administrator told "activated" who walks back to the machine and fails again has been
// actively misled, which is worse than a clear "waiting for approval".

struct PrivilegedAccessView: View {

    /// Device the user was trying to read, for a useful prefilled justification. The
    /// justification lands in the CUSTOMER's own audit log, so naming the device makes their
    /// log more useful, not less private.
    let deviceName: String?
    let loadEligible: () async -> Result<[EligibleAccess], PrivilegedAccessError>
    let activate: (EligibleAccess, String, String?, String) async -> Result<ActivationOutcome, PrivilegedAccessError>
    /// Requests consent for the PIM scopes, returning a message on failure.
    ///
    /// Here rather than only in Settings because **consent is per-organization while the
    /// Settings toggle is per-install.** Somebody who works across tenants has the toggle
    /// on and no consent in the tenant they just signed into, and telling them to go
    /// toggle a switch off and on again is a puzzle, not an instruction.
    let requestConsent: (() async -> String?)?
    /// The tenant's activation rules for one piece of access. Never fails — an unreadable
    /// policy returns `.unknown` and the sheet behaves as it did before policies were read.
    let policy: (EligibleAccess) async -> ActivationPolicy
    /// Re-reads a request PIM already created, for the "Check again" button. Optional so a
    /// preview or a caller that cannot re-check simply does not offer one.
    var recheck: ((String, EligibleAccess) async -> Result<ActivationOutcome, PrivilegedAccessError>)?

    @Environment(\.dismiss) private var dismiss

    @State private var eligible: [EligibleAccess] = []
    @State private var selected: EligibleAccess?
    @State private var justification = ""
    @State private var ticket = ""
    @State private var phase: Phase = .loading
    @State private var failure: PrivilegedFailure?
    @State private var outcome: ActivationOutcome?
    @State private var isRequestingConsent = false
    @State private var duration = ActivationRequest.defaultDuration
    @State private var activePolicy: ActivationPolicy = .unknown
    @State private var isLoadingPolicy = false
    @State private var isChecking = false
    @State private var lastCheckFailed = false

    private enum Phase: Equatable {
        case loading
        case ready
        case activating
        case finished
    }

    var body: some View {
        NavigationStack {
            Form {
                switch phase {
                case .loading:
                    Section { HStack { ProgressView(); Text("Checking what you can activate").padding(.leading, 6) } }
                case .ready, .activating:
                    if let failure { failureSection(failure) }
                    if !eligible.isEmpty {
                        rolesSection
                        justificationSection
                        activateSection
                    }
                case .finished:
                    outcomeSection
                }
            }
            .navigationTitle("Activate access")
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(phase == .finished ? "Done" : "Cancel") { dismiss() }
                }
            }
            .task { await load() }
            .disabled(phase == .activating)
        }
    }

    // MARK: - choosing

    private var rolesSection: some View {
        Section {
            ForEach(eligible) { access in
                Button {
                    selected = access
                    Task { await loadPolicy(for: access) }
                } label: {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(access.label)
                            Text(subtitle(for: access))
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 8)
                        if selected == access {
                            Image(systemName: "checkmark").foregroundStyle(Brand.accent)
                        }
                    }
                }
                .buttonStyle(.plain)
            }
        } header: {
            Text(eligible.count == 1 ? "Eligible access" : "Choose what to activate")
        }
    }

    /// Says what the entry is and, for a role, whether it can actually read a credential.
    ///
    /// Groups are never claimed to grant credential access — a group's id says nothing about
    /// which roles it carries, so promoting one would be a guess presented as fact.
    /// Says what the tenant actually requires, once its policy has been read, rather than
    /// hedging about what tenants generally require.
    private var reasonFooter: String {
        var parts = ["The reason is recorded in your organization's own audit log alongside the activation."]
        if activePolicy.justificationRequired {
            parts.append("Your organization requires one.")
        }
        if activePolicy.ticketRequired {
            parts.append("Your organization also requires a ticket number.")
        }
        if let maximum = activePolicy.maximumDuration, let hours = ActivationPolicy.hours(maximum) {
            parts.append("The longest it permits is \(ActivationPolicy.label(hours: hours)).")
        }
        if activePolicy.authenticationContextClaim != nil {
            parts.append("It also requires you to verify your identity, so expect a sign-in prompt.")
        }
        return parts.joined(separator: " ")
    }

    private func subtitle(for access: EligibleAccess) -> String {
        switch access.kind {
        case .directoryRole:
            return access.canReadLocalCredentials
                ? "Directory role — can read local administrator passwords"
                : "Directory role"
        case .group(_, let accessId):
            // Ownership is not membership with extras. An owner of a role-assignable group
            // can change who is in it, which means granting that group's roles to other
            // people — a bigger thing than reading one password, and worth saying so rather
            // than leaving the difference to one word.
            return accessId == .owner
                ? "Group ownership — also lets you change who else is in this group"
                : "Group membership"
        }
    }

    private var justificationSection: some View {
        Section {
            TextField("Why you need this", text: $justification, axis: .vertical)
                .lineLimit(2...4)
            TextField("Ticket number (optional)", text: $ticket)
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
            Picker("Activate for", selection: $duration) {
                ForEach(activePolicy.offeredDurations, id: \.iso) { option in
                    Text(option.label).tag(option.iso)
                }
            }
            .disabled(isLoadingPolicy)
        } header: {
            Text("Reason")
        } footer: {
            Text(reasonFooter)
        }
    }

    private var activateSection: some View {
        Section {
            Button {
                Task { await performActivation() }
            } label: {
                HStack {
                    if phase == .activating { ProgressView().padding(.trailing, 6) }
                    Text(phase == .activating ? "Activating…" : "Activate")
                }
            }
            .disabled(!canActivate)
        } footer: {
            Text("""
                Microsoft may ask you to sign in again. That is required: it will not grant \
                privileged access unless you have verified your identity in this session.
                """)
        }
    }

    /// Everything the tenant's own policy requires, so Activate is not a button that fails.
    private var canActivate: Bool {
        guard selected != nil, phase != .activating, !isLoadingPolicy else { return false }
        guard !justification.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        if activePolicy.ticketRequired, ticket.trimmingCharacters(in: .whitespaces).isEmpty {
            return false
        }
        return true
    }

    // MARK: - outcome, where over-promising is the danger

    @ViewBuilder
    private var outcomeSection: some View {
        switch outcome {
        case .activated(let until):
            Section {
                Label("Access activated", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(Brand.accent)
                if let until {
                    LabeledContent("Expires", value: SettingsView.relative(until))
                }
            } footer: {
                Text("""
                    Go back and try the reveal again. Microsoft can take a few seconds to \
                    apply a new role, so if it still refuses, wait a moment and retry.
                    """)
            }
        case .provisioning(let requestId, let until):
            // Accepted, nobody to chase. Not dressed as finished either: it is not usable
            // for a few seconds yet, and the reveal will still refuse until it is.
            Section {
                Label("Activating now", systemImage: "arrow.triangle.2.circlepath")
                    .foregroundStyle(Brand.accent)
                if let until {
                    LabeledContent("Expires", value: SettingsView.relative(until))
                }
                checkAgainButton(requestId)
            } header: {
                Text("Accepted — no approval needed")
            } footer: {
                Text("""
                    Microsoft accepted the activation and is applying it now. Nobody has to \
                    approve anything. This usually takes a few seconds — check again, or go \
                    back and try the reveal.
                    """)
            }
        case .pendingApproval(let requestId):
            // Deliberately NOT dressed as success. No checkmark, no accent colour. And
            // reached ONLY for the two statuses that genuinely mean a person must decide —
            // this screen once appeared for ordinary provisioning delays, which sent
            // somebody looking for an approver their tenant does not use.
            Section {
                Label("Waiting for approval", systemImage: "clock")
                    .foregroundStyle(.secondary)
                checkAgainButton(requestId)
            } header: {
                Text("Requested, not yet active")
            } footer: {
                Text("""
                    Your organization requires someone to approve this activation, so nothing \
                    has changed yet. You will not be able to read the password until it is \
                    approved. Approvers are usually notified by email straight away.
                    """)
            }
        case .requested(let requestId, let status):
            // Honest about not knowing. Blaming an approver would be a guess, and so would
            // promising it is on its way.
            Section {
                Label("Requested", systemImage: "clock")
                    .foregroundStyle(.secondary)
                if let detail = Self.statusDetail(status) {
                    Text(detail).font(.footnote).foregroundStyle(.secondary)
                }
                checkAgainButton(requestId)
            } header: {
                Text("Requested, not yet active")
            } footer: {
                Text("""
                    Microsoft created the request but has not reported it as active. If your \
                    organization requires approval, an approver has been notified. If it does \
                    not, this should become active shortly — check again below.
                    """)
            }
        case .refused(let status):
            Section {
                Label("Activation refused", systemImage: "xmark.circle")
                    .foregroundStyle(.secondary)
                if let detail = Self.statusDetail(status) {
                    Text(detail).font(.footnote).foregroundStyle(.secondary)
                }
            } header: {
                Text("Nothing was activated")
            } footer: {
                Text("""
                    Microsoft created the request and then refused it, so nothing is active \
                    and waiting will not help. Usually that means an approver declined it, it \
                    was cancelled, or a policy in your organization blocked it.
                    """)
            }
        case nil:
            if let failure { failureSection(failure) }
        }
    }

    /// Re-reads the request PIM already created, for somebody watching a screen that says
    /// "not yet".
    ///
    /// **A button rather than polling.** The wait is usually seconds, and a timer firing
    /// Graph calls at a screen nobody is looking at spends a customer's throttling budget to
    /// save a tap. This costs one request, only when asked for, and no new permission — it is
    /// a GET on the path the activation was POSTed to.
    ///
    /// Absent when there is no request id to read, which is also how the two settled outcomes
    /// avoid offering it: an active grant has nothing to check and a refusal will never change.
    @ViewBuilder
    private func checkAgainButton(_ requestId: String?) -> some View {
        if let requestId, let recheck, let access = selected {
            Button {
                Task {
                    isChecking = true
                    lastCheckFailed = false
                    switch await recheck(requestId, access) {
                    case .success(let updated):
                        outcome = updated
                    case .failure:
                        // Deliberately NOT the failure section: the activation itself did
                        // not fail, a status read did, and replacing the outcome with an
                        // error would throw away what we already know about the request.
                        lastCheckFailed = true
                    }
                    isChecking = false
                }
            } label: {
                HStack {
                    if isChecking { ProgressView().padding(.trailing, 6) }
                    Text(isChecking ? "Checking…" : "Check again")
                }
            }
            .disabled(isChecking)

            if lastCheckFailed {
                Text("Couldn't reach Microsoft to check. The activation itself is unaffected.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Microsoft's own status word, shown only when there is one.
    ///
    /// Safe to display: it is a fixed Graph enumeration like `PendingScheduleCreation`, not
    /// anything about the tenant, the group or the user. Worth displaying because for a
    /// status this app does not recognise it is the one piece of information that explains
    /// the screen, and reading it off the phone beats collecting it.
    static func statusDetail(_ status: String) -> String? {
        let trimmed = status.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return "Microsoft reported: " + trimmed
    }

    @ViewBuilder
    private func failureSection(_ failure: PrivilegedFailure) -> some View {
        Section {
            Text(failure.title).font(.subheadline.weight(.semibold))
            Text(failure.explanation).font(.footnote).foregroundStyle(.secondary)

            // Recoverable right here rather than by sending the user to Settings. Consent is
            // granted per organization, so an admin who works across tenants will meet this
            // every time they reach a new one — and it is a permission prompt away, not a
            // configuration change.
            if failure.isConsent, let requestConsent {
                Button {
                    Task {
                        isRequestingConsent = true
                        let error = await requestConsent()
                        isRequestingConsent = false
                        if error == nil {
                            await load()
                        } else {
                            self.failure = PrivilegedFailure(consentDenied: error!)
                        }
                    }
                } label: {
                    HStack {
                        if isRequestingConsent { ProgressView().padding(.trailing, 6) }
                        Text(isRequestingConsent ? "Requesting…" : "Request permission")
                    }
                }
                .disabled(isRequestingConsent)
            }
        } header: {
            Text("Couldn't activate")
        }
    }

    // MARK: - actions

    /// Reads the policy for the chosen access and clamps the duration into it.
    ///
    /// Clamping matters as much as the picker: a duration chosen before the policy arrived
    /// could exceed it, and the request would be refused with a 400 that names no reason.
    private func loadPolicy(for access: EligibleAccess) async {
        isLoadingPolicy = true
        let read = await policy(access)
        activePolicy = read
        let allowed = read.offeredDurations.map(\.iso)
        if !allowed.contains(duration) {
            duration = allowed.first ?? ActivationRequest.defaultDuration
        }
        // A tenant that requires a ticket should not offer an Activate button that fails, so
        // the requirement is reflected in the field's own validation below.
        isLoadingPolicy = false
    }

    private func load() async {
        phase = .loading
        failure = nil
        switch await loadEligible() {
        case .success(let access):
            eligible = access
            // One option means no choice to make. Preselect it: an administrator at a
            // broken machine should not have to tap a list of one.
            selected = access.count == 1 ? access.first : nil
            justification = defaultJustification
            phase = .ready
            if let only = selected { await loadPolicy(for: only) }
        case .failure(let error):
            failure = PrivilegedFailure(error)
            phase = .ready
        }
    }

    private var defaultJustification: String {
        if let deviceName, !deviceName.isEmpty {
            return "Retrieving the local administrator password for \(deviceName)"
        }
        return "Retrieving a local administrator password"
    }

    private func performActivation() async {
        guard let selected else { return }
        phase = .activating
        failure = nil

        let trimmedTicket = ticket.trimmingCharacters(in: .whitespaces)
        let result = await activate(
            selected,
            justification.trimmingCharacters(in: .whitespaces),
            trimmedTicket.isEmpty ? nil : trimmedTicket,
            duration)

        switch result {
        case .success(let value):
            outcome = value
            phase = .finished
        case .failure(let error):
            failure = PrivilegedFailure(error)
            phase = .ready
        }
    }
}

/// A failure in the user's terms, with what to do about it.
struct PrivilegedFailure: Equatable {

    /// Appends Microsoft's own error code on its own line.
    ///
    /// A helper rather than an inline escape because writing Swift escape sequences through
    /// a text-processing step is how this file got mangled twice in one session — Python
    /// turns a backslash-n into a real newline and the string literal ends mid-sentence.
    /// Nothing here contains an escape for a tool to eat.
    static func codeSuffix(_ code: String) -> String {
        let blank = String(repeating: "\u{0A}", count: 2)
        return blank + "Microsoft's error code: " + code
    }

    let title: String
    let explanation: String
    /// True when a permission prompt is the fix, so the sheet can offer one inline.
    let isConsent: Bool

    /// Consent was requested and refused. Distinct from "not requested yet": the user has
    /// just been through a prompt, so repeating "request permission" would be a loop.
    init(consentDenied message: String) {
        title = "Permission wasn't granted"
        explanation = message
        isConsent = false
    }

    init(_ error: PrivilegedAccessError) {
        isConsent = (error == .consentRequired)
        switch error {
        case .noEligibleAccess:
            // Not an apology. This usually means their access is permanent rather than
            // PIM-managed, which is a fact about the tenant and not a problem.
            title = "Nothing to activate"
            explanation = """
                Your organization has not made any roles or groups eligible for you to \
                activate. If you should be able to read local administrator passwords, ask \
                an Entra administrator to assign the Cloud Device Administrator role — \
                either permanently, or as eligible so you can activate it here.
                """
        case .consentRequired:
            title = "Permission not granted yet"
            explanation = "LAPSlock hasn't been granted permission in this organization yet. Consent is granted per organization, so signing in somewhere new needs it again. If Microsoft refuses, these are directory permissions and need an Entra administrator to approve them — an Intune Administrator cannot."
        case .alreadyActive:
            title = "Already active"
            explanation = """
                That access is already active, so there is nothing to do. If the reveal is \
                still refused, the role may not be one that can read local administrator \
                passwords — Cloud Device Administrator is the least-privileged role that can.
                """
        case .claimsChallenge:
            // The service retries once. Reaching here means re-authenticating did not
            // satisfy the requirement, which is a tenant policy matter and not something
            // trying again will fix.
            title = "Identity verification didn't satisfy your organization"
            explanation = """
                Microsoft requires you to verify your identity in this session before \
                granting privileged access, and the sign-in did not meet your \
                organization's requirement. This is usually a Conditional Access policy — \
                for example one demanding a compliant device or a stronger authentication \
                method than the one you used.
                """
        case .notAuthorized:
            title = "Microsoft refused the request"
            explanation = "The most likely reason is that these permissions have not been approved for your organization — they need an Entra administrator, and an Intune Administrator cannot grant them. A diagnostics report from Settings carries the Microsoft error code, which says exactly which."
        case .serviceError(let status, let code):
            title = "Microsoft refused the request (HTTP \(status))"
            let codeLine = code.map { PrivilegedFailure.codeSuffix($0) } ?? ""
            if status == 400 {
                // A 400 means the request was rejected, not that the service is down,
                // and the commonest reason by far is an activation longer than the
                // tenant PIM policy allows. Naming that first saves a support round trip.
                explanation = "Nothing was changed. The most likely reason is that the activation length exceeds what your organization allows — try 1 hour. It can also mean the eligibility no longer exists, or that your organization requires a ticket number." + codeLine
            } else {
                explanation = "Nothing was changed. Try again shortly; if it persists, send a diagnostics report from Settings." + codeLine
            }
        case .transport:
            title = "Couldn't reach Microsoft"
            explanation = "Check the connection and try again. Nothing was changed."
        case .decodeFailure:
            title = "Microsoft returned something unexpected"
            explanation = "Nothing was changed. Please report this with a diagnostics report from Settings."
        }
    }
}
