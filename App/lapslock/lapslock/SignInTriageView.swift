import SwiftUI
import Combine
import SignInTriageKit
import DiagnosticsKit

// Sign-in triage. Spec section 3.4. The "Jane can't sign in" screen.
//
// Content column: find the person, then their recent sign-ins with two filters. Detail
// column: one sign-in, with the error explained in plain English, the policy that blocked
// it named, the device, the location and the client, and risk when the tenant has P2.
//
// Pro, by decision D2: the module people open every morning is the one that converts.
// Demo mode shows it in full so App Review can evaluate it.

@MainActor
final class SignInTriageModel: ObservableObject {
    @Published var searchText = ""
    @Published private(set) var users: [DirectoryUser] = []
    @Published private(set) var isSearching = false
    @Published private(set) var searchError: String?

    @Published private(set) var selectedUser: DirectoryUser?
    @Published private(set) var signIns: [SignInEvent] = []
    @Published private(set) var isLoadingSignIns = false
    @Published private(set) var signInsError: String?
    @Published private(set) var lastFailureWasConsent = false

    @Published var failuresOnly = false {
        didSet { if selectedUser != nil { reloadSignIns() } }
    }
    @Published var last24Hours = false {
        didSet { if selectedUser != nil { reloadSignIns() } }
    }

    let glossary = ErrorGlossary.bundled
    private let provider: any SignInTriageProviding
    private var cancellables = Set<AnyCancellable>()
    private var searchTask: Task<Void, Never>?
    private var signInsTask: Task<Void, Never>?

    init(provider: any SignInTriageProviding) {
        self.provider = provider
        $searchText
            .removeDuplicates()
            .debounce(for: .milliseconds(300), scheduler: DispatchQueue.main)
            .sink { [weak self] text in self?.search(text) }
            .store(in: &cancellables)
    }

    func signIn(_ id: String) -> SignInEvent? {
        signIns.first { $0.id == id }
    }

    private func search(_ text: String) {
        searchTask?.cancel()
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 2 else {
            users = []
            searchError = nil
            return
        }
        searchTask = Task { [weak self] in
            guard let self else { return }
            isSearching = true
            defer { isSearching = false }
            do {
                let found = try await provider.searchUsers(prefix: trimmed)
                guard !Task.isCancelled else { return }
                users = found
                searchError = nil
            } catch {
                guard !Task.isCancelled else { return }
                users = []
                searchError = Self.describe(error)
                lastFailureWasConsent = (error as? SignInTriageError) == .consentRequired
            }
        }
    }

    func select(_ user: DirectoryUser) {
        selectedUser = user
        signIns = []
        reloadSignIns()
    }

    func reloadSignIns() {
        guard let user = selectedUser, let upn = user.userPrincipalName else { return }
        signInsTask?.cancel()
        let query = SignInQuery(userPrincipalName: upn, failuresOnly: failuresOnly, last24Hours: last24Hours)
        signInsTask = Task { [weak self] in
            guard let self else { return }
            isLoadingSignIns = true
            signInsError = nil
            lastFailureWasConsent = false
            let started = Date()
            defer { isLoadingSignIns = false }
            do {
                let events = try await provider.signIns(query)
                guard !Task.isCancelled else { return }
                signIns = events
                await Self.record(.success, since: started)
            } catch {
                guard !Task.isCancelled else { return }
                signInsError = Self.describe(error)
                lastFailureWasConsent = (error as? SignInTriageError) == .consentRequired
                await Self.record(Self.outcome(for: error), since: started)
            }
        }
    }

    static func record(_ outcome: DiagnosticOutcome, since started: Date) async {
        await DiagnosticsRecorder.shared.record(
            .graphRead, outcome,
            endpointTemplate: "/v1.0" + SignInTriageService.signInsPath,
            durationMs: Int(Date().timeIntervalSince(started) * 1000))
    }

    static func outcome(for error: Error) -> DiagnosticOutcome {
        guard let e = error as? SignInTriageError else { return .unknown }
        switch e {
        case .consentRequired:    return .consentRequired
        case .notAuthorized:      return .notAuthorized
        case .throttled:          return .throttled
        case .serviceUnavailable: return .serviceUnavailable
        case .transport:          return .transportError
        case .decodeFailure:      return .decodeFailure
        case .cancelled:          return .userCancelled
        }
    }

    static func describe(_ error: Error) -> String {
        guard let e = error as? SignInTriageError else {
            return "Couldn't load sign-ins. Check your connection and try again."
        }
        switch e {
        case .consentRequired:
            return "This organization hasn't granted LAPSlock permission to read the sign-in log yet."
        case .notAuthorized:
            return "Your account can't read the sign-in log, or this tenant has no Entra ID P1. Reports Reader, Security Reader or Global Reader can read it."
        case .throttled(let retryAfter):
            if let retryAfter { return "Microsoft Graph is rate limiting this tenant. Try again in about \(Int(retryAfter)) seconds." }
            return "Microsoft Graph is rate limiting this tenant. Wait a moment and try again."
        case .serviceUnavailable:
            return "Microsoft Entra isn't responding right now. Try again shortly."
        case .transport(let status):
            return "The request failed (HTTP \(status)). Check your connection and try again."
        case .decodeFailure:
            return "Microsoft Graph returned something unexpected. Try again, and let us know if it keeps happening."
        case .cancelled:
            return "Cancelled."
        }
    }
}

// MARK: - content column

struct SignInTriageView: View {
    @ObservedObject var model: SignInTriageModel
    let isDemo: Bool
    @Binding var selection: String?
    var requestConsent: (() async -> String?)? = nil

    @State private var isRequestingConsent = false
    @State private var consentMessage: String?

    var body: some View {
        List(selection: $selection) {
            peopleSection
            if model.selectedUser != nil {
                filterSection
                signInsSection
            }
        }
        .navigationTitle("Sign-in triage")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .searchable(text: $model.searchText, prompt: "Name or sign-in address")
        .refreshable { model.reloadSignIns() }
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    @ViewBuilder
    private var peopleSection: some View {
        Section {
            if model.isSearching {
                HStack(spacing: 8) { ProgressView(); Text("Searching…").font(.footnote).foregroundStyle(.secondary) }
            } else if let error = model.searchError {
                consentAware(error)
            } else if model.users.isEmpty {
                if model.searchText.trimmingCharacters(in: .whitespaces).count >= 2 {
                    Text("Nobody matches \"\(model.searchText)\".").foregroundStyle(.secondary)
                } else if model.selectedUser == nil {
                    Text("Type at least two characters of a name or sign-in address.").foregroundStyle(.secondary)
                }
            } else {
                ForEach(model.users) { user in
                    Button {
                        model.select(user)
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(user.displayName ?? user.userPrincipalName ?? user.id)
                                if let upn = user.userPrincipalName {
                                    Text(upn).font(Brand.data(12)).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            if model.selectedUser?.id == user.id {
                                Image(systemName: "checkmark").foregroundStyle(Brand.accent)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
        } header: {
            Text("People")
        }
    }

    private var filterSection: some View {
        Section {
            Toggle("Failures only", isOn: $model.failuresOnly)
            Toggle("Last 24 hours", isOn: $model.last24Hours)
        } footer: {
            Text("Interactive sign-ins, newest first. Up to 20.")
        }
    }

    @ViewBuilder
    private var signInsSection: some View {
        Section {
            if model.isLoadingSignIns && model.signIns.isEmpty {
                HStack(spacing: 8) { ProgressView(); Text("Reading the sign-in log…").font(.footnote).foregroundStyle(.secondary) }
            } else if let error = model.signInsError {
                consentAware(error)
                Button("Try again") { model.reloadSignIns() }
            } else if model.signIns.isEmpty {
                Text(model.failuresOnly ? "No failed sign-ins in this window." : "No sign-ins in this window.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(model.signIns) { event in
                    NavigationLink(value: event.id) {
                        SignInRow(event: event, glossary: model.glossary)
                    }
                }
            }
        } header: {
            if let user = model.selectedUser {
                Text("Sign-ins for " + (user.displayName ?? user.userPrincipalName ?? ""))
            }
        }
    }

    @ViewBuilder
    private func consentAware(_ message: String) -> some View {
        Label {
            Text(message).font(.footnote)
        } icon: {
            Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
        }
        if model.lastFailureWasConsent, let requestConsent {
            Button {
                Task {
                    isRequestingConsent = true
                    consentMessage = await requestConsent()
                    isRequestingConsent = false
                    if consentMessage == nil { model.reloadSignIns() }
                }
            } label: {
                HStack {
                    if isRequestingConsent { ProgressView().padding(.trailing, 6) }
                    Text(isRequestingConsent ? "Requesting…" : "Request permission")
                }
            }
            .disabled(isRequestingConsent)
            if let consentMessage {
                Text(consentMessage).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}

struct SignInRow: View {
    let event: SignInEvent
    let glossary: ErrorGlossary

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(event.isFailure ? "Failed" : "Success")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background((event.isFailure ? Color.orange : Color.green).opacity(0.16), in: Capsule())
                if event.isFailure {
                    Text(String(event.errorCode)).font(Brand.data(12)).foregroundStyle(.secondary)
                }
                if event.isLegacyClient {
                    Text("Legacy auth")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.red.opacity(0.14), in: Capsule())
                }
                if event.hasRisk {
                    Text("Risk").font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.red.opacity(0.14), in: Capsule())
                }
                Spacer(minLength: 8)
                if let date = event.createdDateTime {
                    Text(Self.relative(date))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .fixedSize()
                }
            }
            Text(event.isFailure
                 ? (glossary.entry(for: event.errorCode)?.title ?? event.status?.failureReason ?? "Failed")
                 : (event.appDisplayName ?? "Signed in"))
                .font(.subheadline.weight(.medium))
            // One string, so it wraps as a sentence rather than as two columns.
            if let caption {
                Text(caption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 3)
    }

    private var caption: String? {
        var parts: [String] = []
        if event.isFailure, let app = event.appDisplayName { parts.append(app) }
        if let blocked = event.blockingPolicies.first?.displayName { parts.append("Blocked by " + blocked) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    /// Minutes and hours, never seconds: a value that ticks on every refresh is noise.
    static func relative(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

// MARK: - detail column

struct SignInDetailView: View {
    let event: SignInEvent
    let glossary: ErrorGlossary

    var body: some View {
        List {
            outcomeSection
            policySection
            deviceSection
            whereSection
            riskSection
            identitySection
        }
        .navigationTitle(event.appDisplayName ?? "Sign-in")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    private var outcomeSection: some View {
        Section {
            if event.isFailure {
                let entry = glossary.entry(for: event.errorCode)
                Text(entry?.title ?? "Failed with code \(event.errorCode)").font(.headline)
                if let entry {
                    Text(entry.meaning)
                    Text(entry.action).foregroundStyle(.secondary)
                } else if let reason = event.status?.failureReason {
                    Text(reason)
                }
                if let details = event.status?.additionalDetails, !details.isEmpty {
                    DataRow(label: "Detail", value: details, monospaced: false)
                }
                DataRow(label: "Code", value: String(event.errorCode))
            } else {
                Label("Signed in", systemImage: "checkmark.circle").foregroundStyle(.green)
            }
            DataRow(label: "When", value: event.createdDateTime?.formatted(date: .abbreviated, time: .shortened), monospaced: false)
            DataRow(label: "App", value: event.appDisplayName, monospaced: false)
            DataRow(label: "Resource", value: event.resourceDisplayName, monospaced: false)
            DataRow(label: "Client", value: event.clientAppUsed.map { event.isLegacyClient ? $0 + " (legacy authentication)" : $0 }, monospaced: false)
        } header: {
            Text("Outcome")
        } footer: {
            if event.isFailure, glossary.entry(for: event.errorCode) == nil {
                Text("This code is not in the glossary yet. Microsoft's own text is shown.")
            }
        }
    }

    @ViewBuilder
    private var policySection: some View {
        Section {
            DataRow(label: "Result", value: SignInVocabulary.conditionalAccessLabel(event.conditionalAccessStatus), monospaced: false)
            let policies = event.appliedConditionalAccessPolicies ?? []
            if policies.isEmpty {
                Text(event.conditionalAccessStatus?.lowercased() == "notapplied"
                     ? "No Conditional Access policy applied to this sign-in."
                     : "Applied policies are not shown. Reading them needs a Conditional Access reader role.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else {
                ForEach(event.decisivePolicies + policies.filter { !$0.applied }) { policy in
                    HStack(alignment: .firstTextBaseline) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(policy.displayName ?? policy.id)
                                .font(policy.failed ? .subheadline.weight(.semibold) : .subheadline)
                            if let controls = policy.enforcedGrantControls, !controls.isEmpty, policy.applied {
                                Text(controls.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        Text(SignInVocabulary.policyResultLabel(policy.result))
                            .font(.caption.weight(.medium))
                            .foregroundStyle(policy.failed ? .orange : .secondary)
                    }
                }
            }
        } header: {
            Text("Conditional Access")
        }
    }

    @ViewBuilder
    private var deviceSection: some View {
        if let device = event.deviceDetail {
            Section("Device") {
                DataRow(label: "Name", value: device.displayName)
                DataRow(label: "OS", value: device.operatingSystem, monospaced: false)
                DataRow(label: "Browser", value: device.browser, monospaced: false)
                DataRow(label: "Join type", value: device.trustType, monospaced: false)
                if let compliant = device.isCompliant {
                    DataRow(label: "Compliant", value: compliant ? "Yes" : "No", monospaced: false)
                }
                if let managed = device.isManaged {
                    DataRow(label: "Managed", value: managed ? "Yes" : "No", monospaced: false)
                }
                DataRow(label: "Device ID", value: device.deviceId)
            }
        }
    }

    private var whereSection: some View {
        Section("Where") {
            DataRow(label: "Location", value: event.location?.label, monospaced: false)
            DataRow(label: "IP address", value: event.ipAddress)
        }
    }

    private var riskSection: some View {
        Section {
            if event.riskIsHidden {
                Text("Risk details need Microsoft Entra ID P2. This tenant's sign-in reports them as hidden.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else {
                DataRow(label: "Sign-in risk", value: SignInVocabulary.riskLabel(event.riskLevelDuringSignIn), monospaced: false)
                DataRow(label: "User risk", value: SignInVocabulary.riskLabel(event.riskLevelAggregated), monospaced: false)
                DataRow(label: "State", value: SignInVocabulary.riskStateLabel(event.riskState), monospaced: false)
            }
        } header: {
            Text("Risk")
        }
    }

    private var identitySection: some View {
        Section("Sign-in") {
            DataRow(label: "User", value: event.userPrincipalName)
            DataRow(label: "Request ID", value: event.id)
            DataRow(label: "Correlation ID", value: event.correlationId)
        }
    }
}

// MARK: - Pro gate

/// What a free install sees in place of the module. Says what it is and where to get it,
/// and nothing else: no countdown, no nag.
struct ProGateView: View {
    let title: String
    let detail: String
    let openSettings: () -> Void

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: "star.circle")
        } description: {
            Text(detail)
        } actions: {
            Button("See plans in Settings") { openSettings() }
        }
    }
}

#Preview("Sign-in triage (demo)") {
    NavigationStack {
        SignInTriageView(
            model: SignInTriageModel(provider: DemoSignInTriageProvider(latency: .milliseconds(1))),
            isDemo: true,
            selection: .constant(nil))
    }
}
