import SwiftUI
import Combine
import SecurityKit
import DiagnosticsKit

// Security, read-only. Spec section 3.12. The security portal's "what just happened" on
// the phone.
//
// Content column: incidents newest first, open only by default, with a severity floor.
// Detail column: the incident, its alerts with their recommended actions, and the
// evidence grouped by kind, each person a tap from their sign-ins and each device a tap
// from the device list. The one way to act on an incident is the portal, and the screen
// says so with a link rather than pretending.
//
// Pro, by decision in the phase 2 plan, like People. Demo shows it in full.

@MainActor
final class SecurityListModel: ObservableObject {
    @Published private(set) var incidents: [SecurityIncident] = []
    @Published var query = ""
    @Published var openOnly: Bool {
        didSet { UserDefaults.standard.set(openOnly, forKey: Self.openOnlyKey) }
    }
    @Published var severity: SecurityFilter.SeverityFloor {
        didSet { UserDefaults.standard.set(severity.rawValue, forKey: Self.severityKey) }
    }
    @Published private(set) var visible: [SecurityIncident] = []
    @Published private(set) var isLoading = false
    @Published private(set) var errorMessage: String?
    @Published private(set) var lastFailureWasConsent = false
    /// Set once the module has loaded at least once this session; the sidebar badge
    /// reads it, so the badge costs no call of its own.
    @Published private(set) var hasLoaded = false

    static let openOnlyKey = "settings.securityOpenOnly"
    static let severityKey = "settings.securitySeverity"

    private let provider: any SecurityProviding
    private var cancellables = Set<AnyCancellable>()

    init(provider: any SecurityProviding) {
        self.provider = provider
        let defaults = UserDefaults.standard
        self.openOnly = defaults.object(forKey: Self.openOnlyKey) as? Bool ?? true
        self.severity = SecurityFilter.SeverityFloor(rawValue: defaults.string(forKey: Self.severityKey) ?? "") ?? .all
        Publishers.CombineLatest4(
            $incidents,
            $query.removeDuplicates().debounce(for: .milliseconds(150), scheduler: DispatchQueue.main),
            $openOnly.removeDuplicates(),
            $severity.removeDuplicates())
            .map { incidents, query, openOnly, severity in
                Self.search(SecurityFilter(openOnly: openOnly, severity: severity).apply(incidents), query: query)
            }
            .assign(to: &$visible)
    }

    var filter: SecurityFilter { SecurityFilter(openOnly: openOnly, severity: severity) }

    /// Open incidents at high severity, for the sidebar badge.
    var openHighCount: Int {
        incidents.filter { $0.isOpen && $0.severity == .high }.count
    }

    static func search(_ incidents: [SecurityIncident], query: String) -> [SecurityIncident] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return incidents }
        return incidents.filter { incident in
            incident.title.localizedCaseInsensitiveContains(trimmed)
                || incident.evidence.contains { $0.label.localizedCaseInsensitiveContains(trimmed) }
                || incident.alerts.contains { $0.displayTitle.localizedCaseInsensitiveContains(trimmed) }
        }
    }

    func incident(_ id: String) -> SecurityIncident? {
        incidents.first { $0.id == id }
    }

    func load() async {
        isLoading = true
        errorMessage = nil
        lastFailureWasConsent = false
        let started = Date()
        defer { isLoading = false }
        do {
            incidents = try await provider.incidents()
            hasLoaded = true
            await Self.record(.success, since: started)
        } catch {
            lastFailureWasConsent = (error as? SecurityError) == .consentRequired
            errorMessage = Self.describe(error)
            await Self.record(Self.outcome(for: error), since: started)
        }
    }

    /// Re-reads one incident and swaps it into the list. Silent on failure: the row is
    /// already on screen.
    func refresh(id: String) async {
        guard let fresh = try? await provider.incident(id: id),
              let index = incidents.firstIndex(where: { $0.id == id }) else { return }
        incidents[index] = fresh
    }

    static func record(_ outcome: DiagnosticOutcome, since started: Date) async {
        await DiagnosticsRecorder.shared.record(
            .graphRead, outcome,
            endpointTemplate: "/v1.0" + SecurityService.incidentsPath,
            durationMs: Int(Date().timeIntervalSince(started) * 1000))
    }

    static func outcome(for error: Error) -> DiagnosticOutcome {
        guard let e = error as? SecurityError else { return .unknown }
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
        guard let e = error as? SecurityError else {
            return "Couldn't load incidents. Check your connection and try again."
        }
        switch e {
        case .consentRequired:
            return "This organization hasn't granted TenantKeep permission to read security incidents yet."
        case .notAuthorized:
            return "Your account can't read security incidents. You'll need a role such as Security Reader, Security Operator or Global Reader, and the tenant needs a Defender plan."
        case .throttled(let retryAfter):
            if let retryAfter {
                return "Microsoft Graph is rate limiting this tenant. Try again in about \(Int(retryAfter)) seconds."
            }
            return "Microsoft Graph is rate limiting this tenant. Try again shortly."
        case .serviceUnavailable:
            return "Microsoft Graph is unavailable right now. Try again shortly."
        case .transport(let status):
            return "Microsoft Graph returned an error (\(status))."
        case .decodeFailure:
            return "Microsoft Graph returned something the app couldn't read."
        case .cancelled:
            return "Cancelled."
        }
    }
}

// MARK: - content column

struct SecurityListView: View {
    @ObservedObject var model: SecurityListModel
    let isDemo: Bool
    @Binding var selection: String?
    /// Requests the module's scope interactively. Nil in demo.
    var requestConsent: (() async -> String?)? = nil

    @State private var isRequestingConsent = false
    @State private var consentMessage: String?

    var body: some View {
        Group {
            if model.isLoading && model.incidents.isEmpty {
                loadingState
            } else if let error = model.errorMessage, model.incidents.isEmpty {
                errorState(error)
            } else if model.incidents.isEmpty {
                emptyState
            } else {
                incidentList
            }
        }
        .navigationTitle("Security")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .searchable(text: $model.query, prompt: "Incident, alert, user or device")
        .refreshable { await model.load() }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Toggle("Open only", isOn: $model.openOnly)
                    Picker("Severity", selection: $model.severity) {
                        ForEach(SecurityFilter.SeverityFloor.allCases) { floor in
                            Text(floor.label).tag(floor)
                        }
                    }
                } label: {
                    Image(systemName: model.openOnly && model.severity == .all
                          ? "line.3.horizontal.decrease.circle"
                          : "line.3.horizontal.decrease.circle.fill")
                }
                .accessibilityLabel("Filter incidents")
            }
        }
        .task {
            if model.incidents.isEmpty { await model.load() }
        }
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    private var incidentList: some View {
        List(selection: $selection) {
            Section {
                ForEach(model.visible) { incident in
                    NavigationLink(value: incident.id) {
                        SecurityIncidentRow(incident: incident)
                    }
                }
            } footer: {
                Text(footer)
            }
            if model.visible.isEmpty {
                Text(model.query.isEmpty
                     ? "No incidents match the filter."
                     : "No incidents match \"\(model.query)\"")
                    .font(.subheadline.weight(.medium))
                    .frame(maxWidth: .infinity)
                    .listRowSeparator(.hidden)
            }
        }
    }

    private var footer: String {
        var parts = ["Read-only."]
        parts.append(model.openOnly ? "Open incidents only;" : "Open and resolved incidents;")
        parts.append(model.severity == .all ? "every severity." : model.severity.label.lowercased() + ".")
        parts.append("Updated in the last \(SecurityService.windowDays) days, newest first.")
        return parts.joined(separator: " ")
    }

    private var loadingState: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("Loading incidents…").font(.subheadline).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No incidents", systemImage: "checkmark.shield")
        } description: {
            Text("Nothing was updated in the last \(SecurityService.windowDays) days, or none your account can read.")
        } actions: {
            Button("Check again") { Task { await model.load() } }
        }
    }

    private func errorState(_ message: String) -> some View {
        ContentUnavailableView {
            Label("Couldn't load incidents", systemImage: "exclamationmark.triangle")
        } description: {
            VStack(spacing: 8) {
                Text(message)
                if let consentMessage {
                    Text(consentMessage).foregroundStyle(.secondary)
                }
            }
        } actions: {
            if model.lastFailureWasConsent, let requestConsent {
                Button {
                    Task {
                        isRequestingConsent = true
                        consentMessage = await requestConsent()
                        isRequestingConsent = false
                        if consentMessage == nil { await model.load() }
                    }
                } label: {
                    HStack {
                        if isRequestingConsent { ProgressView().padding(.trailing, 6) }
                        Text(isRequestingConsent ? "Requesting…" : "Request permission")
                    }
                }
                .disabled(isRequestingConsent)
            }
            Button("Try again") { Task { await model.load() } }
        }
    }
}

struct SecurityIncidentRow: View {
    let incident: SecurityIncident

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(incident.title)
                .font(.body.weight(.medium))
                .lineLimit(2)
            HStack(spacing: 6) {
                SeverityPill(severity: incident.severity)
                Text(incident.status.label)
                    .font(.caption)
                    .foregroundStyle(incident.isOpen ? .primary : .secondary)
                Text("·").foregroundStyle(.secondary)
                Text(alertCount)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
                Text(relative(incident.lastActivity))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            // The summary wraps rather than truncates: "1 user, 3 mailboxes, 1 IP
            // address" cut to "1 user, 3 mailb…" tells the reader nothing.
            if !incident.evidenceSummary.isEmpty {
                Text(incident.evidenceSummary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            if let assignedTo = incident.assignedTo, !assignedTo.isEmpty {
                Text("Assigned to " + assignedTo)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
    }

    private var alertCount: String {
        let n = incident.alerts.count
        return n == 1 ? "1 alert" : "\(n) alerts"
    }

    private func relative(_ date: Date?) -> String {
        guard let date else { return "" }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

/// Severity as text as well as colour, so it survives colour blindness and a selected row.
struct SeverityPill: View {
    let severity: SecuritySeverity

    private var color: Color {
        switch severity {
        case .high:          return .red
        case .medium:        return .orange
        case .low:           return .yellow
        case .informational: return .blue
        case .unknown:       return .secondary
        }
    }

    var body: some View {
        // Primary text on a tinted capsule, not coloured text: on a selected row the
        // background is the accent, and red-on-blue made "High" vanish exactly where
        // somebody had just tapped. The colour stays in the capsule, the word carries
        // the meaning.
        Text(severity.label)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.28), in: Capsule())
            .foregroundStyle(.primary)
    }
}

struct VerdictPill: View {
    let verdict: AlertEvidence.Verdict

    private var color: Color {
        switch verdict {
        case .malicious:      return .red
        case .suspicious:     return .orange
        case .noThreatsFound: return .green
        case .unknown, .other: return .secondary
        }
    }

    var body: some View {
        Text(verdict.label)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.24), in: Capsule())
            .foregroundStyle(.primary)
    }
}

// MARK: - detail column

struct SecurityDetailView: View {
    let incident: SecurityIncident
    let isDemo: Bool
    /// Opens People with this address in the search box.
    let openUser: (String) -> Void
    /// Opens the device list with this host name in the search box.
    let openDevice: (String) -> Void
    var refresh: (() async -> Void)? = nil

    static let quarantineURL = URL(string: "https://security.microsoft.com/quarantine")!

    var body: some View {
        List {
            summarySection
            portalSection
            ForEach(incident.alerts) { alert in
                alertSection(alert)
            }
            evidenceSections
            quarantineSection
        }
        .navigationTitle(incident.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .refreshable { await refresh?() }
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    private var summarySection: some View {
        Section {
            HStack {
                Text("Severity")
                Spacer()
                SeverityPill(severity: incident.severity)
            }
            LabeledContent("Status", value: incident.status.label)
            if let assignedTo = incident.assignedTo, !assignedTo.isEmpty {
                LabeledContent("Assigned to", value: assignedTo)
            }
            if let classification = SecurityVocabulary.verdictLabel(incident.classification) {
                LabeledContent("Classification", value: classification)
            }
            if let determination = SecurityVocabulary.verdictLabel(incident.determination) {
                LabeledContent("Determination", value: determination)
            }
            if let score = incident.priorityScore {
                LabeledContent("Priority", value: "\(score) of 100")
            }
            LabeledContent("Last updated", value: absolute(incident.lastUpdateDateTime))
            if let created = incident.createdDateTime {
                LabeledContent("Created", value: absolute(created))
            }
            if let summary = incident.summary, !summary.isEmpty {
                Text(summary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Incident \(incident.id)")
        }
    }

    @ViewBuilder
    private var portalSection: some View {
        if let raw = incident.incidentWebUrl, let url = URL(string: raw), url.scheme == "https" {
            Section {
                Link(destination: url) {
                    Label("Open in Defender", systemImage: "arrow.up.right.square")
                }
            } footer: {
                Text("Assigning, classifying and resolving happen in the portal. This app reads.")
            }
        }
    }

    private func alertSection(_ alert: SecurityAlert) -> some View {
        Section {
            HStack {
                Text("Severity")
                Spacer()
                SeverityPill(severity: alert.severity)
            }
            LabeledContent("Status", value: alert.status.label)
            if let source = SecurityVocabulary.sourceLabel(alert.serviceSource) {
                LabeledContent("Service", value: source)
            }
            if let detection = SecurityVocabulary.sourceLabel(alert.detectionSource), detection != SecurityVocabulary.sourceLabel(alert.serviceSource) {
                LabeledContent("Detected by", value: detection)
            }
            if let span = activitySpan(alert) {
                LabeledContent("Activity", value: span)
            }
            if !alert.allCategories.isEmpty {
                chipRow("Categories", alert.allCategories.map(SecurityVocabulary.categoryLabel))
            }
            if !alert.mitreTechniques.isEmpty {
                chipRow("MITRE ATT&CK", alert.mitreTechniques)
            }
            if let description = alert.description, !description.isEmpty {
                Text(description)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            if !alert.recommendedActionLines.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Recommended Actions")
                        .font(.subheadline.weight(.semibold))
                    ForEach(Array(alert.recommendedActionLines.enumerated()), id: \.offset) { _, line in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text("•")
                            Text(line)
                        }
                        .font(.subheadline)
                    }
                }
                .padding(.vertical, 2)
            }
            if let raw = alert.alertWebUrl, let url = URL(string: raw), url.scheme == "https" {
                Link(destination: url) {
                    Label("Open alert in Defender", systemImage: "arrow.up.right.square")
                }
            }
        } header: {
            Text(alert.displayTitle)
        }
    }

    @ViewBuilder
    private var evidenceSections: some View {
        let grouped = Dictionary(grouping: incident.evidence, by: \.kindTitle)
        ForEach(AlertEvidence.Kind.displayOrder, id: \.title) { kind in
            if let items = grouped[kind.title], !items.isEmpty {
                Section(kind.title) {
                    ForEach(items) { evidence in
                        evidenceRow(evidence)
                    }
                }
            }
        }
    }

    private func evidenceRow(_ evidence: AlertEvidence) -> some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(evidence.label)
                    .font(.body)
                    .textSelection(.enabled)
                if let detail = evidence.detail, !detail.isEmpty {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(3)
                        .textSelection(.enabled)
                }
                HStack(spacing: 6) {
                    VerdictPill(verdict: evidence.verdict)
                    if !evidence.roles.isEmpty {
                        Text(evidence.roles.map(SecurityVocabulary.categoryLabel).joined(separator: ", "))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if let remediation = evidence.remediationStatus, remediation != "none" {
                        Text(SecurityVocabulary.categoryLabel(remediation))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Spacer(minLength: 0)
            if let upn = evidence.userPrincipalName {
                Button {
                    openUser(upn)
                } label: {
                    Image(systemName: "person.crop.circle.badge.questionmark")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Sign-ins for \(upn)")
            } else if let host = evidence.deviceHostName {
                Button {
                    openDevice(host)
                } label: {
                    Image(systemName: "laptopcomputer.and.arrow.down")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Find \(host) in the device list")
            }
        }
        .padding(.vertical, 2)
    }

    private var quarantineSection: some View {
        Section {
            Link(destination: Self.quarantineURL) {
                Label("Quarantine in the portal", systemImage: "arrow.up.right.square")
            }
        } header: {
            Text("Quarantine")
        } footer: {
            Text("Quarantined mail is not available through Microsoft Graph, so it cannot be listed or released here.")
        }
    }

    private func chipRow(_ title: String, _ values: [String]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.subheadline.weight(.semibold))
            FlowChips(values: values)
        }
        .padding(.vertical, 2)
    }

    private func activitySpan(_ alert: SecurityAlert) -> String? {
        switch (alert.firstActivityDateTime, alert.lastActivityDateTime) {
        case let (first?, last?) where first != last:
            return absolute(first) + " to " + absolute(last)
        case let (first?, _):
            return absolute(first)
        case let (nil, last?):
            return absolute(last)
        default:
            return nil
        }
    }

    private func absolute(_ date: Date?) -> String {
        guard let date else { return "Unknown" }
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}

/// Short values laid out as wrapping chips, each as wide as its text.
struct FlowChips: View {
    let values: [String]

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(Array(values.enumerated()), id: \.offset) { _, value in
                Text(value)
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.secondary.opacity(0.12), in: Capsule())
                    .fixedSize()
            }
        }
    }
}

/// Left-to-right, wrapping to a new line when the next item does not fit. A grid with
/// adaptive columns was tried first and clipped "Credential access" to "Credential ac…"
/// because every column takes the width of the narrowest fit, not of its own chip.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        return place(in: width, subviews: subviews).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let placed = place(in: bounds.width, subviews: subviews)
        for (index, origin) in placed.origins.enumerated() {
            subviews[index].place(
                at: CGPoint(x: bounds.minX + origin.x, y: bounds.minY + origin.y),
                proposal: .unspecified)
        }
    }

    private func place(in width: CGFloat, subviews: Subviews) -> (size: CGSize, origins: [CGPoint]) {
        var origins: [CGPoint] = []
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        var maxX: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0, x + size.width > width {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            origins.append(CGPoint(x: x, y: y))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
            maxX = max(maxX, x - spacing)
        }
        return (CGSize(width: maxX, height: y + rowHeight), origins)
    }
}

#Preview("Security (demo)") {
    NavigationStack {
        SecurityListView(
            model: SecurityListModel(provider: DemoSecurityProvider(latency: .milliseconds(1))),
            isDemo: true,
            selection: .constant(nil))
    }
}
