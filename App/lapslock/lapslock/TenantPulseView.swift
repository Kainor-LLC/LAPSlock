import SwiftUI
import TenantPulseKit
import DiagnosticsKit

// Tenant pulse: the morning screen. Spec section 3.6.
//
// Four cards that load in parallel and fail on their own. A card that cannot load says
// what it needs: a permission, a role, or Microsoft, and the other three stay useful. The
// content column is the cards; the detail column is whichever item was tapped.

@MainActor
@Observable
final class TenantPulseModel {

    enum Card<Value: Equatable>: Equatable {
        case idle
        case loading
        case loaded(Value)
        case failed(message: String, needsConsent: Bool)

        var isLoaded: Bool {
            if case .loaded = self { return true }
            return false
        }
    }

    enum CardKind: Hashable { case health, messages, expiring, score }

    /// The expiring items in one bucket, worked out once per load.
    struct ExpiringGroup: Equatable, Identifiable {
        let bucket: ExpiringItem.Bucket
        let items: [ExpiringItem]
        var id: ExpiringItem.Bucket { bucket }
    }

    private(set) var health: Card<ServiceHealthReport> = .idle
    private(set) var messages: Card<[ServiceMessage]> = .idle
    private(set) var expiring: Card<[ExpiringItem]> = .idle {
        didSet { expiringGroups = Self.groups(expiring) }
    }
    /// The expiring card by bucket, rather than filtered again on every redraw.
    private(set) var expiringGroups: [ExpiringGroup] = []
    /// Cards whose last refresh failed while what they showed before stays on screen.
    private(set) var stale: Set<CardKind> = []
    private(set) var score: Card<SecureScoreSummary?> = .idle
    private(set) var isLoading = false
    /// How far back the Secure Score change looks. Seven days or thirty; remembered.
    var scoreWindowDays: Int {
        didSet { UserDefaults.standard.set(scoreWindowDays, forKey: Self.scoreWindowKey) }
    }
    static let scoreWindowKey = "settings.secureScoreWindowDays"
    static let scoreWindows = SecureScoreSummary.windows

    private let provider: any TenantPulseProviding

    init(provider: any TenantPulseProviding) {
        self.provider = provider
        let stored = UserDefaults.standard.integer(forKey: Self.scoreWindowKey)
        self.scoreWindowDays = Self.scoreWindows.contains(stored) ? stored : 7
    }

    var needsConsent: Bool {
        [health.needsConsent, messages.needsConsent, expiring.needsConsent, score.needsConsent].contains(true)
    }

    var hasLoadedAnything: Bool {
        if case .loaded = health { return true }
        if case .loaded = messages { return true }
        if case .loaded = expiring { return true }
        if case .loaded = score { return true }
        return false
    }

    /// A card already on screen stays there while it is read again, and is replaced only
    /// when its new answer arrives: a refresh no longer blanks the cards, or the item open
    /// in the iPad detail.
    func load() async {
        isLoading = true
        defer { isLoading = false }
        if !health.isLoaded { health = .loading }
        if !messages.isLoaded { messages = .loading }
        if !expiring.isLoaded { expiring = .loading }
        if !score.isLoaded { score = .loading }
        let started = Date()
        // Each card fills as its own read finishes, so a slow Expiring card no longer
        // holds back Secure Score.
        await withTaskGroup(of: Void.self) { group in
            group.addTask { @MainActor in
                let new = await self.card { try await self.provider.health() }
                self.health = self.refreshed(self.health, new, .health)
            }
            group.addTask { @MainActor in
                let new = await self.card { try await self.provider.messages() }
                self.messages = self.refreshed(self.messages, new, .messages)
            }
            group.addTask { @MainActor in
                let new = await self.card { ExpiryWindow.relevant(try await self.provider.expiringItems()) }
                self.expiring = self.refreshed(self.expiring, new, .expiring)
            }
            group.addTask { @MainActor in
                let new = await self.card { try await self.provider.secureScore() }
                self.score = self.refreshed(self.score, new, .score)
            }
        }
        await DiagnosticsRecorder.shared.record(
            .graphRead, hasLoadedAnything ? .success : .unknown,
            endpointTemplate: "/v1.0/admin/serviceAnnouncement",
            durationMs: Int(Date().timeIntervalSince(started) * 1000))
    }

    /// A refresh that failed keeps what was on screen, marked as not refreshed.
    private func refreshed<T>(_ old: Card<T>, _ new: Card<T>, _ kind: CardKind) -> Card<T> {
        if case .failed = new, old.isLoaded {
            stale.insert(kind)
            return old
        }
        stale.remove(kind)
        return new
    }

    private static func groups(_ card: Card<[ExpiringItem]>) -> [ExpiringGroup] {
        guard case .loaded(let items) = card else { return [] }
        let now = Date()
        let byBucket = Dictionary(grouping: items) { $0.bucket(now: now) }
        return ExpiringItem.Bucket.allCases.compactMap { bucket in
            byBucket[bucket].map { ExpiringGroup(bucket: bucket, items: $0) }
        }
    }

    private func card<T: Equatable>(_ work: @escaping () async throws -> T) async -> Card<T> {
        do {
            return .loaded(try await work())
        } catch {
            let typed = error as? TenantPulseError
            return .failed(message: Self.describe(error), needsConsent: typed == .consentRequired)
        }
    }

    func issue(_ id: String) -> ServiceIssue? {
        if case .loaded(let report) = health { return report.activeIssues.first { $0.id == id } }
        return nil
    }

    func message(_ id: String) -> ServiceMessage? {
        if case .loaded(let list) = messages { return list.first { $0.id == id } }
        return nil
    }

    func expiringItem(_ id: String) -> ExpiringItem? {
        if case .loaded(let list) = expiring { return list.first { $0.id == id } }
        return nil
    }

    static func describe(_ error: Error) -> String {
        guard let e = error as? TenantPulseError else {
            return "Couldn't load this. Check your connection and try again."
        }
        switch e {
        case .consentRequired:
            return "Needs a permission this organization hasn't granted yet."
        case .notAuthorized:
            return "Your account can't read this. Global Reader covers every card; Service Support Administrator covers health and messages."
        case .throttled(let retryAfter):
            if let retryAfter { return "Rate limited by Microsoft Graph. Try again in about \(Int(retryAfter)) seconds." }
            return "Rate limited by Microsoft Graph. Wait a moment and try again."
        case .serviceUnavailable:
            return "Microsoft isn't responding for this one right now. Try again shortly."
        case .transport(let status):
            return "The request failed (HTTP \(status))."
        case .decodeFailure:
            return "Microsoft Graph returned something unexpected here."
        case .cancelled:
            return "Cancelled."
        }
    }
}

extension TenantPulseModel.Card {
    var needsConsent: Bool {
        if case .failed(_, let needsConsent) = self { return needsConsent }
        return false
    }
}

/// What the detail column shows. A string so the split view can select it.
enum TenantPulseSelection {
    static func issue(_ id: String) -> String { "issue:" + id }
    static func message(_ id: String) -> String { "message:" + id }
    static func expiring(_ id: String) -> String { "expiring:" + id }

    static func split(_ value: String) -> (kind: String, id: String)? {
        guard let colon = value.firstIndex(of: ":") else { return nil }
        return (String(value[..<colon]), String(value[value.index(after: colon)...]))
    }
}

// MARK: - content column

struct TenantPulseView: View {
    @Bindable var model: TenantPulseModel
    let isDemo: Bool
    @Binding var selection: String?
    /// Interactive consent for the module's scopes. Nil in demo.
    var requestConsent: (() async -> String?)? = nil

    @State private var isRequestingConsent = false
    @State private var consentMessage: String?

    var body: some View {
        List(selection: $selection) {
            if model.needsConsent, requestConsent != nil { consentSection }
            healthSection
            messagesSection
            expiringSection
            scoreSection
        }
        .navigationTitle("Tenant Pulse")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .refreshable { await model.load() }
        .task {
            if !model.hasLoadedAnything { await model.load() }
        }
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    private var consentSection: some View {
        Section {
            Text("Some cards need permissions this organization hasn't granted TenantKeep yet.")
                .font(.footnote)
            Button {
                Task {
                    isRequestingConsent = true
                    consentMessage = await requestConsent?()
                    isRequestingConsent = false
                    if consentMessage == nil { await model.load() }
                }
            } label: {
                HStack {
                    if isRequestingConsent { ProgressView().padding(.trailing, 6) }
                    Text(isRequestingConsent ? "Requesting…" : "Request permissions")
                }
            }
            .disabled(isRequestingConsent)
            if let consentMessage {
                Text(consentMessage).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: health

    @ViewBuilder
    private var healthSection: some View {
        Section("Service Health") {
            switch model.health {
            case .idle, .loading:
                loadingRow("Checking service health…")
            case .failed(let message, _):
                failedRow(message)
            case .loaded(let report):
                if report.degraded.isEmpty && report.activeIssues.isEmpty {
                    Label("All \(report.overviews.count) services operational", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                } else {
                    ForEach(report.degraded) { service in
                        HStack {
                            Text(service.service)
                            Spacer()
                            Text(service.statusLabel)
                                .font(.caption.weight(.medium))
                                .foregroundStyle(.orange)
                        }
                    }
                    // Tagged: a selectable List takes the row's identity as the selection,
                    // not the link's value, so without the tag the prefix never arrives.
                    ForEach(report.activeIssues) { issue in
                        NavigationLink(value: TenantPulseSelection.issue(issue.id)) {
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text(issue.isIncident ? "Incident" : "Advisory")
                                        .font(.caption2.weight(.semibold))
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background((issue.isIncident ? Color.orange : Color.secondary).opacity(0.16), in: Capsule())
                                    Text(issue.service ?? "").font(.caption).foregroundStyle(.secondary)
                                }
                                Text(issue.title ?? issue.id).font(.subheadline)
                            }
                        }
                        .tag(TenantPulseSelection.issue(issue.id))
                    }
                    if report.operationalCount > 0 {
                        Text("\(report.operationalCount) other services operational")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
            if model.stale.contains(.health) { staleRow }
        }
    }

    // MARK: Message Center

    @ViewBuilder
    private var messagesSection: some View {
        Section {
            switch model.messages {
            case .idle, .loading:
                loadingRow("Reading Message Center…")
            case .failed(let message, _):
                failedRow(message)
            case .loaded(let messages):
                if messages.isEmpty {
                    Text("Nothing needs action or planning right now.").foregroundStyle(.secondary)
                } else {
                    ForEach(messages.prefix(20)) { message in
                        NavigationLink(value: TenantPulseSelection.message(message.id)) {
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    if let due = message.actionRequiredByDateTime {
                                        Text("Due " + due.formatted(date: .abbreviated, time: .omitted))
                                            .font(.caption2.weight(.semibold))
                                            .padding(.horizontal, 6).padding(.vertical, 2)
                                            .background(Color.orange.opacity(0.16), in: Capsule())
                                    } else {
                                        Text(message.categoryLabel)
                                            .font(.caption2.weight(.semibold))
                                            .padding(.horizontal, 6).padding(.vertical, 2)
                                            .background(Color.secondary.opacity(0.16), in: Capsule())
                                    }
                                    if message.isMajorChange == true {
                                        Text("Major change").font(.caption2).foregroundStyle(.secondary)
                                    }
                                }
                                Text(message.title ?? message.id).font(.subheadline)
                            }
                        }
                        .tag(TenantPulseSelection.message(message.id))
                    }
                }
            }
            if model.stale.contains(.messages) { staleRow }
        } header: {
            Text("Message Center")
        } footer: {
            if case .loaded = model.messages {
                Text("Action required and plan-for-change posts, deadlines first.")
            }
        }
    }

    // MARK: expiring

    @ViewBuilder
    private var expiringSection: some View {
        Section {
            switch model.expiring {
            case .idle, .loading:
                loadingRow("Checking secrets, certificates and tokens…")
            case .failed(let message, _):
                failedRow(message)
            case .loaded(let items):
                if items.isEmpty {
                    Text("Nothing expires in the next 90 days.").foregroundStyle(.secondary)
                } else {
                    ForEach(model.expiringGroups) { group in
                        let bucket = group.bucket
                        Text(bucket.label.uppercased())
                            .font(Brand.fieldLabel)
                            .foregroundStyle(bucket == .expired ? .red : .secondary)
                            .listRowSeparator(.hidden)
                        ForEach(group.items) { item in
                            NavigationLink(value: TenantPulseSelection.expiring(item.id)) {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(item.owner).font(.subheadline.weight(.medium))
                                    HStack(spacing: 6) {
                                        Text(item.kind.label)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                        // A pill rather than red text: red on the selection
                                        // highlight was unreadable.
                                        Text(daysText(item))
                                            .font(.caption2.weight(.semibold))
                                            .padding(.horizontal, 6).padding(.vertical, 2)
                                            .background((bucket == .expired ? Color.red : Color.secondary).opacity(0.16), in: Capsule())
                                    }
                                }
                            }
                            .tag(TenantPulseSelection.expiring(item.id))
                        }
                    }
                }
            }
            if model.stale.contains(.expiring) { staleRow }
        } header: {
            Text("Expiring")
        }
    }

    private func daysText(_ item: ExpiringItem) -> String {
        let days = item.daysLeft()
        if days < 0 { return "expired \(-days) days ago" }
        if days == 0 { return "expires today" }
        if days == 1 { return "expires tomorrow" }
        return "expires in \(days) days"
    }

    // MARK: Secure Score

    @ViewBuilder
    private var scoreSection: some View {
        Section("Secure Score") {
            switch model.score {
            case .idle, .loading:
                loadingRow("Reading Secure Score…")
            case .failed(let message, _):
                failedRow(message)
            case .loaded(let summary):
                if let summary {
                    let days = model.scoreWindowDays
                    scoreRow("Secure Score", current: summary.latest.currentScore, max: summary.latest.maxScore, change: summary.change(overDays: days))
                    if let identity = summary.latest.identityScore {
                        scoreRow("Identity", current: identity, max: nil, change: summary.identityChange(overDays: days))
                    }
                    Picker("Change over", selection: $model.scoreWindowDays) {
                        ForEach(TenantPulseModel.scoreWindows, id: \.self) { window in
                            Text("\(window) days").tag(window)
                        }
                    }
                    .pickerStyle(.segmented)
                    if let date = summary.latest.createdDateTime {
                        let since = summary.comparison(daysBack: days)?.createdDateTime
                        Text("As of " + date.formatted(date: .abbreviated, time: .omitted)
                             + (since.map { ". Change since " + $0.formatted(date: .abbreviated, time: .omitted) + "." } ?? ". No earlier score to compare."))
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                } else {
                    Text("No Secure Score yet for this tenant.").foregroundStyle(.secondary)
                }
            }
            if model.stale.contains(.score) { staleRow }
        }
    }

    private func scoreRow(_ label: String, current: Double?, max: Double?, change: Double?) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
            Spacer()
            if let current {
                Text(max.map { "\(Int(current.rounded())) of \(Int($0.rounded()))" } ?? "\(Int(current.rounded())) points")
                    .font(Brand.data(15, weight: .medium))
            }
            if let change, change != 0 {
                Text((change > 0 ? "+" : "") + "\(Int(change.rounded()))")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(change > 0 ? .green : .orange)
            }
        }
    }

    // MARK: shared rows

    private func loadingRow(_ text: String) -> some View {
        HStack(spacing: 8) {
            ProgressView()
            Text(text).font(.footnote).foregroundStyle(.secondary)
        }
    }

    private var staleRow: some View {
        Label("Couldn't refresh this. Showing what was read before.", systemImage: "clock.arrow.circlepath")
            .font(.footnote)
            .foregroundStyle(.secondary)
    }

    private func failedRow(_ message: String) -> some View {
        Label {
            Text(message).font(.footnote)
        } icon: {
            Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
        }
    }
}

// MARK: - detail column

struct TenantPulseDetailView: View {
    let model: TenantPulseModel
    let selection: String

    var body: some View {
        Group {
            if let parts = TenantPulseSelection.split(selection) {
                switch parts.kind {
                case "issue":
                    if let issue = model.issue(parts.id) { IssueDetail(issue: issue) } else { gone }
                case "message":
                    if let message = model.message(parts.id) { MessageDetail(message: message) } else { gone }
                case "expiring":
                    if let item = model.expiringItem(parts.id) { ExpiringDetail(item: item) } else { gone }
                default:
                    gone
                }
            } else {
                gone
            }
        }
    }

    private var gone: some View {
        ContentUnavailableView("Not loaded", systemImage: "waveform.path.ecg", description: Text("Pull to refresh the list."))
    }
}

private struct IssueDetail: View {
    let issue: ServiceIssue

    var body: some View {
        List {
            Section {
                Text(issue.title ?? issue.id).font(.headline)
                DataRow(label: "Service", value: issue.service, monospaced: false)
                DataRow(label: "Feature", value: issue.feature, monospaced: false)
                DataRow(label: "Type", value: issue.isIncident ? "Incident" : "Advisory", monospaced: false)
                DataRow(label: "Status", value: issue.status.map(TenantPulseVocabulary.healthStatusLabel), monospaced: false)
                DataRow(label: "Started", value: issue.startDateTime?.formatted(date: .abbreviated, time: .shortened), monospaced: false)
                DataRow(label: "Updated", value: issue.lastModifiedDateTime?.formatted(date: .abbreviated, time: .shortened), monospaced: false)
                DataRow(label: "ID", value: issue.id)
            }
            if let impact = issue.impactDescription, !impact.isEmpty {
                Section("Impact") {
                    Text(impact).textSelection(.enabled)
                }
            }
        }
        .navigationTitle(issue.service ?? "Issue")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct MessageDetail: View {
    let message: ServiceMessage

    var body: some View {
        List {
            Section {
                Text(message.title ?? message.id).font(.headline)
                DataRow(label: "Category", value: message.categoryLabel, monospaced: false)
                DataRow(label: "Severity", value: message.severity?.capitalized, monospaced: false)
                if message.isMajorChange == true {
                    DataRow(label: "Major change", value: "Yes", monospaced: false)
                }
                DataRow(label: "Action by", value: message.actionRequiredByDateTime?.formatted(date: .abbreviated, time: .omitted), monospaced: false)
                DataRow(label: "Published", value: message.startDateTime?.formatted(date: .abbreviated, time: .omitted), monospaced: false)
                DataRow(label: "Updated", value: message.lastModifiedDateTime?.formatted(date: .abbreviated, time: .omitted), monospaced: false)
                DataRow(label: "Services", value: message.services?.joined(separator: ", "), monospaced: false)
                DataRow(label: "Tags", value: message.tags?.joined(separator: ", "), monospaced: false)
                DataRow(label: "ID", value: message.id)
            } footer: {
                Text("The full post, with its body and attachments, is in the Microsoft 365 admin center under Message center.")
            }
        }
        .navigationTitle("Message Center")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct ExpiringDetail: View {
    let item: ExpiringItem

    var body: some View {
        List {
            Section {
                Text(item.owner).font(.headline)
                DataRow(label: "Kind", value: item.kind.label, monospaced: false)
                DataRow(label: "Name", value: item.detail, monospaced: false)
                DataRow(label: "Expires", value: item.expiresAt.formatted(date: .long, time: .shortened), monospaced: false)
                DataRow(label: "Status", value: item.bucket().label, monospaced: false)
            } footer: {
                Text(footer)
            }
        }
        .navigationTitle(item.kind.label)
        .navigationBarTitleDisplayMode(.inline)
    }

    private var footer: String {
        switch item.kind {
        case .appSecret, .appCertificate:
            return "Renew it in the Entra admin center under App registrations, then update whatever uses it before the old one lapses."
        case .samlCertificate:
            return "Rotate it in the Entra admin center under Enterprise applications, Single sign-on, and give the other side the new certificate first."
        case .applePushCertificate:
            return "Renew it in the Intune admin center with the same Apple ID that created it. A new Apple ID means re-enrolling every Apple device."
        case .vppToken:
            return "Download a new token from Apple Business Manager or Apple School Manager and upload it in the Intune admin center."
        }
    }
}

#Preview("Tenant pulse (demo)") {
    NavigationStack {
        TenantPulseView(
            model: TenantPulseModel(provider: DemoTenantPulseProvider(latency: .milliseconds(1))),
            isDemo: true,
            selection: .constant(nil))
    }
}
