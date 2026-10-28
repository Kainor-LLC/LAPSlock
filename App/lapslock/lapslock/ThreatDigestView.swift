import SwiftUI
import ThreatDigestKit

// The Threat Digest. Spec section 3.14. The second tab of the Security module.
//
// Content column: the few cards that matter this week, then the rest collapsed. Detail
// column: one item with why it ranked, what each source said, and a link per source.
// Nothing here is written by the app: every summary is the source's own text. The feeds
// are public and the Kit that fetches them is capped at Foundation, so nothing of the
// tenant can travel with the request.
//
// Free tier: the data is public and this is the module's best hook. Tenant correlation
// is phase 3 and Pro.

@MainActor
@Observable
final class ThreatDigestModel {
    private(set) var snapshot: DigestSnapshot? {
        didSet { rank() }
    }
    private(set) var isLoading = false
    private(set) var errorMessage: String?
    var microsoftOnly: Bool {
        didSet {
            UserDefaults.standard.set(microsoftOnly, forKey: Self.microsoftOnlyKey)
            if microsoftOnly != oldValue { rank() }
        }
    }
    private(set) var cards: [(item: DigestItem, ranking: DigestRanking)] = []
    private(set) var rest: [(item: DigestItem, ranking: DigestRanking)] = []
    var showRest = false

    static let microsoftOnlyKey = "settings.digestMicrosoftOnly"
    /// Before ids were kept: the time of the last look. Read once, for the first visit
    /// after the change, then removed.
    static let lastSeenKey = "settings.digestLastSeen"
    static let seenIdsKey = "settings.digestSeenIds"

    /// What the last look contained, as it was when the digest loaded, so an item stays
    /// "new" for the whole visit and only stops being new on the next one.
    ///
    /// Ids, not a time. The KEV catalog dates an entry by day, which reads as midnight, so
    /// anything CISA added after a look earlier the same day compared as older than the
    /// look and was never marked new.
    private(set) var seenIds: Set<String>?
    private(set) var seenBefore: Date?
    private let provider: any ThreatDigestProviding

    init(provider: any ThreatDigestProviding) {
        self.provider = provider
        self.microsoftOnly = UserDefaults.standard.object(forKey: Self.microsoftOnlyKey) as? Bool ?? true
        self.seenIds = (UserDefaults.standard.array(forKey: Self.seenIdsKey) as? [String]).map(Set.init)
        self.seenBefore = UserDefaults.standard.object(forKey: Self.lastSeenKey) as? Date
    }

    /// Ranks what is loaded under the current filter, into the cards and the rest.
    private func rank() {
        guard let snapshot else {
            cards = []
            rest = []
            return
        }
        let ranker = DigestRanker(now: snapshot.fetchedAt)
        let split = ranker.split(ranker.ranked(Self.filter(snapshot.items, microsoftOnly: microsoftOnly)))
        cards = split.cards
        rest = split.rest
    }

    /// The default filter hides vulnerabilities in other vendors' products. Advisories
    /// always show: a ransomware campaign is everybody's business.
    static func filter(_ items: [DigestItem], microsoftOnly: Bool) -> [DigestItem] {
        guard microsoftOnly else { return items }
        return items.filter { $0.kind == .advisory || $0.isMicrosoft }
    }

    func entry(_ id: String) -> (item: DigestItem, ranking: DigestRanking)? {
        (cards + rest).first { $0.item.id == id }
    }

    func isNew(_ item: DigestItem) -> Bool {
        if let seenIds { return !seenIds.contains(item.id) }
        guard let published = item.published else { return false }
        guard let seenBefore else { return true }
        return published > seenBefore
    }

    var unavailable: [DigestSourceStatus] { snapshot?.unavailable ?? [] }

    /// `refresh` asks every feed again, for pull to refresh; otherwise a digest read in
    /// the last few minutes, by this tenant or another, is reused. With nothing on screen,
    /// the last copy kept on the phone paints first.
    func load(refresh: Bool = false) async {
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }
        if snapshot == nil, let last = await provider.lastDigest() {
            snapshot = last
        }
        do {
            snapshot = try await refresh ? provider.refreshedDigest() : provider.digest()
            if snapshot?.statuses.allSatisfy({ !$0.isAvailable }) == true {
                errorMessage = "None of the feeds answered. Check your connection and try again."
            }
        } catch {
            errorMessage = "Couldn't load the digest. Check your connection and try again."
        }
    }

    /// Called when the reader arrives. The model outlives a switch to another module, so
    /// reading what the last visit saw only when it was built kept everything "new" until
    /// the app was relaunched.
    func beginVisit() {
        seenIds = (UserDefaults.standard.array(forKey: Self.seenIdsKey) as? [String]).map(Set.init)
        seenBefore = UserDefaults.standard.object(forKey: Self.lastSeenKey) as? Date
    }

    /// Called when the reader leaves, so the next visit marks only what came after.
    func markSeen() {
        guard let items = snapshot?.items else { return }
        UserDefaults.standard.set(items.map(\.id), forKey: Self.seenIdsKey)
        UserDefaults.standard.removeObject(forKey: Self.lastSeenKey)
    }
}

// MARK: - content column

struct ThreatDigestListView: View {
    @Bindable var model: ThreatDigestModel
    let isDemo: Bool
    @Binding var selection: String?

    var body: some View {
        Group {
            if model.isLoading && model.snapshot == nil {
                loadingState
            } else if let error = model.errorMessage, model.cards.isEmpty, model.rest.isEmpty {
                errorState(error)
            } else if model.snapshot == nil {
                loadingState
            } else {
                digestList
            }
        }
        .navigationTitle("Security")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .refreshable { await model.load(refresh: true) }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Toggle("Microsoft products only", isOn: $model.microsoftOnly)
                } label: {
                    Image(systemName: model.microsoftOnly
                          ? "line.3.horizontal.decrease.circle"
                          : "line.3.horizontal.decrease.circle.fill")
                }
                .accessibilityLabel("Filter digest")
            }
        }
        .task {
            if model.snapshot == nil { await model.load() }
        }
        .onAppear { model.beginVisit() }
        .onDisappear { model.markSeen() }
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    private var digestList: some View {
        List(selection: $selection) {
            Section {
                if model.cards.isEmpty {
                    Text("Nothing ranks high enough this week. The rest is below.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.cards, id: \.item.id) { entry in
                        NavigationLink(value: entry.item.id) {
                            DigestCardRow(item: entry.item, ranking: entry.ranking, isNew: model.isNew(entry.item))
                        }
                    }
                }
            } header: {
                Text("This Week")
            } footer: {
                Text(cardsFooter)
            }
            Section {
                if model.showRest {
                    ForEach(model.rest, id: \.item.id) { entry in
                        NavigationLink(value: entry.item.id) {
                            DigestCardRow(item: entry.item, ranking: entry.ranking, isNew: model.isNew(entry.item), compact: true)
                        }
                    }
                } else if !model.rest.isEmpty {
                    Button {
                        model.showRest = true
                    } label: {
                        Text("Show \(model.rest.count) more")
                    }
                }
            } header: {
                Text("The Rest")
            }
            if !model.unavailable.isEmpty {
                Section {
                    ForEach(model.unavailable, id: \.source) { status in
                        if case .unavailable(let reason) = status.state {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(status.source.title + " unavailable")
                                    .font(.subheadline.weight(.medium))
                                Text(reason)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    Text("Sources")
                }
            }
        }
    }

    private var cardsFooter: String {
        var parts = ["Ranked on the phone from CISA KEV, CISA advisories and Microsoft MSRC; the words are theirs."]
        parts.append(model.microsoftOnly ? "Microsoft products only; advisories always show." : "Every vendor.")
        if let fetchedAt = model.snapshot?.fetchedAt {
            // The copy kept on the phone can be from another day; say which.
            let day: Date.FormatStyle.DateStyle = Calendar.current.isDateInToday(fetchedAt) ? .omitted : .abbreviated
            parts.append("Fetched " + fetchedAt.formatted(date: day, time: .shortened) + ".")
        }
        return parts.joined(separator: " ")
    }

    private var loadingState: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("Reading the feeds…").font(.subheadline).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorState(_ message: String) -> some View {
        ContentUnavailableView {
            Label("Couldn't load the digest", systemImage: "exclamationmark.triangle")
        } description: {
            Text(message)
        } actions: {
            Button("Try again") { Task { await model.load() } }
        }
    }
}

struct DigestCardRow: View {
    let item: DigestItem
    let ranking: DigestRanking
    let isNew: Bool
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                if isNew {
                    // Primary text on a tinted capsule, like every other pill in the
                    // app: an accent dot vanished on a selected row.
                    Text("New")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Brand.accent.opacity(0.22), in: Capsule())
                        .foregroundStyle(.primary)
                }
                Text(item.title)
                    .font(.body.weight(.medium))
                    .lineLimit(compact ? 2 : 3)
            }
            Text(item.subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            if !compact, !item.summary.isEmpty {
                Text(item.summary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            if !ranking.signals.isEmpty {
                FlowChips(values: ranking.signals.filter { $0 != .new && $0 != .microsoft }.map(\.label))
            }
            HStack(spacing: 6) {
                // An advisory's subtitle already names its source.
                if item.kind == .vulnerability {
                    Text(item.sources.sorted().map(\.title).joined(separator: ", "))
                }
                Spacer(minLength: 0)
                if let published = item.published {
                    Text(relative(published))
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
    }

    private func relative(_ date: Date) -> String {
        RelativeDates.abbreviated(date)
    }
}

// MARK: - detail column

struct DigestDetailView: View {
    let item: DigestItem
    let ranking: DigestRanking
    let isDemo: Bool

    var body: some View {
        List {
            summarySection
            whySection
            if item.sources.contains(.kev) { kevSection }
            if item.sources.contains(.msrc) { msrcSection }
            if item.kind == .advisory, !item.cves.isEmpty { cveSection }
            linksSection
        }
        .navigationTitle(item.kind == .vulnerability ? item.id : "Advisory")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    private var summarySection: some View {
        Section {
            Text(item.title)
                .font(.headline)
                .textSelection(.enabled)
            LabeledContent(item.kind == .vulnerability ? "Product" : "Source", value: item.subtitle)
            if let published = item.published {
                LabeledContent("Published", value: published.formatted(date: .abbreviated, time: .omitted))
            }
            if !item.summary.isEmpty {
                Text(item.summary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        } footer: {
            Text("The description is the source's own text. Open the source for the full page.")
        }
    }

    private var whySection: some View {
        Section("Why It Ranked") {
            if ranking.signals.isEmpty {
                Text("No ranking signals. It is here because a source published it this month.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(ranking.signals, id: \.self) { signal in
                    LabeledContent(signal.label, value: "+\(DigestRanker.weights[signal] ?? 0)")
                }
                LabeledContent("Score", value: String(ranking.score))
            }
        }
    }

    private var kevSection: some View {
        Section("CISA Known Exploited Vulnerabilities") {
            if let added = item.kevDateAdded {
                LabeledContent("Added", value: added.formatted(date: .abbreviated, time: .omitted))
            }
            if let due = item.kevDueDate {
                LabeledContent("Due date", value: due.formatted(date: .abbreviated, time: .omitted))
            }
            LabeledContent("Ransomware use", value: item.kevRansomware ? "Known" : "Unknown")
            if let action = item.kevRequiredAction, !action.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Required action").font(.subheadline.weight(.semibold))
                    Text(action).font(.subheadline).foregroundStyle(.secondary)
                }
                .padding(.vertical, 2)
            }
        }
    }

    private var msrcSection: some View {
        Section("Microsoft Security Update Guide") {
            if let severity = item.msrcSeverity { LabeledContent("Severity", value: severity) }
            if let impact = item.msrcImpact { LabeledContent("Impact", value: impact) }
            if let cvss = item.cvssBase { LabeledContent("CVSS base", value: String(format: "%.1f", cvss)) }
            LabeledContent("Exploited", value: item.msrcExploited ? "Yes" : "No")
            LabeledContent("Publicly disclosed", value: item.msrcPubliclyDisclosed ? "Yes" : "No")
            if let exploitability = item.msrcExploitability { LabeledContent("Exploitability", value: exploitability) }
        }
    }

    private var cveSection: some View {
        Section("CVEs Named") {
            ForEach(item.cves, id: \.self) { cve in
                Link(cve, destination: MSRCPage.guidePage(cve))
            }
        } 
    }

    private var linksSection: some View {
        Section {
            ForEach(item.links) { link in
                Link(destination: link.url) {
                    Label("Open at " + link.source.title, systemImage: "arrow.up.right.square")
                }
            }
        } header: {
            Text("Sources")
        } footer: {
            Text("Each link opens the source's page in the browser. The app fetched a public file and sent nothing else.")
        }
    }
}

#Preview("Digest (demo)") {
    NavigationStack {
        ThreatDigestListView(
            model: ThreatDigestModel(provider: DemoThreatDigestProvider(latency: .milliseconds(1))),
            isDemo: true,
            selection: .constant(nil))
    }
}
