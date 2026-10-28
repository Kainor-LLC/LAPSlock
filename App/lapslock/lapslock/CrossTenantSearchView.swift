import SwiftUI
import Combine
import AuthKit
import InventoryKit
import SignInTriageKit
import SecurityKit
import SavedSearchKit

// One saved search, run in every organization. Phase 5 step D, MSP only.
//
// The order and the limits are `CrossTenantRunner`'s, in SavedSearchKit, where they are
// tested. This file is what each kind reads, how a failure reads on its row, and the screen.
//
// Each organization gets its own services on a `TenantScopedAuth`: silent tokens for that
// tenant only, the adapter the background alerts run uses. It cannot prompt, and it cannot
// move the operating tenant, so the screens behind this sheet stay in the organization they
// were in. Every read is one a screen already makes; nothing here writes. The results live
// in this sheet's model and are gone when it closes.

/// The reads one organization is searched with.
struct CrossTenantSources: Sendable {
    let inventory: any DeviceInventoryProviding
    let signIns: any SignInTriageProviding
    let security: any SecurityProviding
    let hunting: any EmailHuntingProviding

    /// The live organization's reads, after a silent token proves the tenant needs no
    /// foreground sign-in. The probe asks for the device scope consented at sign-in, as the
    /// alerts run does; a module consent missing later shows on its own row.
    static func live(base: any AuthManaging, tenantId: String) async throws -> CrossTenantSources {
        let scoped = TenantScopedAuth(base: base, tenantId: tenantId)
        do {
            _ = try await scoped.token(scopes: DeviceInventoryService.requiredScopes, allowInteractive: false)
        } catch {
            throw CrossTenantFailure.needsSignIn
        }
        let graph = GraphClient(auth: scoped)
        return CrossTenantSources(
            inventory: DeviceInventoryService(auth: scoped),
            signIns: SignInTriageService(graph: graph),
            security: SecurityService(graph: graph),
            hunting: EmailHuntingService(graph: graph))
    }

    /// Demo mode's sample customers; the second is the quiet one.
    static func demo(quiet: Bool) -> CrossTenantSources {
        CrossTenantSources(
            inventory: DemoInventoryProvider(latency: .milliseconds(150), quiet: quiet),
            signIns: DemoSignInTriageProvider(quiet: quiet),
            security: DemoSecurityProvider(quiet: quiet),
            hunting: DemoEmailHuntingProvider(quiet: quiet))
    }

    /// The saved search, read the way its own screen reads it.
    func hits(for search: SavedSearch) async throws -> TenantHits {
        do {
            switch search.scope {
            case .devices:
                // The whole inventory, a page at a time, then the device list's own match.
                // A large tenant can take a while; the runner's budget bounds it.
                try await inventory.loadFirstPage()
                while try await inventory.loadNextPage() != nil {
                    try Task.checkCancellation()
                }
                let found = DeviceSearch.filter(try await inventory.cachedDevices(), query: search.query)
                return TenantHits(count: found.count, top: found.prefix(TenantHits.topLimit).map(\.deviceName))

            case .people:
                // The same person search, then each match's sign-ins with the saved
                // filters. The first three people only: a short name can match dozens. The
                // count is people with sign-ins that match; each line says how many.
                let failuresOnly = search.options["failuresOnly"] == "true"
                let last24Hours = search.options["last24Hours"] == "true"
                var count = 0
                var top: [String] = []
                for user in try await signIns.searchUsers(prefix: search.query).prefix(3) {
                    guard let upn = user.userPrincipalName else { continue }
                    let events = try await signIns.signIns(
                        SignInQuery(userPrincipalName: upn, failuresOnly: failuresOnly, last24Hours: last24Hours))
                    guard !events.isEmpty else { continue }
                    count += 1
                    let noun = failuresOnly ? "failed sign-in" : "sign-in"
                    top.append((user.displayName ?? upn) + ", " + String(events.count) + " " + noun + (events.count == 1 ? "" : "s"))
                }
                return TenantHits(count: count, top: top)

            case .incidents:
                let filter = SecurityFilter(
                    openOnly: search.options["openOnly"].map { $0 == "true" } ?? true,
                    severity: search.options["severity"].flatMap(SecurityFilter.SeverityFloor.init(rawValue:)) ?? .all)
                let found = await SecurityListModel.search(filter.apply(try await security.incidents()), query: search.query)
                return TenantHits(count: found.count, top: found.prefix(TenantHits.topLimit).map(\.title))

            case .email:
                guard let hunt = search.options["hunt"].flatMap(EmailHunt.init(rawValue:)) else {
                    throw CrossTenantFailure.unavailable("This saved search has no query.")
                }
                let window = search.options["window"].flatMap(Int.init).flatMap(HuntWindow.init(rawValue:)) ?? .day
                let value = hunt.parameter?.validate(search.query)
                let result = try await hunting.run(hunt, value: value, window: window, allowInteractive: false)
                return TenantHits(count: result.rows.count, top: result.rows.compactMap { row in
                    row["Subject"].map { subject in subject + (row["RecipientEmailAddress"].map { ", to " + $0 } ?? "") }
                        ?? row["Url"] ?? row["AccountUpn"]
                })

            case .conditionalAccess:
                throw CrossTenantFailure.unavailable("Conditional Access searches run in one organization at a time.")
            }
        } catch {
            throw Self.classify(error)
        }
    }

    /// Every module's own errors, in the three words a row has.
    static func classify(_ error: Error) -> Error {
        if error is CrossTenantFailure || error is CancellationError { return error }
        if let error = error as? AuthError {
            switch error {
            case .consentRequired, .interactionRequired, .noAccount: return CrossTenantFailure.needsSignIn
            default: return CrossTenantFailure.unavailable("Couldn't get a sign-in for this organization.")
            }
        }
        if let error = error as? InventoryError {
            switch error {
            case .consentRequired: return CrossTenantFailure.needsSignIn
            case .notAuthorized: return CrossTenantFailure.unavailable("Your account can't read devices here.")
            case .throttled: return CrossTenantFailure.throttled
            case .cancelled: return CancellationError()
            default: return CrossTenantFailure.unavailable("Microsoft didn't return the devices.")
            }
        }
        if let error = error as? SignInTriageError {
            switch error {
            case .consentRequired: return CrossTenantFailure.needsSignIn
            case .notAuthorized: return CrossTenantFailure.unavailable("Can't read sign-ins here: no role, or no Entra ID P1.")
            case .throttled: return CrossTenantFailure.throttled
            case .cancelled: return CancellationError()
            default: return CrossTenantFailure.unavailable("Microsoft didn't return the sign-ins.")
            }
        }
        if let error = error as? SecurityError {
            switch error {
            case .consentRequired: return CrossTenantFailure.needsSignIn
            case .notAuthorized: return CrossTenantFailure.unavailable("Your account can't read incidents here.")
            case .throttled: return CrossTenantFailure.throttled
            case .cancelled: return CancellationError()
            default: return CrossTenantFailure.unavailable("Microsoft didn't return the incidents.")
            }
        }
        if let error = error as? HuntError {
            switch error {
            case .consentRequired: return CrossTenantFailure.needsSignIn
            case .notAuthorized: return CrossTenantFailure.unavailable("Advanced hunting isn't available here.")
            case .throttled: return CrossTenantFailure.throttled
            case .invalidValue(let why): return CrossTenantFailure.unavailable(why)
            default: return CrossTenantFailure.unavailable(error.message)
            }
        }
        return CrossTenantFailure.unavailable("Couldn't search this organization.")
    }
}

/// What the module shell needs to offer the run: nil where it is not offered (not MSP, a
/// pinned tenant, not Pro).
struct CrossTenantSearchSetup {
    /// The organizations, the admin's own first, read when the sheet opens.
    let targets: () -> [CrossTenantTarget]
    /// The organization on screen now, so its row can say so.
    let currentTenantId: () -> String?
    let sources: @Sendable (CrossTenantTarget) async throws -> CrossTenantSources
    /// Switches into an organization and puts the search on screen there.
    let open: (SavedSearch, CrossTenantTarget) async -> Void
}

@MainActor
@Observable
final class CrossTenantSearchModel {
    struct Row: Identifiable {
        let target: CrossTenantTarget
        var outcome: CrossTenantOutcome
        var id: String { target.id }
    }

    private(set) var rows: [Row]
    private(set) var stop: CrossTenantStop?
    let search: SavedSearch
    @ObservationIgnored private let sources: @Sendable (CrossTenantTarget) async throws -> CrossTenantSources

    init(search: SavedSearch, targets: [CrossTenantTarget],
         sources: @escaping @Sendable (CrossTenantTarget) async throws -> CrossTenantSources) {
        self.search = search
        self.rows = targets.map { Row(target: $0, outcome: .waiting) }
        self.sources = sources
    }

    var isRunning: Bool { stop == nil }

    /// The run, tied to the sheet's task: closing the sheet cancels it.
    func run() async {
        guard stop == nil else { return }
        let search = self.search
        let sources = self.sources
        stop = await CrossTenantRunner().run(
            rows.map(\.target),
            search: { target in try await sources(target).hits(for: search) },
            report: { [weak self] index, outcome in
                await MainActor.run { self?.rows[index].outcome = outcome }
            })
    }
}

struct CrossTenantSearchView: View {
    @State private var model: CrossTenantSearchModel
    let currentTenantId: String?
    let open: (CrossTenantTarget) -> Void
    @Environment(\.dismiss) private var dismiss

    init(model: @escaping () -> CrossTenantSearchModel, currentTenantId: String?, open: @escaping (CrossTenantTarget) -> Void) {
        // Built on every init of this view, kept on the first; the initializer only maps the
        // targets to rows, so the discarded ones cost nothing.
        _model = State(initialValue: model())
        self.currentTenantId = currentTenantId
        self.open = open
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(model.rows) { row in
                        Button {
                            dismiss()
                            open(row.target)
                        } label: {
                            rowLabel(row)
                        }
                        .buttonStyle(.plain)
                        .disabled(!Self.canOpen(row.outcome))
                    }
                } header: {
                    Text(model.search.name)
                } footer: {
                    Text("Read-only. Each organization is searched in turn with your existing sign-in, and nothing in it is changed. Tap one to switch to it with this search on screen. The results are not kept once this closes.")
                }
                if model.stop == .throttled {
                    Section {
                        Label("Stopped: Microsoft throttled two organizations in a row. Try again in a few minutes.", systemImage: "hourglass")
                            .font(.footnote)
                            .foregroundStyle(.orange)
                    }
                }
            }
            .navigationTitle("Every Organization")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
                if model.isRunning {
                    ToolbarItem(placement: .topBarLeading) { ProgressView() }
                }
            }
            .task { await model.run() }
        }
    }

    /// Waiting and running rows have nothing to open yet; every other row can be opened,
    /// including one that needs a sign-in, since switching there is how to sign in.
    static func canOpen(_ outcome: CrossTenantOutcome) -> Bool {
        switch outcome {
        case .waiting, .running: return false
        default: return true
        }
    }

    private func rowLabel(_ row: CrossTenantSearchModel.Row) -> some View {
        let isCurrent = row.target.tenantId.lowercased() == currentTenantId?.lowercased()
        return HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 3) {
                Text(row.target.label + (isCurrent ? " (on screen)" : ""))
                status(row.outcome)
            }
            Spacer(minLength: 8)
            if case .found(let hits) = row.outcome, hits.count > 0 {
                Text(String(hits.count))
                    .font(.headline.monospacedDigit())
                    .foregroundStyle(Brand.accent)
            }
        }
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private func status(_ outcome: CrossTenantOutcome) -> some View {
        switch outcome {
        case .waiting:
            Text("Waiting").font(.caption).foregroundStyle(.secondary)
        case .running:
            HStack(spacing: 6) {
                ProgressView().controlSize(.mini)
                Text("Searching…")
            }
            .font(.caption).foregroundStyle(.secondary)
        case .found(let hits) where hits.count == 0:
            Text("Nothing found").font(.caption).foregroundStyle(.secondary)
        case .found(let hits):
            VStack(alignment: .leading, spacing: 1) {
                ForEach(Array(hits.top.enumerated()), id: \.offset) { _, hit in
                    Text(hit).lineLimit(1)
                }
                if hits.count > hits.top.count {
                    Text("and " + String(hits.count - hits.top.count) + " more")
                }
            }
            .font(.caption).foregroundStyle(.secondary)
        case .needsSignIn:
            Label("Sign in needed. Switch to it once to sign in or approve.", systemImage: "person.crop.circle.badge.exclamationmark")
                .font(.caption).foregroundStyle(.orange)
        case .throttled:
            Label("Throttled by Microsoft", systemImage: "hourglass")
                .font(.caption).foregroundStyle(.orange)
        case .timedOut:
            Label("Took longer than 30 seconds. Switch to it to search there.", systemImage: "clock")
                .font(.caption).foregroundStyle(.orange)
        case .unavailable(let why):
            Label(why, systemImage: "exclamationmark.triangle")
                .font(.caption).foregroundStyle(.orange)
        case .notRun:
            Text("Not searched").font(.caption).foregroundStyle(.secondary)
        }
    }
}
