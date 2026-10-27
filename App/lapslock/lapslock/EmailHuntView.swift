import SwiftUI
import SecurityKit
import Combine

// Investigate email: the Security module's Email tab, phase 3 step H, spec 3.12.
//
// Content column: the fixed queries as plain rows, and the quarantine said honestly: it is
// not in Microsoft Graph, so the app links to the portal rather than pretending. Detail
// column: one query, its one value if it takes one, the window, Run, and the results. The
// queries are written in SecurityKit, in the open source; there is no box for KQL.
// Results live in memory for the session and are never written to disk.

@MainActor
final class EmailHuntModel: ObservableObject {
    @Published var value = ""
    @Published var window: HuntWindow = .day
    @Published private(set) var running = false
    @Published private(set) var result: HuntResult?
    @Published private(set) var ranValue: String?
    @Published private(set) var ranWindow: HuntWindow = .day
    @Published private(set) var errorMessage: String?
    @Published private(set) var needsConsent = false
    @Published private(set) var copied = false

    let hunt: EmailHunt
    private let provider: any EmailHuntingProviding
    private let requestConsent: (() async -> String?)?

    init(hunt: EmailHunt, provider: any EmailHuntingProviding, requestConsent: (() async -> String?)?) {
        self.hunt = hunt
        self.provider = provider
        self.requestConsent = requestConsent
    }

    /// Nil when the value is fine or not needed; otherwise what to fix.
    var valueProblem: String? {
        guard let parameter = hunt.parameter else { return nil }
        if value.trimmingCharacters(in: .whitespaces).isEmpty { return nil }
        return parameter.validate(value) == nil ? parameter.invalidMessage : nil
    }

    var canRun: Bool {
        guard !running else { return false }
        guard let parameter = hunt.parameter else { return true }
        return parameter.validate(value) != nil
    }

    func run() async {
        guard canRun else { return }
        running = true
        errorMessage = nil
        needsConsent = false
        copied = false
        defer { running = false }
        let checked = hunt.parameter?.validate(value)
        do {
            result = try await provider.run(hunt, value: checked, window: window, allowInteractive: false)
            ranValue = checked
            ranWindow = window
        } catch let error as HuntError {
            result = nil
            if error == .consentRequired, requestConsent != nil { needsConsent = true }
            errorMessage = error.message
        } catch {
            result = nil
            errorMessage = HuntError.unavailable.message
        }
    }

    func grantAndRun() async {
        guard let requestConsent else { return }
        if let problem = await requestConsent() {
            errorMessage = problem
            return
        }
        needsConsent = false
        await run()
    }

    func copyResults() {
        guard let result else { return }
        UIPasteboard.general.string = result.text(for: hunt, value: ranValue, window: ranWindow, at: Date())
        copied = true
    }
}

// MARK: - content column

struct EmailHuntListView: View {
    let isDemo: Bool
    @Binding var selection: String?

    var body: some View {
        List(selection: $selection) {
            Section {
                ForEach(EmailHunt.allCases) { hunt in
                    NavigationLink(value: hunt.rawValue) {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(hunt.title)
                                Text(hunt.detail).font(.caption).foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: hunt.symbol)
                        }
                    }
                }
            } header: {
                Text("Investigate Email")
            } footer: {
                Text("Fixed, read-only advanced hunting queries, written in the app's open source. Needs Microsoft Defender for Office 365, and a role that can run hunting queries.")
            }
            Section {
                Text("Quarantine is not in Microsoft Graph, so this app cannot list or release quarantined messages.")
                    .font(.footnote)
                Link(destination: URL(string: "https://security.microsoft.com/quarantine")!) {
                    Label("Open quarantine in Microsoft Defender", systemImage: "arrow.up.right.square")
                }
            } header: {
                Text("Quarantine")
            }
        }
        .navigationTitle(AppModule.security.title)
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }
}

// MARK: - detail column

struct EmailHuntDetailView: View {
    @StateObject private var model: EmailHuntModel

    init(make: @escaping () -> EmailHuntModel) {
        _model = StateObject(wrappedValue: make())
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if let parameter = model.hunt.parameter {
                        TextField(parameter.prompt, text: $model.value, prompt: Text(parameter.example))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(parameter == .subject ? .default : .emailAddress)
                            .submitLabel(.search)
                            .onSubmit { Task { await model.run() } }
                            .accessibilityLabel(parameter.prompt)
                        if let problem = model.valueProblem {
                            Text(problem).font(.footnote).foregroundStyle(.orange)
                        }
                    }
                    Picker("Window", selection: $model.window) {
                        ForEach(HuntWindow.allCases) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    Button {
                        Task { await model.run() }
                    } label: {
                        HStack {
                            if model.running { ProgressView().padding(.trailing, 6) }
                            Text(model.running ? "Running…" : "Run query")
                        }
                    }
                    .disabled(!model.canRun)
                } footer: {
                    Text(model.hunt.detail)
                }

                if let error = model.errorMessage {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.footnote)
                        if model.needsConsent {
                            Button("Request permission") { Task { await model.grantAndRun() } }
                        }
                    }
                }

                if let result = model.result {
                    Section {
                        if result.rows.isEmpty {
                            Text("Nothing found in the last " + model.ranWindow.label + ".").foregroundStyle(.secondary)
                        }
                        ForEach(result.rows) { row in
                            NavigationLink {
                                HuntRowDetailView(row: row, columns: result.columns)
                            } label: {
                                HuntRowSummary(row: row)
                            }
                        }
                    } header: {
                        Text(result.rows.count == 1 ? "1 Result" : String(result.rows.count) + " Results")
                    } footer: {
                        if result.rows.count >= 200 {
                            Text("Showing the newest 200. Narrow the window or the value for the rest, or run it in Microsoft Defender.")
                        }
                    }
                }
            }
            .navigationTitle(model.hunt.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if model.result != nil {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            model.copyResults()
                        } label: {
                            Label(model.copied ? "Copied" : "Copy results", systemImage: model.copied ? "checkmark" : "doc.on.clipboard")
                                .labelStyle(.titleAndIcon)
                        }
                        .accessibilityHint("The query, the window and every row, as text for a ticket.")
                    }
                }
            }
        }
    }
}

/// The few columns that matter at a glance, whichever query produced the row.
private struct HuntRowSummary: View {
    let row: HuntRow

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(row["Subject"] ?? row["Url"] ?? row["NetworkMessageId"] ?? "Result")
                .lineLimit(2)
            let from = row["SenderFromAddress"]
            let to = row["RecipientEmailAddress"] ?? row["AccountUpn"]
            if from != nil || to != nil {
                Text([from, to].compactMap { $0 }.joined(separator: " to "))
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            let verdict = [row["ThreatTypes"], row["DeliveryAction"] ?? row["ActionType"], row["DeliveryLocation"],
                           row["IsClickedThrough"].map { $0 == "Yes" ? "Clicked through" : "Did not click through" }]
                .compactMap { $0 }
            if !verdict.isEmpty {
                Text(verdict.joined(separator: " · "))
                    .font(.caption)
                    .foregroundStyle(row["ThreatTypes"] != nil ? Color.orange : Color.secondary)
            }
            if let time = row["Timestamp"] {
                Text(HuntRowDetailView.when(time)).font(.caption2).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

struct HuntRowDetailView: View {
    let row: HuntRow
    let columns: [String]

    static func when(_ text: String) -> String {
        let parser = ISO8601DateFormatter()
        parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let date = parser.date(from: text) ?? ISO8601DateFormatter().date(from: text)
        return date.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? text
    }

    var body: some View {
        List {
            ForEach(columns, id: \.self) { column in
                if let value = row[column] {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(column).font(.caption).foregroundStyle(.secondary)
                        Text(column == "Timestamp" ? Self.when(value) : value)
                            .font(column.hasSuffix("Id") ? .footnote.monospaced() : .body)
                            .textSelection(.enabled)
                    }
                    .accessibilityElement(children: .combine)
                }
            }
        }
        .navigationTitle(row["Subject"] ?? "Result")
        .navigationBarTitleDisplayMode(.inline)
    }
}
