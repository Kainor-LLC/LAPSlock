import SwiftUI
import InventoryKit

// The module registry and the shell that hosts the modules.
//
// One list drives everything that varies per module: the sidebar, the keyboard shortcut,
// what demo mode can show, and later the tier gate, the scopes, the consent prompt and the
// managed-app-config switch. Adding a module means adding a case here and the five things
// the registry points at; it does not mean touching the shell.
//
// The shell is a three-column NavigationSplitView: modules, list, detail. On iPhone it
// collapses to a stack whose root is the module list, and launch restores the last-used
// module, so the admin who opens the app for one thing lands on that thing. A tab bar
// would have been the other answer, but with an iOS 17 floor it cannot become a sidebar on
// iPad, and two shells on the screen that shows passwords is two sets of navigation bugs.
//
// Why selection lives here and not in the list. Favourites, recents and the free-tier
// count used to update from the detail screen's `onDisappear`. In a split view the detail
// column is always present and never disappears, so both broke silently on iPad. Selection
// change is the event that actually means "a device was opened" on both devices, and the
// meter announces its own changes, so the list stays right while the detail stays open.

/// Everything that varies per module, in one place.
enum AppModule: String, CaseIterable, Identifiable {
    case credentials
    case privilegedAccess

    var id: String { rawValue }

    var title: String {
        switch self {
        case .credentials:      return "LAPSlock"
        case .privilegedAccess: return "Privileged access"
        }
    }

    var subtitle: String {
        switch self {
        case .credentials:      return "LAPS passwords and BitLocker keys"
        case .privilegedAccess: return "Activate an eligible role or group"
        }
    }

    var symbol: String {
        switch self {
        case .credentials:      return "key.horizontal"
        case .privilegedAccess: return "person.badge.key"
        }
    }

    /// Whether the module works on demo data. A module that cannot says so on screen
    /// rather than vanishing, so a reviewer still sees that it exists.
    var availableInDemo: Bool {
        switch self {
        case .credentials:      return true
        case .privilegedAccess: return false
        }
    }

    /// The registry flag. Always on today; the managed app config read in phase 3 turns
    /// modules off here and nowhere else.
    var isEnabled: Bool { true }

    static var enabled: [AppModule] { allCases.filter(\.isEnabled) }

    /// The module to open at launch. Plain UserDefaults: which screen somebody looked at
    /// last is not sensitive, and this is read from a view initializer, which is not on
    /// the main actor and so cannot go through `AppSettings`.
    static var lastUsed: AppModule {
        get {
            guard let raw = UserDefaults.standard.string(forKey: lastUsedKey),
                  let module = AppModule(rawValue: raw), module.isEnabled
            else { return .credentials }
            return module
        }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: lastUsedKey) }
    }

    private static let lastUsedKey = "settings.lastModule"
}

extension Notification.Name {
    /// Posted after a reveal is charged, so every screen showing the free-tier count
    /// re-reads it. The meter itself cannot publish: LicensingKit is capped at Foundation
    /// and CryptoKit by the isolation guard, and Combine is neither.
    static let revealMeterDidChange = Notification.Name("lapslock.revealMeterDidChange")
}

/// What the credentials module needs from the root, built once per session.
struct CredentialsColumns {
    /// Deferred so the shell can own the model as state and build it exactly once.
    let makeListModel: @MainActor () -> DeviceListModel
    var tenantSwitcher: (() -> TenantSwitcherView)? = nil
    var onAppearRefresh: (() async -> Void)? = nil
    var tenantBanner: (label: String, isAwayFromHome: Bool)? = nil
    let detailBuilder: (ManagedDeviceSummary) -> DeviceDetailView
}

struct ModuleShell: View {
    let isDemo: Bool
    private let credentials: CredentialsColumns
    private let settingsBuilder: () -> SettingsView
    /// The privileged access column. Nil in demo, where there is no account to activate
    /// anything for, and the column says so.
    private let privilegedColumn: (() -> PrivilegedAccessView)?

    @StateObject private var listModel: DeviceListModel
    @State private var selectedModule: AppModule?
    @State private var selectedDeviceId: String?
    /// All three columns from the first frame. The default is `.automatic`, which on an
    /// iPad in portrait opens with the sidebar and the list both collapsed and only "No
    /// device selected" on screen, two taps from anything useful. Ignored on iPhone, where
    /// the split view is collapsed regardless.
    @State private var columnVisibility: NavigationSplitViewVisibility = .all
    @State private var compactColumn: NavigationSplitViewColumn = .content
    @State private var showingSettings = false
    @State private var searchPresented = false
    @Environment(\.horizontalSizeClass) private var sizeClass

    init(
        isDemo: Bool,
        credentials: CredentialsColumns,
        settingsBuilder: @escaping () -> SettingsView,
        privilegedColumn: (() -> PrivilegedAccessView)?
    ) {
        self.isDemo = isDemo
        self.credentials = credentials
        self.settingsBuilder = settingsBuilder
        self.privilegedColumn = privilegedColumn
        _listModel = StateObject(wrappedValue: credentials.makeListModel())
        _selectedModule = State(initialValue: AppModule.lastUsed)
    }

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility, preferredCompactColumn: $compactColumn) {
            sidebar
                .navigationSplitViewColumnWidth(min: 220, ideal: 260, max: 320)
        } content: {
            contentColumn
                .navigationSplitViewColumnWidth(min: 320, ideal: 380)
        } detail: {
            detailColumn
        }
        .navigationSplitViewStyle(.balanced)
        .sheet(isPresented: $showingSettings) { settingsBuilder() }
        .onChange(of: selectedModule) { _, module in
            // A module change closes whatever the previous one had open. On iPhone the
            // sidebar selection clears when the stack pops to it, which is not a change
            // of mind, so nil is not remembered.
            selectedDeviceId = nil
            if let module { AppModule.lastUsed = module }
        }
        .onChange(of: selectedDeviceId) { _, id in
            // The event that means "a device was opened", on iPhone and iPad alike.
            if let id, let device = device(id) { listModel.recordVisit(device) }
            // And, on the way back on iPhone, the moment a reveal may have been spent.
            listModel.refreshRemaining()
        }
        .onReceive(NotificationCenter.default.publisher(for: .revealMeterDidChange)) { _ in
            listModel.refreshRemaining()
        }
        .background { keyboardShortcuts }
    }

    // MARK: - columns

    private var sidebar: some View {
        List(selection: $selectedModule) {
            ForEach(AppModule.enabled) { module in
                NavigationLink(value: module) {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(module.title)
                            Text(module.subtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: module.symbol)
                    }
                }
                .accessibilityLabel(module.title)
                .accessibilityHint(module.subtitle)
            }
        }
        .navigationTitle("LAPSlock")
        .toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showingSettings = true
                } label: {
                    Image(systemName: "gearshape")
                }
                .accessibilityLabel("Settings")
            }
        }
        .safeAreaInset(edge: .top) {
            if isDemo { DemoBanner() }
        }
    }

    @ViewBuilder
    private var contentColumn: some View {
        switch selectedModule {
        case .credentials?:
            DeviceListView(
                model: listModel,
                isDemo: isDemo,
                selection: $selectedDeviceId,
                searchPresented: $searchPresented,
                tenantSwitcher: credentials.tenantSwitcher,
                onAppearRefresh: credentials.onAppearRefresh,
                tenantBanner: credentials.tenantBanner,
                // In a compact stack the sidebar gear is a swipe away, so the gear stays on
                // the list where it has always been. Regular width shows one gear, not two.
                settingsBuilder: sizeClass == .compact ? settingsBuilder : nil
            )
        case .privilegedAccess?:
            if let privilegedColumn {
                privilegedColumn()
            } else {
                ContentUnavailableView {
                    Label("Needs a signed-in account", systemImage: "person.badge.key")
                } description: {
                    Text("Demo data has no roles to activate. Sign in to use this module.")
                }
                .navigationTitle(AppModule.privilegedAccess.title)
                .safeAreaInset(edge: .top) { DemoBanner() }
            }
        case nil:
            ContentUnavailableView("Choose a module", systemImage: "square.grid.2x2")
        }
    }

    @ViewBuilder
    private var detailColumn: some View {
        switch selectedModule {
        case .credentials?:
            if let id = selectedDeviceId, let device = device(id) {
                // Keyed by id so choosing another device replaces the screen outright, which
                // is what makes the previous one's onDisappear fire and its reveal wipe.
                credentials.detailBuilder(device)
                    .id(id)
            } else {
                ContentUnavailableView {
                    Label("No device selected", systemImage: "laptopcomputer")
                } description: {
                    Text("Pick a device from the list, or search for one.")
                }
            }
        case .privilegedAccess?:
            ContentUnavailableView {
                Label("Privileged access", systemImage: "person.badge.key")
            } description: {
                Text("Activate an eligible Entra role or PIM group from the list. Your organization's policy applies exactly as it would in the portal: justification, ticket, approval and identity verification.")
            }
        case nil:
            Color.clear
        }
    }

    private func device(_ id: String) -> ManagedDeviceSummary? {
        listModel.devices.first { $0.id == id }
    }

    // MARK: - keyboard

    /// Cmd-K searches, Cmd-1 onward switches modules. Invisible buttons rather than scene
    /// commands, because these act on state that lives in this view.
    private var keyboardShortcuts: some View {
        Group {
            Button("Search devices") {
                selectedModule = .credentials
                searchPresented = true
            }
            .keyboardShortcut("k", modifiers: .command)

            ForEach(Array(AppModule.enabled.prefix(9).enumerated()), id: \.element) { index, module in
                Button(module.title) { selectedModule = module }
                    .keyboardShortcut(KeyEquivalent(Character(String(index + 1))), modifiers: .command)
            }
        }
        .opacity(0)
        .accessibilityHidden(true)
        .allowsHitTesting(false)
    }
}
