import SwiftUI
import InventoryKit
import ConditionalAccessKit
import TenantPulseKit
import SignInTriageKit
import SecurityKit
import ThreatDigestKit
import ManagedConfigKit

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
    case signInTriage
    case tenantPulse
    case conditionalAccess
    case security

    var id: String { rawValue }

    var title: String {
        switch self {
        case .credentials:       return "LAPSlock"
        case .privilegedAccess:  return "Privileged Access"
        case .signInTriage:      return "Sign-in Triage"
        case .tenantPulse:       return "Tenant Pulse"
        case .conditionalAccess: return "Conditional Access"
        case .security:          return "Security"
        }
    }

    var subtitle: String {
        switch self {
        case .credentials:       return "LAPS passwords and BitLocker keys"
        case .privilegedAccess:  return "Activate an eligible role or group"
        case .signInTriage:      return "Why a sign-in failed, and which policy blocked it"
        case .tenantPulse:       return "Health, Message Center, expiries, Secure Score"
        case .conditionalAccess: return "Policies, read-only, and what changed"
        case .security:          return "Incidents, alerts and who was involved"
        }
    }

    var symbol: String {
        switch self {
        case .credentials:       return "key.horizontal"
        case .privilegedAccess:  return "person.badge.key"
        case .signInTriage:      return "person.crop.circle.badge.questionmark"
        case .tenantPulse:       return "waveform.path.ecg"
        case .conditionalAccess: return "checkmark.shield"
        case .security:          return "exclamationmark.shield"
        }
    }

    /// Whether the module works on demo data. A module that cannot says so on screen
    /// rather than vanishing, so a reviewer still sees that it exists.
    var availableInDemo: Bool {
        switch self {
        case .credentials:       return true
        case .privilegedAccess:  return false
        case .signInTriage:      return true
        case .tenantPulse:       return true
        case .conditionalAccess: return true
        case .security:          return true
        }
    }

    /// Pro-only modules, decision D2. Demo mode shows them so App Review can evaluate.
    var requiresPro: Bool {
        switch self {
        case .signInTriage: return true
        case .security:     return true
        default:            return false
        }
    }

    /// The registry flag. The organization's managed app configuration turns modules off
    /// here and nowhere else.
    var isEnabled: Bool { !ManagedConfigStore.read().isDisabled(rawValue) }

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

/// What the Sign-in triage module needs from the root, built once per session.
struct SignInTriageColumns {
    let makeModel: @MainActor () -> SignInTriageModel
    var requestConsent: (() async -> String?)? = nil
}

/// What the Tenant pulse module needs from the root, built once per session.
struct TenantPulseColumns {
    let makeModel: @MainActor () -> TenantPulseModel
    /// Interactive consent for the module's scopes. Nil in demo.
    var requestConsent: (() async -> String?)? = nil
}

/// What the Conditional Access module needs from the root, built once per session.
struct ConditionalAccessColumns {
    let makeListModel: @MainActor () -> ConditionalAccessListModel
    let makeDetailModel: @MainActor (ConditionalAccessPolicy) -> ConditionalAccessDetailModel
    /// Interactive consent for the module's scopes. Nil in demo.
    var requestConsent: (() async -> String?)? = nil
    /// Interactive consent for the audit-log scope. Nil in demo.
    var requestChangesConsent: (() async -> String?)? = nil
}

/// What the Security module needs from the root, built once per session.
struct SecurityColumns {
    let makeModel: @MainActor () -> SecurityListModel
    /// The Threat Digest, the module's second tab. Public feeds, no scope, free tier.
    let makeDigestModel: @MainActor () -> ThreatDigestModel
    /// Interactive consent for the module's scope. Nil in demo.
    var requestConsent: (() async -> String?)? = nil
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
    /// Pro-only modules show their gate when false. Demo passes true.
    let isPro: Bool
    private let credentials: CredentialsColumns
    private let signInTriage: SignInTriageColumns
    private let conditionalAccess: ConditionalAccessColumns
    private let tenantPulse: TenantPulseColumns
    private let security: SecurityColumns
    private let settingsBuilder: () -> SettingsView
    /// The privileged access column. Nil in demo, where there is no account to activate
    /// anything for, and the column says so.
    private let privilegedColumn: (() -> PrivilegedAccessView)?

    @StateObject private var listModel: DeviceListModel
    @StateObject private var policyModel: ConditionalAccessListModel
    @StateObject private var pulseModel: TenantPulseModel
    @StateObject private var triageModel: SignInTriageModel
    @StateObject private var securityModel: SecurityListModel
    @StateObject private var digestModel: ThreatDigestModel
    @State private var selectedModule: AppModule?
    @State private var selectedDeviceId: String?
    @State private var selectedPolicyId: String?
    @State private var selectedPulseItem: String?
    @State private var selectedSignInId: String?
    @State private var selectedIncidentId: String?
    @State private var selectedDigestId: String?
    @State private var securityTab: SecurityTab = .incidents

    enum SecurityTab: String, CaseIterable, Identifiable {
        case incidents
        case digest
        var id: String { rawValue }
        var label: String {
            switch self {
            case .incidents: return "Incidents"
            case .digest:    return "Digest"
            }
        }
    }
    /// All three columns from the first frame. The default is `.automatic`, which on an
    /// iPad in portrait opens with the sidebar and the list both collapsed and only "No
    /// device selected" on screen, two taps from anything useful. Ignored on iPhone, where
    /// the split view is collapsed regardless.
    @State private var columnVisibility: NavigationSplitViewVisibility = .all
    @State private var compactColumn: NavigationSplitViewColumn = .content
    @State private var showingSettings = false
    @State private var searchPresented = false
    /// The fold, on a device that has one. Unknown everywhere else.
    @State private var hinge: HingePosture = .unknown
    /// The open-posture split view's own visibility; kept at all columns.
    @State private var openVisibility: NavigationSplitViewVisibility = .all
    /// How wide the list column is, from the menu, remembered between launches.
    @State private var listWidth: ListWidthPreset = ListWidthPreset.stored
    /// Re-renders the sidebar when the organization pushes a new policy.
    @ObservedObject private var managed = ManagedConfigStore.shared
    @Environment(\.horizontalSizeClass) private var sizeClass

    /// Open across the fold with room for two columns: the layout puts a boundary on the
    /// hinge. In a compact width the shell is a stack and the fold is nobody's problem.
    private var hingeOpen: Bool { hinge.isOpen && sizeClass == .regular }

    init(
        isDemo: Bool,
        isPro: Bool,
        credentials: CredentialsColumns,
        conditionalAccess: ConditionalAccessColumns,
        signInTriage: SignInTriageColumns,
        tenantPulse: TenantPulseColumns,
        security: SecurityColumns,
        settingsBuilder: @escaping () -> SettingsView,
        privilegedColumn: (() -> PrivilegedAccessView)?
    ) {
        self.isDemo = isDemo
        self.isPro = isPro
        self.credentials = credentials
        self.signInTriage = signInTriage
        self.conditionalAccess = conditionalAccess
        self.tenantPulse = tenantPulse
        self.security = security
        self.settingsBuilder = settingsBuilder
        self.privilegedColumn = privilegedColumn
        _listModel = StateObject(wrappedValue: credentials.makeListModel())
        _policyModel = StateObject(wrappedValue: conditionalAccess.makeListModel())
        _pulseModel = StateObject(wrappedValue: tenantPulse.makeModel())
        _triageModel = StateObject(wrappedValue: signInTriage.makeModel())
        _securityModel = StateObject(wrappedValue: security.makeModel())
        _digestModel = StateObject(wrappedValue: security.makeDigestModel())
        _selectedModule = State(initialValue: AppModule.lastUsed)
    }

    var body: some View {
        GeometryReader { geometry in
            let fullWidth = geometry.size.width + geometry.safeAreaInsets.leading + geometry.safeAreaInsets.trailing
            let hingeWidth = HingeLayout.contentWidth(
                fullWidth: fullWidth,
                leadingInset: geometry.safeAreaInsets.leading,
                sidebarShown: false,
                open: true,
                ideal: 380,
                fraction: listWidth.openFraction)
            if hingeOpen {
                // Open across the fold. A two-column split view, which tiles on the
                // phone idiom; the three-column one only ever overlays the list on the
                // detail there, and the one state where the detail could be tapped was
                // the detail alone, with the left half empty. The list takes the left
                // half to the pixel of the hinge, the detail the right. Modules move to
                // a menu in the list's toolbar, and the sidebar toggle is removed so
                // nothing can put the detail across the fold.
                NavigationSplitView(columnVisibility: $openVisibility) {
                    contentColumn
                        .toolbar(removing: .sidebarToggle)
                        .toolbar { ToolbarItem(placement: .topBarLeading) { modulesMenu } }
                        .navigationSplitViewColumnWidth(min: hingeWidth, ideal: hingeWidth, max: hingeWidth)
                } detail: {
                    detailColumn
                }
                .navigationSplitViewStyle(.balanced)
            } else {
                NavigationSplitView(columnVisibility: $columnVisibility, preferredCompactColumn: $compactColumn) {
                    sidebar
                        .navigationSplitViewColumnWidth(min: 220, ideal: 260, max: 320)
                } content: {
                    contentColumn
                        .navigationSplitViewColumnWidth(min: 250, ideal: listWidth.tiledIdeal)
                } detail: {
                    detailColumn
                }
                .navigationSplitViewStyle(.balanced)
            }
        }
        .background { HingeMonitor(posture: $hinge) }
        .onChange(of: hingeOpen) { _, open in
            // Back from the fold, all three columns come back as they were at launch.
            if !open { columnVisibility = .all }
            openVisibility = .all
        }
        .onChange(of: listWidth) { _, preset in preset.store() }
        .onChange(of: managed.config) { _, _ in
            // A module switched off while open closes; the first one still on opens.
            if let module = selectedModule, !module.isEnabled {
                selectedModule = AppModule.enabled.first
            }
        }
        .sheet(isPresented: $showingSettings) { settingsBuilder() }
        .onChange(of: selectedModule) { _, module in
            // A module change closes whatever the previous one had open. On iPhone the
            // sidebar selection clears when the stack pops to it, which is not a change
            // of mind, so nil is not remembered.
            selectedDeviceId = nil
            selectedPolicyId = nil
            selectedPulseItem = nil
            selectedSignInId = nil
            selectedIncidentId = nil
            selectedDigestId = nil
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
        .onReceive(NotificationCenter.default.publisher(for: .openModuleFromAlert)) { note in
            // A tapped notification opens its module in the tenant on screen. (verify) on
            // device whether an MSP wants the tap to switch tenant as well; today it does not.
            if let raw = note.userInfo?["module"] as? String, let module = AppModule(rawValue: raw), module.isEnabled {
                selectedModule = module
            }
        }
        .background { keyboardShortcuts }
    }

    // MARK: - columns

    /// The module list as a menu, for the open posture where there is no sidebar.
    private var modulesMenu: some View {
        Menu {
            Picker("Module", selection: Binding(
                get: { selectedModule ?? .credentials },
                set: { selectedModule = $0 })) {
                ForEach(AppModule.enabled) { module in
                    Label(module.title, systemImage: module.symbol).tag(module)
                }
            }
            Divider()
            listWidthPicker
            Divider()
            Button {
                showingSettings = true
            } label: {
                Label("Settings", systemImage: "gearshape")
            }
        } label: {
            Image(systemName: "square.grid.2x2")
        }
        .accessibilityLabel("Modules")
    }

    /// Compact, narrow, balanced or wide list, as a submenu so the menu that holds it
    /// stays short. Balanced is the hinge on an open device.
    private var listWidthPicker: some View {
        Menu {
            Picker("List Width", selection: $listWidth) {
                ForEach(ListWidthPreset.allCases) { preset in
                    Label(preset.label, systemImage: preset.symbol).tag(preset)
                }
            }
        } label: {
            Label("List Width", systemImage: listWidth.symbol)
        }
    }

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
                // Open high-severity incidents, once the module has loaded this session.
                // Zero hides the badge, so no module pays for a count it does not have.
                .badge(module == .security ? securityModel.openHighCount : 0)
                .accessibilityLabel(module.title)
                .accessibilityHint(module.subtitle)
            }
        }
        .navigationTitle("TenantKeep")
        .toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    listWidthPicker
                    Divider()
                    Button {
                        showingSettings = true
                    } label: {
                        Label("Settings", systemImage: "gearshape")
                    }
                } label: {
                    Image(systemName: "gearshape")
                }
                .accessibilityLabel("Settings and layout")
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
        case .signInTriage?:
            if isPro || isDemo {
                SignInTriageView(
                    model: triageModel,
                    isDemo: isDemo,
                    selection: $selectedSignInId,
                    requestConsent: signInTriage.requestConsent
                )
            } else {
                ProGateView(
                    title: "Sign-in Triage is part of Pro",
                    detail: "Search a person, see their last sign-ins, and read why each one failed with the policy that blocked it named. Pro also removes the reveal limit.",
                    openSettings: { showingSettings = true }
                )
                .navigationTitle(AppModule.signInTriage.title)
            }
        case .tenantPulse?:
            TenantPulseView(
                model: pulseModel,
                isDemo: isDemo,
                selection: $selectedPulseItem,
                requestConsent: tenantPulse.requestConsent
            )
        case .conditionalAccess?:
            ConditionalAccessListView(
                model: policyModel,
                isDemo: isDemo,
                selection: $selectedPolicyId,
                requestConsent: conditionalAccess.requestConsent
            )
        case .security?:
            securityContent
                .safeAreaInset(edge: .top) { securityTabPicker }
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

    /// Incidents (Pro) or the Threat Digest (free), one segmented control above either.
    @ViewBuilder
    private var securityContent: some View {
        switch securityTab {
        case .incidents:
            if isPro || isDemo {
                SecurityListView(
                    model: securityModel,
                    isDemo: isDemo,
                    selection: $selectedIncidentId,
                    requestConsent: security.requestConsent
                )
            } else {
                ProGateView(
                    title: "Incidents are part of Pro",
                    detail: "See the open incidents, every alert's recommended actions, and the users, devices, mailboxes and addresses involved, read-only. The Digest tab is free. Pro also removes the reveal limit.",
                    openSettings: { showingSettings = true }
                )
                .navigationTitle(AppModule.security.title)
            }
        case .digest:
            ThreatDigestListView(
                model: digestModel,
                isDemo: isDemo,
                selection: $selectedDigestId
            )
        }
    }

    private var securityTabPicker: some View {
        Picker("Security view", selection: $securityTab) {
            ForEach(SecurityTab.allCases) { tab in
                Text(tab.label).tag(tab)
            }
        }
        .pickerStyle(.segmented)
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(.bar)
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
        case .signInTriage?:
            if let id = selectedSignInId, let event = triageModel.signIn(id) {
                SignInDetailView(event: event, glossary: triageModel.glossary)
                    .id(id)
            } else {
                ContentUnavailableView {
                    Label("Sign-in Triage", systemImage: "person.crop.circle.badge.questionmark")
                } description: {
                    Text(isPro || isDemo
                         ? "Find a person, then tap a sign-in to see why it went the way it did."
                         : "Available with Pro.")
                }
            }
        case .tenantPulse?:
            if let item = selectedPulseItem {
                TenantPulseDetailView(model: pulseModel, selection: item)
                    .id(item)
            } else {
                ContentUnavailableView {
                    Label("Tenant Pulse", systemImage: "waveform.path.ecg")
                } description: {
                    Text("Tap an incident, a Message Center post or an expiring item for the detail.")
                }
            }
        case .conditionalAccess?:
            if let id = selectedPolicyId, let policy = policyModel.policy(id) {
                ConditionalAccessDetailView(
                    model: conditionalAccess.makeDetailModel(policy),
                    name: { policyModel.name(for: $0) },
                    isDemo: isDemo,
                    requestChangesConsent: conditionalAccess.requestChangesConsent
                )
                .id(id)
            } else {
                ContentUnavailableView {
                    Label("No policy selected", systemImage: "checkmark.shield")
                } description: {
                    Text("Pick a policy from the list. Nothing here can change one.")
                }
            }
        case .security? where securityTab == .digest:
            if let id = selectedDigestId, let entry = digestModel.entry(id) {
                DigestDetailView(item: entry.item, ranking: entry.ranking, isDemo: isDemo)
                    .id(id)
            } else {
                ContentUnavailableView {
                    Label("Threat Digest", systemImage: "newspaper")
                } description: {
                    Text("Pick a card for why it ranked, what each source said, and the links.")
                }
            }
        case .security?:
            if let id = selectedIncidentId, let incident = securityModel.incident(id) {
                SecurityDetailView(
                    incident: incident,
                    isDemo: isDemo,
                    openUser: { upn in
                        // Read-only to read-only, so no gate: the search box fills and
                        // the person's row is one tap away.
                        triageModel.searchText = upn
                        selectedModule = .signInTriage
                    },
                    openDevice: { host in
                        listModel.query = host
                        selectedModule = .credentials
                    },
                    refresh: { await securityModel.refresh(id: id) }
                )
                .id(id)
            } else {
                ContentUnavailableView {
                    Label("Security", systemImage: "exclamationmark.shield")
                } description: {
                    Text(isPro || isDemo
                         ? "Pick an incident for its alerts, the recommended actions and who was involved."
                         : "Available with Pro.")
                }
            }
        case .privilegedAccess?:
            ContentUnavailableView {
                Label("Privileged Access", systemImage: "person.badge.key")
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
