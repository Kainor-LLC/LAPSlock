import SwiftUI
import InventoryKit
import ConditionalAccessKit
import TenantPulseKit
import SignInTriageKit
import SecurityKit
import ThreatDigestKit
import ManagedConfigKit
import UserActionsKit
import DeviceActionsKit
import GroupWritesKit
import ApprovalsKit
import SavedSearchKit

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
    case people
    case tenantPulse
    case conditionalAccess
    case security

    var id: String { rawValue }

    var title: String {
        switch self {
        case .credentials:       return "LAPSlock"
        case .privilegedAccess:  return "Privileged Access"
        case .people:            return "People"
        case .tenantPulse:       return "Tenant Pulse"
        case .conditionalAccess: return "Conditional Access"
        case .security:          return "Security"
        }
    }

    var subtitle: String {
        switch self {
        case .credentials:       return "Every device, with LAPS passwords, BitLocker keys and actions"
        case .privilegedAccess:  return "Activate an eligible role or group"
        case .people:            return "Sign-ins, account state, actions and leavers"
        case .tenantPulse:       return "Health, Message Center, expiries, Secure Score"
        case .conditionalAccess: return "Policies, read-only, and what changed"
        case .security:          return "Incidents, alerts and who was involved"
        }
    }

    var symbol: String {
        switch self {
        case .credentials:       return "key.horizontal"
        case .privilegedAccess:  return "person.badge.key"
        case .people:            return "person.2"
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
        case .privilegedAccess:  return true
        case .people:            return true
        case .tenantPulse:       return true
        case .conditionalAccess: return true
        case .security:          return true
        }
    }

    /// Pro-only modules, decision D2. Demo mode shows them so App Review can evaluate.
    var requiresPro: Bool {
        switch self {
        case .people: return true
        case .security:     return true
        default:            return false
        }
    }

    /// The registry flag. The organization's managed app configuration turns modules off
    /// here and nowhere else.
    var isEnabled: Bool { !ManagedConfigStore.shared.config.isDisabled(rawValue) }

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

/// What the People module needs from the root, built once per session.
struct PeopleColumns {
    let makeModel: @MainActor () -> SignInTriageModel
    /// The directory the module column lists.
    let makeDirectory: @MainActor () -> PeopleDirectoryModel
    var requestConsent: (() async -> String?)? = nil
    /// User actions for the selected person; nil when they are off.
    var makeUserActions: ((UserActionTarget) -> UserActionsModel)? = nil
    /// Device actions for the leaver checklist; nil when they are off.
    var makeDeviceActions: ((DeviceActionTarget) -> DeviceActionsModel)? = nil
    /// The selected person's state at a glance; nil when user actions are off.
    var snapshot: ((UserActionTarget) async -> PersonSnapshot)? = nil
    /// The selected person's groups; nil when group changes are off.
    var makeGroups: ((GroupMember) -> PersonGroupsModel)? = nil
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
    /// The Email tab's hunting queries.
    var emailHunting: any EmailHuntingProviding = DemoEmailHuntingProvider()
    /// Consent for the hunting scope, asked the first time a query runs. Nil in demo.
    var requestHuntingConsent: (() async -> String?)? = nil
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
    private let signInTriage: PeopleColumns
    private let conditionalAccess: ConditionalAccessColumns
    private let tenantPulse: TenantPulseColumns
    private let security: SecurityColumns
    private let settingsBuilder: () -> SettingsView
    /// The privileged access column. Nil in demo, where there is no account to activate
    /// anything for, and the column says so.
    private let privilegedColumn: (() -> PrivilegedAccessView)?
    @StateModel private var approvalsModel: ApprovalsModel
    /// The Activate column's form, kept across module and tab switches.
    @StateModel private var activateForm = ActivateFormState()
    /// A tapped alert to open, set by the root once it has switched to the alert's
    /// organization. Cleared here when opened.
    @Binding private var openRoute: AlertRoute?
    /// Saved searches, or nil where they are not offered (not Pro, outside demo).
    private let savedSearches: SavedSearchLibrary?
    /// A saved email query to fill in when its detail opens.
    @State private var huntPrefill: SavedSearch?
    /// The run across organizations, or nil where it is not offered (not MSP).
    private let crossTenant: CrossTenantSearchSetup?
    /// The saved search being run in every organization, while its sheet is open.
    @State private var runningEverywhere: SavedSearch?
    /// A saved search to put on screen, set by the root after a row in that sheet switched
    /// organization. Cleared here when applied.
    @Binding private var pendingSearch: SavedSearch?
    @State private var showingTenantSwitcher = false
    @State private var privilegedTab: PrivilegedTab = .activate
    @State private var selectedApprovalId: String?

    enum PrivilegedTab: String, CaseIterable, Identifiable {
        case activate, approvals
        var id: String { rawValue }
        var label: String { self == .activate ? "Activate" : "Approvals" }
    }

    @StateModel private var listModel: DeviceListModel
    @StateModel private var policyModel: ConditionalAccessListModel
    @StateModel private var pulseModel: TenantPulseModel
    @StateModel private var triageModel: SignInTriageModel
    @StateModel private var directoryModel: PeopleDirectoryModel
    @StateModel private var securityModel: SecurityListModel
    @StateModel private var digestModel: ThreatDigestModel
    @State private var selectedModule: AppModule?
    @State private var selectedDeviceId: String?
    /// The device as it was when opened. A pull to refresh starts the list again from its
    /// first page, so the open device can be missing from it for a while; without this the
    /// detail emptied, which wiped a revealed password and cancelled a pending action's
    /// undo window, then came back as a fresh screen once the fill reached it.
    @State private var openedDevice: ManagedDeviceSummary?
    @State private var selectedPolicyId: String?
    @State private var selectedPulseItem: String?
    /// The person whose page is open, by id.
    @State private var selectedPersonId: String?
    @State private var selectedIncidentId: String?
    @State private var selectedDigestId: String?
    @State private var selectedHuntId: String?
    @State private var securityTab: SecurityTab = .incidents

    enum SecurityTab: String, CaseIterable, Identifiable {
        case incidents
        case email
        case digest
        var id: String { rawValue }
        var label: String {
            switch self {
            case .incidents: return "Incidents"
            case .email:     return "Email"
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
    private let managed = ManagedConfigStore.shared
    @Environment(\.horizontalSizeClass) private var sizeClass

    /// Open across the fold with room for two columns: the layout puts a boundary on the
    /// hinge. In a compact width the shell is a stack and the fold is nobody's problem.
    private var hingeOpen: Bool { hinge.isOpen && sizeClass == .regular }

    init(
        isDemo: Bool,
        isPro: Bool,
        credentials: CredentialsColumns,
        conditionalAccess: ConditionalAccessColumns,
        signInTriage: PeopleColumns,
        tenantPulse: TenantPulseColumns,
        security: SecurityColumns,
        settingsBuilder: @escaping () -> SettingsView,
        privilegedColumn: (() -> PrivilegedAccessView)?,
        makeApprovals: @escaping @MainActor () -> ApprovalsModel,
        openRoute: Binding<AlertRoute?>,
        savedSearches: SavedSearchLibrary?,
        crossTenant: CrossTenantSearchSetup? = nil,
        pendingSearch: Binding<SavedSearch?> = .constant(nil)
    ) {
        _openRoute = openRoute
        self.savedSearches = savedSearches
        self.crossTenant = crossTenant
        _pendingSearch = pendingSearch
        self.isDemo = isDemo
        self.isPro = isPro
        self.credentials = credentials
        self.signInTriage = signInTriage
        self.conditionalAccess = conditionalAccess
        self.tenantPulse = tenantPulse
        self.security = security
        self.settingsBuilder = settingsBuilder
        self.privilegedColumn = privilegedColumn
        _listModel = StateModel(wrappedValue: credentials.makeListModel())
        _policyModel = StateModel(wrappedValue: conditionalAccess.makeListModel())
        _pulseModel = StateModel(wrappedValue: tenantPulse.makeModel())
        _triageModel = StateModel(wrappedValue: signInTriage.makeModel())
        _directoryModel = StateModel(wrappedValue: signInTriage.makeDirectory())
        _securityModel = StateModel(wrappedValue: security.makeModel())
        _digestModel = StateModel(wrappedValue: security.makeDigestModel())
        _approvalsModel = StateModel(wrappedValue: makeApprovals())
        _selectedModule = State(initialValue: AppModule.lastUsed)
    }

    var body: some View {
        let _ = PerfProbe.body("ModuleShell")
        // The geometry is read only open across the fold, where the list's width is the
        // hinge's. Around the whole shell it re-ran everything on every size change: each
        // frame of a Stage Manager resize, and rotation (OPTIMIZATION-PLAN.md, step H).
        Group {
            if hingeOpen {
                GeometryReader { geometry in
                    let fullWidth = geometry.size.width + geometry.safeAreaInsets.leading + geometry.safeAreaInsets.trailing
                    let hingeWidth = HingeLayout.contentWidth(
                        fullWidth: fullWidth,
                        leadingInset: geometry.safeAreaInsets.leading,
                        sidebarShown: false,
                        open: true,
                        ideal: 380,
                        fraction: listWidth.openFraction)
                    // Open across the fold. A two-column split view, which tiles on the
                    // phone idiom; the three-column one only ever overlays the list on the
                    // detail there, and the one state where the detail could be tapped was
                    // the detail alone, with the left half empty. The list takes the left
                    // half to the pixel of the hinge, the detail the right. Modules move to
                    // a menu in the list's toolbar, and the sidebar toggle is removed so
                    // nothing can put the detail across the fold.
                    NavigationSplitView(columnVisibility: $openVisibility) {
                        moduleColumn
                            .toolbar(removing: .sidebarToggle)
                            .toolbar { ToolbarItem(placement: .topBarLeading) { modulesMenu } }
                            .navigationSplitViewColumnWidth(min: hingeWidth, ideal: hingeWidth, max: hingeWidth)
                    } detail: {
                        detailColumn
                    }
                    .navigationSplitViewStyle(.balanced)
                }
            } else {
                NavigationSplitView(columnVisibility: $columnVisibility, preferredCompactColumn: $compactColumn) {
                    sidebar
                        .navigationSplitViewColumnWidth(min: 220, ideal: 260, max: 320)
                } content: {
                    moduleColumn
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
        .sheet(isPresented: $showingTenantSwitcher) {
            if let tenantSwitcher = credentials.tenantSwitcher { tenantSwitcher() }
        }
        .task { await credentials.onAppearRefresh?() }
        .onChange(of: selectedModule) { _, module in
            // A module change closes whatever the previous one had open. On iPhone the
            // sidebar selection clears when the stack pops to it, which is not a change
            // of mind, so nil is not remembered.
            selectedDeviceId = nil
            selectedPolicyId = nil
            selectedPulseItem = nil
            // Not when People is what opens: an alert or an incident opening a person sets
            // the module and the person together.
            if module != .people { selectedPersonId = nil }
            selectedIncidentId = nil
            selectedApprovalId = nil
            selectedDigestId = nil
            selectedHuntId = nil
            if let module { AppModule.lastUsed = module }
        }
        .onChange(of: selectedDeviceId) { _, id in
            // The event that means "a device was opened", on iPhone and iPad alike.
            if let id, let device = device(id) {
                openedDevice = device
                listModel.recordVisit(device)
            }
            // And, on the way back on iPhone, the moment a reveal may have been spent.
            listModel.refreshRemaining()
        }
        .onReceive(NotificationCenter.default.publisher(for: .revealMeterDidChange)) { _ in
            listModel.refreshRemaining()
        }
        // A tapped alert. The root has already switched to its organization, so this only
        // opens the module; after a switch this is a new shell, and onAppear catches it.
        .onAppear { open(openRoute) }
        .onChange(of: openRoute) { _, route in open(route) }
        // A row tapped in the run across organizations. After a switch this is a new shell,
        // and onAppear catches it; in the same organization the change does.
        .onAppear { applyPending(pendingSearch) }
        .onChange(of: pendingSearch) { _, search in applyPending(search) }
        .sheet(item: $runningEverywhere) { search in
            if let crossTenant {
                CrossTenantSearchView(
                    model: {
                        CrossTenantSearchModel(search: search, targets: crossTenant.targets(), sources: crossTenant.sources)
                    },
                    currentTenantId: crossTenant.currentTenantId(),
                    open: { target in Task { await crossTenant.open(search, target) } })
            }
        }
        .background { keyboardShortcuts }
    }

    // MARK: - saved searches

    /// The saved-search screen the module column is showing, if it has one.
    private var searchScope: SavedSearch.Scope? {
        switch selectedModule {
        case .credentials?: return .devices
        case .people?: return .people
        case .conditionalAccess?: return .conditionalAccess
        case .security?:
            switch securityTab {
            case .incidents: return .incidents
            case .email: return .email
            case .digest: return nil
            }
        default: return nil
        }
    }

    /// What is on screen now, in a saved search's terms. Nil when there is nothing typed
    /// worth saving; incidents always have their filters, so they can always be saved.
    private func currentSearch(_ scope: SavedSearch.Scope) -> (query: String, options: [String: String])? {
        func typed(_ text: String) -> String { text.trimmingCharacters(in: .whitespacesAndNewlines) }
        switch scope {
        case .devices:
            let query = typed(listModel.query)
            return query.isEmpty ? nil : (query, [:])
        case .people:
            let query = typed(directoryModel.query)
            return query.isEmpty ? nil : (query, ["failuresOnly": String(triageModel.failuresOnly),
                                                  "last24Hours": String(triageModel.last24Hours)])
        case .incidents:
            return (typed(securityModel.query), ["openOnly": String(securityModel.openOnly),
                                                 "severity": securityModel.severity.rawValue])
        case .conditionalAccess:
            let query = typed(policyModel.query)
            return query.isEmpty ? nil : (query, ["sort": policyModel.sortOrder.rawValue])
        case .email:
            return nil
        }
    }

    /// Puts a saved search back on screen. Options the screen does not know are ignored, and
    /// a missing one leaves that filter as it is.
    private func applySearch(_ search: SavedSearch) {
        switch search.scope {
        case .devices:
            listModel.query = search.query
        case .people:
            if let value = search.options["failuresOnly"] { triageModel.failuresOnly = value == "true" }
            if let value = search.options["last24Hours"] { triageModel.last24Hours = value == "true" }
            // An address opens that person's page; anything else filters the directory.
            if search.query.contains("@") {
                openPerson(search.query)
            } else {
                directoryModel.query = search.query
            }
        case .incidents:
            securityTab = .incidents
            securityModel.query = search.query
            if let value = search.options["openOnly"] { securityModel.openOnly = value == "true" }
            if let raw = search.options["severity"], let floor = SecurityFilter.SeverityFloor(rawValue: raw) {
                securityModel.severity = floor
            }
        case .conditionalAccess:
            policyModel.query = search.query
            if let raw = search.options["sort"], let order = ConditionalAccessListModel.SortOrder(rawValue: raw) {
                policyModel.sortOrder = order
            }
        case .email:
            guard let raw = search.options["hunt"], EmailHunt(rawValue: raw) != nil else { return }
            securityTab = .email
            huntPrefill = search
            selectedHuntId = raw
        }
    }

    /// Opens the module a saved search belongs to and puts the search on screen.
    private func applyPending(_ search: SavedSearch?) {
        guard let search else { return }
        pendingSearch = nil
        switch search.scope {
        case .devices: selectedModule = .credentials
        case .people: selectedModule = .people
        case .incidents, .email: selectedModule = .security
        case .conditionalAccess: selectedModule = .conditionalAccess
        }
        applySearch(search)
    }

    /// The run across organizations from a bookmark menu, where it is offered.
    private var runEverywhere: ((SavedSearch) -> Void)? {
        guard crossTenant != nil else { return nil }
        return { runningEverywhere = $0 }
    }

    private func open(_ route: AlertRoute?) {
        guard let route else { return }
        openRoute = nil
        guard route.module.isEnabled else { return }
        selectedModule = route.module
        if route.module == .privilegedAccess, route.tab == "approvals" { privilegedTab = .approvals }
        if route.module == .security, route.tab == "digest" { securityTab = .digest }
        if route.module == .people, let upn = route.upn { openPerson(upn) }
    }

    /// Opens a person's page from an address: an alert, an incident, a saved search. Found
    /// in the directory, or asked of Graph when not loaded yet. When nobody has the address
    /// the search field gets it instead, so what was asked for is still on screen.
    private func openPerson(_ address: String) {
        Task {
            if let user = await directoryModel.person(withAddress: address) {
                directoryModel.query = ""
                triageModel.select(user)
                selectedPersonId = user.id
            } else {
                directoryModel.query = address
            }
        }
    }

    /// The directory's selection. A tap opens the person here, before the detail column is
    /// built, so their page never shows the person before them.
    private var personSelection: Binding<String?> {
        Binding(
            get: { selectedPersonId },
            set: { id in
                if let id, id != triageModel.selectedUser?.id, let entry = directoryModel.entry(id) {
                    triageModel.select(entry.user)
                }
                selectedPersonId = id
            })
    }

    // MARK: - columns

    /// The module's own column, with the organization switcher in its toolbar and, for an
    /// MSP, the organization banner above it. Every module, not only Devices: the switcher
    /// was built when Devices was the only module, and an MSP in Security or People could
    /// neither see which customer they were in nor change it.
    private var moduleColumn: some View {
        contentColumn
            .toolbar {
                if credentials.tenantSwitcher != nil {
                    ToolbarItem(placement: .topBarLeading) {
                        Button {
                            showingTenantSwitcher = true
                        } label: {
                            Image(systemName: credentials.tenantBanner?.isAwayFromHome == true ? "building.2.fill" : "building.2")
                        }
                        .accessibilityLabel("Switch organization")
                        .accessibilityValue(credentials.tenantBanner?.label ?? "")
                    }
                }
                if let savedSearches, let scope = searchScope {
                    ToolbarItem(placement: .topBarTrailing) {
                        SavedSearchMenu(
                            library: savedSearches,
                            scope: scope,
                            // Email's query lives in the detail column, which saves it there.
                            current: scope == .email ? nil : { currentSearch(scope) },
                            apply: { applySearch($0) },
                            runEverywhere: runEverywhere)
                    }
                }
            }
            .safeAreaInset(edge: .top) {
                // Live only: in demo every screen already carries the demo banner, which
                // names the sample customer when it is not the first.
                if !isDemo, credentials.tenantSwitcher != nil, let banner = credentials.tenantBanner {
                    TenantBanner(label: banner.label, isAwayFromHome: banner.isAwayFromHome)
                }
            }
    }

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
                // Tagged with the module itself. Untagged, a selectable List tags a row with
                // its ForEach id, here the module's raw string, which never equals the
                // selection, so the highlight showed only for a moment after a tap: never at
                // launch, and gone after a sheet or a tab in another column.
                .tag(module)
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
                // The shell shows the banner above every module when the switcher exists;
                // the device list keeps its own for a single-organization admin.
                tenantBanner: credentials.tenantSwitcher == nil ? credentials.tenantBanner : nil,
                // In a compact stack the sidebar gear is a swipe away, so the gear stays on
                // the list where it has always been. Regular width shows one gear, not two.
                settingsBuilder: sizeClass == .compact ? settingsBuilder : nil
            )
        case .people?:
            if isPro || isDemo {
                PeopleView(
                    directory: directoryModel,
                    isDemo: isDemo,
                    selection: personSelection,
                    requestConsent: signInTriage.requestConsent
                )
            } else {
                ProGateView(
                    title: "People is part of Pro",
                    detail: "Search a person, see whether they can sign in, read why each sign-in failed with the policy that blocked it named, and act on their account. Pro also removes the reveal limit.",
                    openSettings: { showingSettings = true }
                )
                .navigationTitle(AppModule.people.title)
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
            privilegedContent
                .safeAreaInset(edge: .top) { privilegedTabPicker }
        case nil:
            ContentUnavailableView("Choose a module", systemImage: "square.grid.2x2")
        }
    }

    /// Activate (needs a signed-in account) or Approvals, one segmented control above either.
    @ViewBuilder
    private var privilegedContent: some View {
        switch privilegedTab {
        case .activate:
            if let privilegedColumn {
                privilegedColumn().holding(activateForm)
            } else {
                ContentUnavailableView {
                    Label("Needs a signed-in account", systemImage: "person.badge.key")
                } description: {
                    Text("Demo data has no roles to activate. The Approvals tab shows sample requests.")
                }
                .navigationTitle(AppModule.privilegedAccess.title)
                .navigationBarTitleDisplayMode(.inline)
            }
        case .approvals:
            ApprovalsListView(model: approvalsModel, isDemo: isDemo, selection: $selectedApprovalId)
                .navigationTitle(AppModule.privilegedAccess.title)
                .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var privilegedTabPicker: some View {
        VStack(spacing: 0) {
            if isDemo { DemoBanner() }
            Picker("Privileged Access view", selection: $privilegedTab) {
                ForEach(PrivilegedTab.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
        .background(.bar)
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
        case .email:
            if isPro || isDemo {
                EmailHuntListView(isDemo: isDemo, selection: $selectedHuntId)
            } else {
                ProGateView(
                    title: "Email investigation is part of Pro",
                    detail: "Fixed, read-only hunting queries: everything a sender sent, what reached a person, phish that got through, what was pulled back, and who clicked. The Digest tab is free. Pro also removes the reveal limit.",
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
            if let id = selectedDeviceId {
                // Its own view: until the shell has recorded the opened device it is found
                // in the device list, and that read belongs to this column, not the shell.
                DeviceDetailColumn(
                    id: id,
                    list: listModel,
                    openedDevice: openedDevice,
                    detailBuilder: credentials.detailBuilder)
            } else {
                NoDeviceSelectedView()
            }
        case .people?:
            if let id = selectedPersonId, let user = triageModel.selectedUser, user.id == id {
                PersonColumn(user: user, model: triageModel, people: signInTriage)
                    .id(user.id)
            } else {
                ContentUnavailableView {
                    Label("People", systemImage: "person.2")
                } description: {
                    Text(isPro || isDemo
                         ? "Pick a person for their account, their actions, leaver checklist and groups, and their recent sign-ins."
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
                // Keyed on the change time too: the detail's model keeps the policy it was
                // built with, so a refresh that brings back an edited policy rebuilds it.
                .id(id + "#" + String(policy.modifiedDateTime?.timeIntervalSince1970 ?? 0))
            } else {
                ContentUnavailableView {
                    Label("No policy selected", systemImage: "checkmark.shield")
                } description: {
                    Text("Pick a policy from the list. Nothing here can change one.")
                }
            }
        case .security? where securityTab == .email:
            if let id = selectedHuntId, let hunt = EmailHunt(rawValue: id), isPro || isDemo {
                EmailHuntDetailView(
                    make: {
                        let model = EmailHuntModel(hunt: hunt, provider: security.emailHunting, requestConsent: security.requestHuntingConsent)
                        if let prefill = huntPrefill, prefill.options["hunt"] == hunt.rawValue {
                            model.value = prefill.query
                            if let window = prefill.options["window"].flatMap(Int.init).flatMap(HuntWindow.init(rawValue:)) {
                                model.window = window
                            }
                        }
                        return model
                    },
                    savedSearches: savedSearches,
                    apply: { applySearch($0) },
                    runEverywhere: runEverywhere)
                // Keyed by the recalled search too, so recalling one rebuilds the query.
                .id(id + (huntPrefill?.id.uuidString ?? ""))
            } else {
                ContentUnavailableView {
                    Label("Investigate Email", systemImage: "envelope.badge.shield.half.filled")
                } description: {
                    Text(isPro || isDemo
                         ? "Pick a query. Each is fixed and read-only, and takes at most one value."
                         : "Available with Pro.")
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
                        // Read-only to read-only, so no gate: the person's page opens.
                        selectedModule = .people
                        openPerson(upn)
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
        case .privilegedAccess? where privilegedTab == .approvals:
            if let id = selectedApprovalId, let approval = approvalsModel.approval(id) {
                ApprovalDetailView(model: approvalsModel, approval: approval)
                    .id(id)
            } else {
                ContentUnavailableView {
                    Label("PIM Approvals", systemImage: "checkmark.seal")
                } description: {
                    Text("Pick a request for who is asking, for what, for how long and why, then approve or deny it with a reason.")
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
        DeviceDetailColumn.device(id, in: listModel, openedDevice: openedDevice)
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

            if credentials.tenantSwitcher != nil {
                Button("Switch organization") { showingTenantSwitcher = true }
                    .keyboardShortcut("t", modifiers: [.command, .shift])
            }

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

/// The detail column for an open device: the device as it was when opened, or from the
/// list for the moment before the shell has recorded it. Not from the list once opened:
/// the detail's model keeps the device it was built with anyway, and reading the list here
/// would redraw the open device on every page of the fill. It also covers a pull to
/// refresh, which can leave the open device out of the list for a while.
private struct DeviceDetailColumn: View {
    let id: String
    let list: DeviceListModel
    let openedDevice: ManagedDeviceSummary?
    let detailBuilder: (ManagedDeviceSummary) -> DeviceDetailView

    var body: some View {
        if let device = Self.device(id, in: list, openedDevice: openedDevice) {
            // Keyed by id so choosing another device replaces the screen outright, which
            // is what makes the previous one's onDisappear fire and its reveal wipe.
            detailBuilder(device)
                .id(id)
        } else {
            NoDeviceSelectedView()
        }
    }

    static func device(_ id: String, in list: DeviceListModel, openedDevice: ManagedDeviceSummary?) -> ManagedDeviceSummary? {
        if let openedDevice, openedDevice.id == id { return openedDevice }
        return list.devicesById[id]
    }
}

private struct NoDeviceSelectedView: View {
    var body: some View {
        ContentUnavailableView {
            Label("No device selected", systemImage: "laptopcomputer")
        } description: {
            Text("Pick a device from the list, or search for one.")
        }
    }
}
