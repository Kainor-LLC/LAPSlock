import Foundation

// A Conditional Access policy as Graph returns it, read-only.
//
// The model keeps Graph's shape and names so a reader can hold the portal and this screen
// side by side. Every collection is optional on the wire and empty here: Graph sends null
// for a condition that was never set, and a policy with a null `excludeGroups` is not a
// decoding failure. Unknown state values decode as `.unknown` rather than failing the
// whole list, because Microsoft adds states and a new one must not take the module down.
//
// Nothing here edits anything. There is no write path in this module by design (spec 3.7):
// if someone wants to change Conditional Access from a parking lot, the app should not
// help them.

public struct ConditionalAccessPolicy: Codable, Sendable, Equatable, Identifiable {

    public enum State: String, Codable, Sendable, Equatable, CaseIterable {
        case enabled
        case disabled
        case reportOnly = "enabledForReportingButNotEnforced"
        case unknown

        public init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = State(rawValue: raw) ?? .unknown
        }

        public var label: String {
            switch self {
            case .enabled:    return "On"
            case .disabled:   return "Off"
            case .reportOnly: return "Report-only"
            case .unknown:    return "Unknown"
            }
        }
    }

    public let id: String
    public let displayName: String
    public let state: State
    public let createdDateTime: Date?
    public let modifiedDateTime: Date?
    public let conditions: Conditions
    public let grantControls: GrantControls?
    public let sessionControls: SessionControls?

    public init(
        id: String,
        displayName: String,
        state: State,
        createdDateTime: Date? = nil,
        modifiedDateTime: Date? = nil,
        conditions: Conditions = Conditions(),
        grantControls: GrantControls? = nil,
        sessionControls: SessionControls? = nil
    ) {
        self.id = id
        self.displayName = displayName
        self.state = state
        self.createdDateTime = createdDateTime
        self.modifiedDateTime = modifiedDateTime
        self.conditions = conditions
        self.grantControls = grantControls
        self.sessionControls = sessionControls
    }

    /// The date the list sorts and badges by. Graph leaves `modifiedDateTime` null on a
    /// policy that has never been edited since creation, so creation stands in.
    public var lastChanged: Date? { modifiedDateTime ?? createdDateTime }

    /// Whether the policy changed inside the window, for the "changed recently" badge.
    public func changed(withinDays days: Int, now: Date = Date()) -> Bool {
        guard let date = lastChanged else { return false }
        return now.timeIntervalSince(date) <= TimeInterval(days) * 86_400
    }

    // MARK: - conditions

    public struct Conditions: Codable, Sendable, Equatable {
        public var users: Users
        public var applications: Applications
        public var platforms: Platforms?
        public var locations: Locations?
        @EmptyIfMissing public var clientAppTypes: [String]
        @EmptyIfMissing public var signInRiskLevels: [String]
        @EmptyIfMissing public var userRiskLevels: [String]
        public var devices: Devices?

        public init(
            users: Users = Users(),
            applications: Applications = Applications(),
            platforms: Platforms? = nil,
            locations: Locations? = nil,
            clientAppTypes: [String] = [],
            signInRiskLevels: [String] = [],
            userRiskLevels: [String] = [],
            devices: Devices? = nil
        ) {
            self.users = users
            self.applications = applications
            self.platforms = platforms
            self.locations = locations
            self.clientAppTypes = clientAppTypes
            self.signInRiskLevels = signInRiskLevels
            self.userRiskLevels = userRiskLevels
            self.devices = devices
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            users = try c.decodeIfPresent(Users.self, forKey: .users) ?? Users()
            applications = try c.decodeIfPresent(Applications.self, forKey: .applications) ?? Applications()
            platforms = try c.decodeIfPresent(Platforms.self, forKey: .platforms)
            locations = try c.decodeIfPresent(Locations.self, forKey: .locations)
            _clientAppTypes = try c.decode(EmptyIfMissing<[String]>.self, forKey: .clientAppTypes)
            _signInRiskLevels = try c.decode(EmptyIfMissing<[String]>.self, forKey: .signInRiskLevels)
            _userRiskLevels = try c.decode(EmptyIfMissing<[String]>.self, forKey: .userRiskLevels)
            devices = try c.decodeIfPresent(Devices.self, forKey: .devices)
        }
    }

    public struct Users: Codable, Sendable, Equatable {
        @EmptyIfMissing public var includeUsers: [String]
        @EmptyIfMissing public var excludeUsers: [String]
        @EmptyIfMissing public var includeGroups: [String]
        @EmptyIfMissing public var excludeGroups: [String]
        @EmptyIfMissing public var includeRoles: [String]
        @EmptyIfMissing public var excludeRoles: [String]

        public init(
            includeUsers: [String] = [], excludeUsers: [String] = [],
            includeGroups: [String] = [], excludeGroups: [String] = [],
            includeRoles: [String] = [], excludeRoles: [String] = []
        ) {
            self.includeUsers = includeUsers
            self.excludeUsers = excludeUsers
            self.includeGroups = includeGroups
            self.excludeGroups = excludeGroups
            self.includeRoles = includeRoles
            self.excludeRoles = excludeRoles
        }
    }

    public struct Applications: Codable, Sendable, Equatable {
        @EmptyIfMissing public var includeApplications: [String]
        @EmptyIfMissing public var excludeApplications: [String]
        @EmptyIfMissing public var includeUserActions: [String]
        @EmptyIfMissing public var includeAuthenticationContextClassReferences: [String]

        public init(
            includeApplications: [String] = [], excludeApplications: [String] = [],
            includeUserActions: [String] = [], includeAuthenticationContextClassReferences: [String] = []
        ) {
            self.includeApplications = includeApplications
            self.excludeApplications = excludeApplications
            self.includeUserActions = includeUserActions
            self.includeAuthenticationContextClassReferences = includeAuthenticationContextClassReferences
        }
    }

    public struct Platforms: Codable, Sendable, Equatable {
        @EmptyIfMissing public var includePlatforms: [String]
        @EmptyIfMissing public var excludePlatforms: [String]
        public init(includePlatforms: [String] = [], excludePlatforms: [String] = []) {
            self.includePlatforms = includePlatforms
            self.excludePlatforms = excludePlatforms
        }
    }

    public struct Locations: Codable, Sendable, Equatable {
        @EmptyIfMissing public var includeLocations: [String]
        @EmptyIfMissing public var excludeLocations: [String]
        public init(includeLocations: [String] = [], excludeLocations: [String] = []) {
            self.includeLocations = includeLocations
            self.excludeLocations = excludeLocations
        }
    }

    public struct Devices: Codable, Sendable, Equatable {
        public var deviceFilter: DeviceFilter?
        public init(deviceFilter: DeviceFilter? = nil) { self.deviceFilter = deviceFilter }
    }

    public struct DeviceFilter: Codable, Sendable, Equatable {
        /// `include` or `exclude`.
        public var mode: String
        public var rule: String
        public init(mode: String, rule: String) {
            self.mode = mode
            self.rule = rule
        }
    }

    // MARK: - controls

    public struct GrantControls: Codable, Sendable, Equatable {
        /// `AND` or `OR`, how `builtInControls` combine.
        public var `operator`: String?
        @EmptyIfMissing public var builtInControls: [String]
        @EmptyIfMissing public var customAuthenticationFactors: [String]
        @EmptyIfMissing public var termsOfUse: [String]
        public var authenticationStrength: AuthenticationStrength?

        public init(
            operator: String? = nil,
            builtInControls: [String] = [],
            customAuthenticationFactors: [String] = [],
            termsOfUse: [String] = [],
            authenticationStrength: AuthenticationStrength? = nil
        ) {
            self.operator = `operator`
            self.builtInControls = builtInControls
            self.customAuthenticationFactors = customAuthenticationFactors
            self.termsOfUse = termsOfUse
            self.authenticationStrength = authenticationStrength
        }
    }

    public struct AuthenticationStrength: Codable, Sendable, Equatable {
        public var id: String?
        public var displayName: String?
        public init(id: String? = nil, displayName: String? = nil) {
            self.id = id
            self.displayName = displayName
        }
    }

    public struct SessionControls: Codable, Sendable, Equatable {
        public var signInFrequency: SignInFrequency?
        public var persistentBrowser: PersistentBrowser?
        public var applicationEnforcedRestrictions: Enabled?
        public var cloudAppSecurity: CloudAppSecurity?
        public var disableResilienceDefaults: Bool?

        public init(
            signInFrequency: SignInFrequency? = nil,
            persistentBrowser: PersistentBrowser? = nil,
            applicationEnforcedRestrictions: Enabled? = nil,
            cloudAppSecurity: CloudAppSecurity? = nil,
            disableResilienceDefaults: Bool? = nil
        ) {
            self.signInFrequency = signInFrequency
            self.persistentBrowser = persistentBrowser
            self.applicationEnforcedRestrictions = applicationEnforcedRestrictions
            self.cloudAppSecurity = cloudAppSecurity
            self.disableResilienceDefaults = disableResilienceDefaults
        }
    }

    public struct SignInFrequency: Codable, Sendable, Equatable {
        public var value: Int?
        /// `hours` or `days`.
        public var type: String?
        public var isEnabled: Bool?
        /// `timeBased` or `everyTime`.
        public var frequencyInterval: String?
        public init(value: Int? = nil, type: String? = nil, isEnabled: Bool? = nil, frequencyInterval: String? = nil) {
            self.value = value
            self.type = type
            self.isEnabled = isEnabled
            self.frequencyInterval = frequencyInterval
        }
    }

    public struct PersistentBrowser: Codable, Sendable, Equatable {
        /// `always` or `never`.
        public var mode: String?
        public var isEnabled: Bool?
        public init(mode: String? = nil, isEnabled: Bool? = nil) {
            self.mode = mode
            self.isEnabled = isEnabled
        }
    }

    public struct Enabled: Codable, Sendable, Equatable {
        public var isEnabled: Bool?
        public init(isEnabled: Bool? = nil) { self.isEnabled = isEnabled }
    }

    public struct CloudAppSecurity: Codable, Sendable, Equatable {
        public var cloudAppSecurityType: String?
        public var isEnabled: Bool?
        public init(cloudAppSecurityType: String? = nil, isEnabled: Bool? = nil) {
            self.cloudAppSecurityType = cloudAppSecurityType
            self.isEnabled = isEnabled
        }
    }
}

// MARK: - tolerant collections

/// A collection Graph may omit or send as null. Decodes to empty in either case.
@propertyWrapper
public struct EmptyIfMissing<Value: Codable & Sendable & Equatable & EmptyRepresentable>: Codable, Sendable, Equatable {
    public var wrappedValue: Value

    public init(wrappedValue: Value) { self.wrappedValue = wrappedValue }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        wrappedValue = container.decodeNil() ? Value.empty : try container.decode(Value.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(wrappedValue)
    }
}

public protocol EmptyRepresentable {
    static var empty: Self { get }
}

extension Array: EmptyRepresentable {
    public static var empty: [Element] { [] }
}

public extension KeyedDecodingContainer {
    /// A missing key is the same as null: empty.
    func decode<T>(_ type: EmptyIfMissing<T>.Type, forKey key: Key) throws -> EmptyIfMissing<T> {
        try decodeIfPresent(type, forKey: key) ?? EmptyIfMissing(wrappedValue: T.empty)
    }
}

// MARK: - what a policy points at

/// Something in the directory that a policy names by id and a person knows by name.
public struct DirectoryReference: Hashable, Sendable, Codable {
    public enum Kind: String, Sendable, Codable, CaseIterable {
        case user
        case group
        case role
        case application
        case location
    }
    public let kind: Kind
    public let id: String

    public init(kind: Kind, id: String) {
        self.kind = kind
        self.id = id
    }
}

public extension ConditionalAccessPolicy {

    /// Every id in the policy that is a directory object rather than a keyword, so the
    /// names can be fetched in one pass before the detail is shown.
    var references: Set<DirectoryReference> {
        var refs = Set<DirectoryReference>()
        func add(_ kind: DirectoryReference.Kind, _ ids: [String]) {
            for id in ids where ConditionalAccessVocabulary.isDirectoryId(id) {
                refs.insert(DirectoryReference(kind: kind, id: id))
            }
        }
        add(.user, conditions.users.includeUsers)
        add(.user, conditions.users.excludeUsers)
        add(.group, conditions.users.includeGroups)
        add(.group, conditions.users.excludeGroups)
        add(.role, conditions.users.includeRoles)
        add(.role, conditions.users.excludeRoles)
        add(.application, conditions.applications.includeApplications)
        add(.application, conditions.applications.excludeApplications)
        add(.location, conditions.locations?.includeLocations ?? [])
        add(.location, conditions.locations?.excludeLocations ?? [])
        return refs
    }
}

/// The keywords Graph uses in place of ids, and their plain-English forms.
public enum ConditionalAccessVocabulary {

    /// True for a GUID, which is the only shape a directory object id takes. Keywords such
    /// as `All` and well-known application names are not looked up.
    public static func isDirectoryId(_ value: String) -> Bool {
        value.range(of: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                    options: .regularExpression) != nil
    }

    public static func userLabel(_ token: String) -> String {
        switch token {
        case "All":                   return "All users"
        case "None":                  return "No users"
        case "GuestsOrExternalUsers": return "Guests and external users"
        default:                      return token
        }
    }

    public static func applicationLabel(_ token: String) -> String {
        switch token {
        case "All":                    return "All cloud apps"
        case "None":                   return "No apps"
        case "Office365":              return "Office 365"
        case "MicrosoftAdminPortals":  return "Microsoft admin portals"
        default:                       return token
        }
    }

    public static func locationLabel(_ token: String) -> String {
        switch token {
        case "All":        return "Any location"
        case "AllTrusted": return "All trusted locations"
        default:           return token
        }
    }

    public static func platformLabel(_ token: String) -> String {
        switch token.lowercased() {
        case "all":          return "All platforms"
        case "android":      return "Android"
        case "ios":          return "iOS"
        case "windows":      return "Windows"
        case "windowsphone": return "Windows Phone"
        case "macos":        return "macOS"
        case "linux":        return "Linux"
        default:             return token
        }
    }

    public static func clientAppLabel(_ token: String) -> String {
        switch token {
        case "all":                         return "All client apps"
        case "browser":                     return "Browser"
        case "mobileAppsAndDesktopClients": return "Mobile apps and desktop clients"
        case "exchangeActiveSync":          return "Exchange ActiveSync (legacy)"
        case "other":                       return "Other clients (legacy authentication)"
        default:                            return token
        }
    }

    public static func grantControlLabel(_ token: String) -> String {
        switch token {
        case "block":                              return "Block access"
        case "mfa":                                return "Require multifactor authentication"
        case "compliantDevice":                    return "Require a compliant device"
        case "domainJoinedDevice":                 return "Require a Microsoft Entra hybrid joined device"
        case "approvedApplication":                return "Require an approved client app"
        case "compliantApplication":               return "Require an app protection policy"
        case "passwordChange":                     return "Require a password change"
        case "unknownFutureValue":                 return "Unknown control"
        default:                                   return token
        }
    }

    public static func riskLabel(_ token: String) -> String {
        switch token {
        case "low":    return "Low"
        case "medium": return "Medium"
        case "high":   return "High"
        case "none":   return "None"
        case "hidden": return "Hidden"
        default:       return token
        }
    }

    /// A GUID shortened for a row where the name could not be resolved. Enough to match
    /// against the portal, not enough to crowd the screen.
    public static func shortId(_ id: String) -> String {
        guard isDirectoryId(id) else { return id }
        return String(id.prefix(8)) + "…"
    }
}
