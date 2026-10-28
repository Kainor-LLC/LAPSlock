import Foundation
import AuthKit

// Incidents, alerts and evidence as the Microsoft Graph security API returns them on v1.0,
// read-only. Spec section 3.12.
//
// The model keeps Graph's names so the portal and this screen can be held side by side.
// Every enum here is evolvable on Microsoft's side, so each one decodes an unexpected
// value into an `unknown` case instead of failing the whole incident: a new severity or
// service source must not take the module down. The same goes for evidence: Graph has
// fifty evidence types and the module models the nine an on-call administrator acts on;
// anything else becomes an `other` row that shows its type name rather than vanishing.

public enum SecuritySeverity: String, Codable, Sendable, Equatable, CaseIterable, Comparable {
    case unknown
    case informational
    case low
    case medium
    case high

    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = SecuritySeverity(rawValue: raw) ?? .unknown
    }

    public var rank: Int {
        switch self {
        case .unknown:       return 0
        case .informational: return 1
        case .low:           return 2
        case .medium:        return 3
        case .high:          return 4
        }
    }

    public static func < (a: SecuritySeverity, b: SecuritySeverity) -> Bool { a.rank < b.rank }

    public var label: String {
        switch self {
        case .unknown:       return "Unknown"
        case .informational: return "Info"
        case .low:           return "Low"
        case .medium:        return "Medium"
        case .high:          return "High"
        }
    }
}

/// One incident: the case the security portal groups related alerts under.
public struct SecurityIncident: Codable, Sendable, Equatable, Identifiable {

    public enum Status: Codable, Sendable, Equatable {
        case active
        case inProgress
        case resolved
        case redirected
        case awaitingAction
        case unknown(String)

        public init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self.init(raw)
        }

        public init(_ raw: String) {
            switch raw {
            case "active":         self = .active
            case "inProgress":     self = .inProgress
            case "resolved":       self = .resolved
            case "redirected":     self = .redirected
            case "awaitingAction": self = .awaitingAction
            default:               self = .unknown(raw)
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(rawValue)
        }

        public var rawValue: String {
            switch self {
            case .active:            return "active"
            case .inProgress:        return "inProgress"
            case .resolved:          return "resolved"
            case .redirected:        return "redirected"
            case .awaitingAction:    return "awaitingAction"
            case .unknown(let raw):  return raw
            }
        }

        public var label: String {
            switch self {
            case .active:         return "Active"
            case .inProgress:     return "In progress"
            case .resolved:       return "Resolved"
            case .redirected:     return "Redirected"
            case .awaitingAction: return "Awaiting action"
            case .unknown:        return "Unknown"
            }
        }

        /// Resolved and redirected are closed; everything else still wants a person.
        public var isOpen: Bool {
            switch self {
            case .resolved, .redirected: return false
            default:                     return true
            }
        }
    }

    public let id: String
    public let displayName: String?
    public let severity: SecuritySeverity
    public let status: Status
    public let assignedTo: String?
    public let classification: String?
    public let determination: String?
    public let createdDateTime: Date?
    public let lastUpdateDateTime: Date?
    public let priorityScore: Int?
    public let incidentWebUrl: String?
    public let summary: String?
    public let alerts: [SecurityAlert]
    /// False on the lean first read, which leaves the alerts out, so the row shows no
    /// alert count and no evidence rather than zero of each.
    public let alertsIncluded: Bool
    /// Every piece of evidence across the incident's alerts, in alert order. Worked out
    /// once, when the incident is made, rather than on every read of a row.
    public let evidence: [AlertEvidence]
    /// "2 users, 1 device, 3 URLs", for the list row. Empty when there is no evidence.
    public let evidenceSummary: String
    /// The title, the alert titles and the evidence labels, folded, for the list's search.
    public let searchKey: String

    public init(
        id: String,
        displayName: String?,
        severity: SecuritySeverity,
        status: Status,
        assignedTo: String? = nil,
        classification: String? = nil,
        determination: String? = nil,
        createdDateTime: Date? = nil,
        lastUpdateDateTime: Date? = nil,
        priorityScore: Int? = nil,
        incidentWebUrl: String? = nil,
        summary: String? = nil,
        alerts: [SecurityAlert] = [],
        alertsIncluded: Bool = true
    ) {
        self.id = id
        self.displayName = displayName
        self.severity = severity
        self.status = status
        self.assignedTo = assignedTo
        self.classification = classification
        self.determination = determination
        self.createdDateTime = createdDateTime
        self.lastUpdateDateTime = lastUpdateDateTime
        self.priorityScore = priorityScore
        self.incidentWebUrl = incidentWebUrl
        self.summary = summary
        self.alerts = alerts
        self.alertsIncluded = alertsIncluded
        let evidence = alerts.flatMap(\.evidence)
        self.evidence = evidence
        evidenceSummary = Self.summary(of: evidence)
        searchKey = Self.searchKey(title: Self.title(displayName: displayName, id: id), alerts: alerts, evidence: evidence)
    }

    enum CodingKeys: String, CodingKey {
        case id, displayName, severity, status, assignedTo, classification, determination
        case createdDateTime, lastUpdateDateTime, priorityScore, incidentWebUrl, summary, alerts
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let id = try c.decode(String.self, forKey: .id)
        let displayName = try c.decodeIfPresent(String.self, forKey: .displayName)
        self.id = id
        self.displayName = displayName
        severity = try c.decodeIfPresent(SecuritySeverity.self, forKey: .severity) ?? .unknown
        status = try c.decodeIfPresent(Status.self, forKey: .status) ?? .unknown("")
        assignedTo = try c.decodeIfPresent(String.self, forKey: .assignedTo)
        classification = try c.decodeIfPresent(String.self, forKey: .classification)
        determination = try c.decodeIfPresent(String.self, forKey: .determination)
        createdDateTime = try c.decodeIfPresent(Date.self, forKey: .createdDateTime)
        lastUpdateDateTime = try c.decodeIfPresent(Date.self, forKey: .lastUpdateDateTime)
        priorityScore = try c.decodeIfPresent(Int.self, forKey: .priorityScore)
        incidentWebUrl = try c.decodeIfPresent(String.self, forKey: .incidentWebUrl)
        summary = try c.decodeIfPresent(String.self, forKey: .summary)
        let alerts = try c.decodeIfPresent([SecurityAlert].self, forKey: .alerts) ?? []
        self.alerts = alerts
        alertsIncluded = c.contains(.alerts)
        let evidence = alerts.flatMap(\.evidence)
        self.evidence = evidence
        evidenceSummary = Self.summary(of: evidence)
        searchKey = Self.searchKey(title: Self.title(displayName: displayName, id: id), alerts: alerts, evidence: evidence)
    }

    /// The title the list shows. Graph can leave `displayName` null on a redirected incident.
    public var title: String { Self.title(displayName: displayName, id: id) }

    private static func title(displayName: String?, id: String) -> String {
        if let displayName, !displayName.isEmpty { return displayName }
        return "Incident " + id
    }

    /// Case, accents and width set aside, the same way for the key and the query.
    public static func fold(_ text: String) -> String {
        text.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
    }

    /// Fields joined with a separator nobody types, so a query cannot match across two.
    private static func searchKey(title: String, alerts: [SecurityAlert], evidence: [AlertEvidence]) -> String {
        ([title] + alerts.map(\.displayTitle) + evidence.map(\.label) + evidence.flatMap(\.personNames))
            .map(fold).joined(separator: "\u{1F}")
    }

    /// Whether a query, folded with `fold`, appears in the title, an alert or the evidence.
    public func matches(folded query: String) -> Bool {
        searchKey.contains(query)
    }

    public var isOpen: Bool { status.isOpen }

    /// The date the list sorts by: the last update, or creation when there has been none.
    public var lastActivity: Date? { lastUpdateDateTime ?? createdDateTime }

    private static func summary(of evidence: [AlertEvidence]) -> String {
        let counts = Dictionary(grouping: evidence, by: \.kindTitle).mapValues(\.count)
        let ordered = AlertEvidence.Kind.displayOrder.compactMap { kind -> String? in
            guard let count = counts[kind.title] else { return nil }
            return "\(count) " + (count == 1 ? kind.singular : kind.plural)
        }
        return ordered.joined(separator: ", ")
    }
}

/// One alert inside an incident.
public struct SecurityAlert: Codable, Sendable, Equatable, Identifiable {

    public enum Status: Codable, Sendable, Equatable {
        case new
        case inProgress
        case resolved
        case unknown(String)

        public init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self.init(raw)
        }

        public init(_ raw: String) {
            switch raw {
            case "new":        self = .new
            case "inProgress": self = .inProgress
            case "resolved":   self = .resolved
            default:           self = .unknown(raw)
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(rawValue)
        }

        public var rawValue: String {
            switch self {
            case .new:              return "new"
            case .inProgress:       return "inProgress"
            case .resolved:         return "resolved"
            case .unknown(let raw): return raw
            }
        }

        public var label: String {
            switch self {
            case .new:        return "New"
            case .inProgress: return "In progress"
            case .resolved:   return "Resolved"
            case .unknown:    return "Unknown"
            }
        }
    }

    public let id: String
    public let title: String?
    public let description: String?
    public let severity: SecuritySeverity
    public let status: Status
    public let serviceSource: String?
    public let detectionSource: String?
    public let category: String?
    public let categories: [String]
    public let recommendedActions: String?
    public let mitreTechniques: [String]
    public let createdDateTime: Date?
    public let firstActivityDateTime: Date?
    public let lastActivityDateTime: Date?
    public let alertWebUrl: String?
    public let evidence: [AlertEvidence]

    public init(
        id: String,
        title: String?,
        description: String? = nil,
        severity: SecuritySeverity,
        status: Status,
        serviceSource: String? = nil,
        detectionSource: String? = nil,
        category: String? = nil,
        categories: [String] = [],
        recommendedActions: String? = nil,
        mitreTechniques: [String] = [],
        createdDateTime: Date? = nil,
        firstActivityDateTime: Date? = nil,
        lastActivityDateTime: Date? = nil,
        alertWebUrl: String? = nil,
        evidence: [AlertEvidence] = []
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.severity = severity
        self.status = status
        self.serviceSource = serviceSource
        self.detectionSource = detectionSource
        self.category = category
        self.categories = categories
        self.recommendedActions = recommendedActions
        self.mitreTechniques = mitreTechniques
        self.createdDateTime = createdDateTime
        self.firstActivityDateTime = firstActivityDateTime
        self.lastActivityDateTime = lastActivityDateTime
        self.alertWebUrl = alertWebUrl
        self.evidence = evidence
    }

    enum CodingKeys: String, CodingKey {
        case id, title, description, severity, status, serviceSource, detectionSource, category, categories
        case recommendedActions, mitreTechniques, createdDateTime, firstActivityDateTime, lastActivityDateTime
        case alertWebUrl, evidence
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let id = try c.decode(String.self, forKey: .id)
        self.id = id
        title = try c.decodeIfPresent(String.self, forKey: .title)
        description = try c.decodeIfPresent(String.self, forKey: .description)
        severity = try c.decodeIfPresent(SecuritySeverity.self, forKey: .severity) ?? .unknown
        status = try c.decodeIfPresent(Status.self, forKey: .status) ?? .unknown("")
        serviceSource = try c.decodeIfPresent(String.self, forKey: .serviceSource)
        detectionSource = try c.decodeIfPresent(String.self, forKey: .detectionSource)
        category = try c.decodeIfPresent(String.self, forKey: .category)
        categories = try c.decodeIfPresent([String].self, forKey: .categories) ?? []
        recommendedActions = try c.decodeIfPresent(String.self, forKey: .recommendedActions)
        mitreTechniques = try c.decodeIfPresent([String].self, forKey: .mitreTechniques) ?? []
        createdDateTime = try c.decodeIfPresent(Date.self, forKey: .createdDateTime)
        firstActivityDateTime = try c.decodeIfPresent(Date.self, forKey: .firstActivityDateTime)
        lastActivityDateTime = try c.decodeIfPresent(Date.self, forKey: .lastActivityDateTime)
        alertWebUrl = try c.decodeIfPresent(String.self, forKey: .alertWebUrl)
        // Evidence has no id on the wire. The alert's id and the position are the same on
        // every read, so a refresh keeps each evidence row's identity.
        let evidence = try c.decodeIfPresent([AlertEvidence].self, forKey: .evidence) ?? []
        self.evidence = evidence.enumerated().map { $0.element.identified(id + ":" + String($0.offset)) }
    }

    public var displayTitle: String {
        if let title, !title.isEmpty { return title }
        return "Alert " + id
    }

    /// Graph sends the recommended actions as one string with line breaks between steps.
    public var recommendedActionLines: [String] {
        guard let recommendedActions else { return [] }
        return recommendedActions
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// The categories Graph lists, or the deprecated single category when that is all there is.
    public var allCategories: [String] {
        if !categories.isEmpty { return categories }
        if let category, !category.isEmpty { return [category] }
        return []
    }
}

/// One piece of evidence on an alert: who, what and where.
public struct AlertEvidence: Codable, Sendable, Equatable, Identifiable {

    public enum Verdict: Codable, Sendable, Equatable {
        case unknown
        case suspicious
        case malicious
        case noThreatsFound
        case other(String)

        public init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self.init(raw)
        }

        public init(_ raw: String) {
            switch raw {
            case "unknown":        self = .unknown
            case "suspicious":     self = .suspicious
            case "malicious":      self = .malicious
            case "noThreatsFound": self = .noThreatsFound
            default:               self = .other(raw)
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(rawValue)
        }

        public var rawValue: String {
            switch self {
            case .unknown:          return "unknown"
            case .suspicious:       return "suspicious"
            case .malicious:        return "malicious"
            case .noThreatsFound:   return "noThreatsFound"
            case .other(let raw):   return raw
            }
        }

        public var label: String {
            switch self {
            case .unknown:        return "No verdict"
            case .suspicious:     return "Suspicious"
            case .malicious:      return "Malicious"
            case .noThreatsFound: return "No threats found"
            case .other:          return "Unknown"
            }
        }
    }

    public enum Kind: Sendable, Equatable {
        case user(UserAccount)
        case device(Device)
        case mailbox(Mailbox)
        case ip(address: String, country: String?)
        case url(String)
        case file(File)
        case process(Process)
        case cloudApplication(name: String?, appId: String?)
        case oauthApplication(name: String?, appId: String?, publisher: String?)
        case other(typeName: String)

        /// The order the groups appear in on screen: people first, then what they touched.
        public static let displayOrder: [Kind] = [
            .user(UserAccount()), .device(Device()), .mailbox(Mailbox()),
            .ip(address: "", country: nil), .url(""), .file(File()), .process(Process()),
            .cloudApplication(name: nil, appId: nil), .oauthApplication(name: nil, appId: nil, publisher: nil),
            .other(typeName: "")
        ]

        public var title: String {
            switch self {
            case .user:             return "Users"
            case .device:           return "Devices"
            case .mailbox:          return "Mailboxes"
            case .ip:               return "IP Addresses"
            case .url:              return "URLs"
            case .file:             return "Files"
            case .process:          return "Processes"
            case .cloudApplication: return "Cloud Apps"
            case .oauthApplication: return "OAuth Apps"
            case .other:            return "Other"
            }
        }

        public var singular: String {
            switch self {
            case .user:             return "user"
            case .device:           return "device"
            case .mailbox:          return "mailbox"
            case .ip:               return "IP address"
            case .url:              return "URL"
            case .file:             return "file"
            case .process:          return "process"
            case .cloudApplication: return "cloud app"
            case .oauthApplication: return "OAuth app"
            case .other:            return "other item"
            }
        }

        public var plural: String {
            switch self {
            case .ip:      return "IP addresses"
            case .mailbox: return "mailboxes"
            case .process: return "processes"
            case .other:   return "other items"
            default:       return singular + "s"
            }
        }
    }

    public struct UserAccount: Codable, Sendable, Equatable {
        public var accountName: String?
        public var domainName: String?
        public var userPrincipalName: String?
        public var displayName: String?
        public var azureAdUserId: String?
        public init(accountName: String? = nil, domainName: String? = nil, userPrincipalName: String? = nil, displayName: String? = nil, azureAdUserId: String? = nil) {
            self.accountName = accountName
            self.domainName = domainName
            self.userPrincipalName = userPrincipalName
            self.displayName = displayName
            self.azureAdUserId = azureAdUserId
        }
        /// The sign-in address, or the best stand-in Graph gave.
        public var label: String {
            if let userPrincipalName, !userPrincipalName.isEmpty { return userPrincipalName }
            if let displayName, !displayName.isEmpty { return displayName }
            if let accountName, let domainName { return domainName + "\\" + accountName }
            return accountName ?? "Unknown user"
        }
    }

    public struct Device: Codable, Sendable, Equatable {
        public var deviceDnsName: String?
        public var mdeDeviceId: String?
        public var azureAdDeviceId: String?
        public var osPlatform: String?
        public var osBuild: Int?
        public var healthStatus: String?
        public var riskScore: String?
        public var onboardingStatus: String?
        public init(deviceDnsName: String? = nil, mdeDeviceId: String? = nil, azureAdDeviceId: String? = nil, osPlatform: String? = nil, osBuild: Int? = nil, healthStatus: String? = nil, riskScore: String? = nil, onboardingStatus: String? = nil) {
            self.deviceDnsName = deviceDnsName
            self.mdeDeviceId = mdeDeviceId
            self.azureAdDeviceId = azureAdDeviceId
            self.osPlatform = osPlatform
            self.osBuild = osBuild
            self.healthStatus = healthStatus
            self.riskScore = riskScore
            self.onboardingStatus = onboardingStatus
        }
        /// The short host name, which is what the Intune device list is searched by.
        public var hostName: String? {
            guard let deviceDnsName, !deviceDnsName.isEmpty else { return nil }
            return deviceDnsName.components(separatedBy: ".").first
        }
    }

    public struct Mailbox: Codable, Sendable, Equatable {
        public var displayName: String?
        public var primaryAddress: String?
        public var userAccount: UserAccount?
        public init(displayName: String? = nil, primaryAddress: String? = nil, userAccount: UserAccount? = nil) {
            self.displayName = displayName
            self.primaryAddress = primaryAddress
            self.userAccount = userAccount
        }
    }

    public struct File: Codable, Sendable, Equatable {
        public var fileName: String?
        public var filePath: String?
        public var sha256: String?
        public var sha1: String?
        public var filePublisher: String?
        public var fileSize: Int?
        public init(fileName: String? = nil, filePath: String? = nil, sha256: String? = nil, sha1: String? = nil, filePublisher: String? = nil, fileSize: Int? = nil) {
            self.fileName = fileName
            self.filePath = filePath
            self.sha256 = sha256
            self.sha1 = sha1
            self.filePublisher = filePublisher
            self.fileSize = fileSize
        }
    }

    public struct Process: Codable, Sendable, Equatable {
        public var processId: Int?
        public var processCommandLine: String?
        public var imageFile: File?
        public var userAccount: UserAccount?
        public var detectionStatus: String?
        public init(processId: Int? = nil, processCommandLine: String? = nil, imageFile: File? = nil, userAccount: UserAccount? = nil, detectionStatus: String? = nil) {
            self.processId = processId
            self.processCommandLine = processCommandLine
            self.imageFile = imageFile
            self.userAccount = userAccount
            self.detectionStatus = detectionStatus
        }
    }

    public let id: String
    public let kind: Kind
    /// What this item did in the alert, as Graph names it: attacker, compromised, source.
    public let roles: [String]
    public let verdict: Verdict
    public let remediationStatus: String?
    public let createdDateTime: Date?

    public init(
        id: String,
        kind: Kind,
        roles: [String] = [],
        verdict: Verdict = .unknown,
        remediationStatus: String? = nil,
        createdDateTime: Date? = nil
    ) {
        self.id = id
        self.kind = kind
        self.roles = roles
        self.verdict = verdict
        self.remediationStatus = remediationStatus
        self.createdDateTime = createdDateTime
    }

    // MARK: - wire shape

    enum CodingKeys: String, CodingKey {
        case odataType = "@odata.type"
        case roles, verdict, remediationStatus, createdDateTime
        case userAccount
        case deviceDnsName, mdeDeviceId, azureAdDeviceId, osPlatform, osBuild, healthStatus, riskScore, onboardingStatus
        case displayName, primaryAddress
        case ipAddress, countryLetterCode
        case url
        case fileDetails
        case processId, processCommandLine, imageFile, detectionStatus
        case appId, instanceName, publisher, objectId
    }

    public static let typePrefix = "#microsoft.graph.security."

    /// The same evidence under another id. An alert gives each of its own one.
    func identified(_ id: String) -> AlertEvidence {
        AlertEvidence(id: id, kind: kind, roles: roles, verdict: verdict, remediationStatus: remediationStatus, createdDateTime: createdDateTime)
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Where it sat in the response, until the alert that holds it gives it a better one.
        id = "evidence:" + decoder.codingPath.map { $0.intValue.map(String.init) ?? $0.stringValue }.joined(separator: "/")
        roles = try c.decodeIfPresent([String].self, forKey: .roles) ?? []
        verdict = try c.decodeIfPresent(Verdict.self, forKey: .verdict) ?? .unknown
        remediationStatus = try c.decodeIfPresent(String.self, forKey: .remediationStatus)
        createdDateTime = try c.decodeIfPresent(Date.self, forKey: .createdDateTime)

        let fullType = try c.decodeIfPresent(String.self, forKey: .odataType) ?? ""
        let typeName = fullType.hasPrefix(Self.typePrefix) ? String(fullType.dropFirst(Self.typePrefix.count)) : fullType
        switch typeName {
        case "userEvidence":
            kind = .user(try c.decodeIfPresent(UserAccount.self, forKey: .userAccount) ?? UserAccount())
        case "deviceEvidence":
            kind = .device(Device(
                deviceDnsName: try c.decodeIfPresent(String.self, forKey: .deviceDnsName),
                mdeDeviceId: try c.decodeIfPresent(String.self, forKey: .mdeDeviceId),
                azureAdDeviceId: try c.decodeIfPresent(String.self, forKey: .azureAdDeviceId),
                osPlatform: try c.decodeIfPresent(String.self, forKey: .osPlatform),
                osBuild: try c.decodeIfPresent(Int.self, forKey: .osBuild),
                healthStatus: try c.decodeIfPresent(String.self, forKey: .healthStatus),
                riskScore: try c.decodeIfPresent(String.self, forKey: .riskScore),
                onboardingStatus: try c.decodeIfPresent(String.self, forKey: .onboardingStatus)))
        case "mailboxEvidence":
            kind = .mailbox(Mailbox(
                displayName: try c.decodeIfPresent(String.self, forKey: .displayName),
                primaryAddress: try c.decodeIfPresent(String.self, forKey: .primaryAddress),
                userAccount: try c.decodeIfPresent(UserAccount.self, forKey: .userAccount)))
        case "ipEvidence":
            kind = .ip(
                address: try c.decodeIfPresent(String.self, forKey: .ipAddress) ?? "",
                country: try c.decodeIfPresent(String.self, forKey: .countryLetterCode))
        case "urlEvidence":
            kind = .url(try c.decodeIfPresent(String.self, forKey: .url) ?? "")
        case "fileEvidence":
            kind = .file(try c.decodeIfPresent(File.self, forKey: .fileDetails) ?? File())
        case "processEvidence":
            kind = .process(Process(
                processId: try c.decodeIfPresent(Int.self, forKey: .processId),
                processCommandLine: try c.decodeIfPresent(String.self, forKey: .processCommandLine),
                imageFile: try c.decodeIfPresent(File.self, forKey: .imageFile),
                userAccount: try c.decodeIfPresent(UserAccount.self, forKey: .userAccount),
                detectionStatus: try c.decodeIfPresent(String.self, forKey: .detectionStatus)))
        case "cloudApplicationEvidence":
            kind = .cloudApplication(
                name: try c.decodeIfPresent(String.self, forKey: .displayName),
                appId: Self.looseString(c, .appId))
        case "oauthApplicationEvidence":
            kind = .oauthApplication(
                name: try c.decodeIfPresent(String.self, forKey: .displayName),
                appId: Self.looseString(c, .appId),
                publisher: try c.decodeIfPresent(String.self, forKey: .publisher))
        default:
            kind = .other(typeName: typeName.isEmpty ? "evidence" : typeName)
        }
    }

    /// Graph sends an app id as a number on one evidence type and a string on another.
    private static func looseString(_ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys) -> String? {
        if let number = try? c.decodeIfPresent(Int.self, forKey: key) { return String(number) }
        return try? c.decodeIfPresent(String.self, forKey: key)
    }

    /// Encoded for fixtures and tests only; the app never sends evidence anywhere.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(roles, forKey: .roles)
        try c.encode(verdict, forKey: .verdict)
        try c.encodeIfPresent(remediationStatus, forKey: .remediationStatus)
        try c.encodeIfPresent(createdDateTime, forKey: .createdDateTime)
        switch kind {
        case .user(let account):
            try c.encode(Self.typePrefix + "userEvidence", forKey: .odataType)
            try c.encode(account, forKey: .userAccount)
        case .device(let device):
            try c.encode(Self.typePrefix + "deviceEvidence", forKey: .odataType)
            try c.encodeIfPresent(device.deviceDnsName, forKey: .deviceDnsName)
            try c.encodeIfPresent(device.mdeDeviceId, forKey: .mdeDeviceId)
            try c.encodeIfPresent(device.azureAdDeviceId, forKey: .azureAdDeviceId)
            try c.encodeIfPresent(device.osPlatform, forKey: .osPlatform)
            try c.encodeIfPresent(device.osBuild, forKey: .osBuild)
            try c.encodeIfPresent(device.healthStatus, forKey: .healthStatus)
            try c.encodeIfPresent(device.riskScore, forKey: .riskScore)
            try c.encodeIfPresent(device.onboardingStatus, forKey: .onboardingStatus)
        case .mailbox(let mailbox):
            try c.encode(Self.typePrefix + "mailboxEvidence", forKey: .odataType)
            try c.encodeIfPresent(mailbox.displayName, forKey: .displayName)
            try c.encodeIfPresent(mailbox.primaryAddress, forKey: .primaryAddress)
            try c.encodeIfPresent(mailbox.userAccount, forKey: .userAccount)
        case .ip(let address, let country):
            try c.encode(Self.typePrefix + "ipEvidence", forKey: .odataType)
            try c.encode(address, forKey: .ipAddress)
            try c.encodeIfPresent(country, forKey: .countryLetterCode)
        case .url(let url):
            try c.encode(Self.typePrefix + "urlEvidence", forKey: .odataType)
            try c.encode(url, forKey: .url)
        case .file(let file):
            try c.encode(Self.typePrefix + "fileEvidence", forKey: .odataType)
            try c.encode(file, forKey: .fileDetails)
        case .process(let process):
            try c.encode(Self.typePrefix + "processEvidence", forKey: .odataType)
            try c.encodeIfPresent(process.processId, forKey: .processId)
            try c.encodeIfPresent(process.processCommandLine, forKey: .processCommandLine)
            try c.encodeIfPresent(process.imageFile, forKey: .imageFile)
            try c.encodeIfPresent(process.userAccount, forKey: .userAccount)
            try c.encodeIfPresent(process.detectionStatus, forKey: .detectionStatus)
        case .cloudApplication(let name, let appId):
            try c.encode(Self.typePrefix + "cloudApplicationEvidence", forKey: .odataType)
            try c.encodeIfPresent(name, forKey: .displayName)
            try c.encodeIfPresent(appId, forKey: .appId)
        case .oauthApplication(let name, let appId, let publisher):
            try c.encode(Self.typePrefix + "oauthApplicationEvidence", forKey: .odataType)
            try c.encodeIfPresent(name, forKey: .displayName)
            try c.encodeIfPresent(appId, forKey: .appId)
            try c.encodeIfPresent(publisher, forKey: .publisher)
        case .other(let typeName):
            try c.encode(Self.typePrefix + typeName, forKey: .odataType)
        }
    }

    // MARK: - presentation

    public var kindTitle: String { kind.title }

    /// The one line that identifies the item.
    public var label: String {
        switch kind {
        case .user(let account):                   return account.label
        case .device(let device):                  return device.deviceDnsName ?? device.azureAdDeviceId ?? device.mdeDeviceId ?? "Unknown device"
        case .mailbox(let mailbox):                return mailbox.primaryAddress ?? mailbox.displayName ?? mailbox.userAccount?.label ?? "Unknown mailbox"
        case .ip(let address, _):                  return address.isEmpty ? "Unknown address" : address
        case .url(let url):                        return url.isEmpty ? "Unknown URL" : url
        case .file(let file):                      return file.fileName ?? file.sha256 ?? "Unknown file"
        case .process(let process):                return process.imageFile?.fileName ?? process.processCommandLine ?? "Unknown process"
        case .cloudApplication(let name, let id):  return name ?? id ?? "Unknown cloud app"
        case .oauthApplication(let name, let id, _): return name ?? id ?? "Unknown OAuth app"
        case .other(let typeName):                 return Self.humanize(typeName)
        }
    }

    /// The names of the people it carries, beside the address its label shows, so the
    /// list's search finds a person by name as well as by address.
    var personNames: [String] {
        switch kind {
        case .user(let account):    return [account.displayName].compactMap { $0 }
        case .mailbox(let mailbox): return [mailbox.displayName, mailbox.userAccount?.displayName].compactMap { $0 }
        case .process(let process): return [process.userAccount?.displayName].compactMap { $0 }
        default:                    return []
        }
    }

    /// The second line, when there is something worth saying.
    public var detail: String? {
        switch kind {
        case .user(let account):
            if let displayName = account.displayName, displayName != account.label { return displayName }
            return nil
        case .device(let device):
            return [device.osPlatform, device.riskScore.map { "risk " + $0 }, device.healthStatus]
                .compactMap { $0 }.joined(separator: ", ").nonEmpty
        case .mailbox(let mailbox):
            return mailbox.displayName != mailbox.label ? mailbox.displayName : nil
        case .ip(_, let country):
            return country
        case .url:
            return nil
        case .file(let file):
            return file.filePath ?? file.filePublisher
        case .process(let process):
            return process.processCommandLine
        case .cloudApplication(_, let appId):
            return appId
        case .oauthApplication(_, let appId, let publisher):
            return [publisher, appId].compactMap { $0 }.joined(separator: ", ").nonEmpty
        case .other:
            return "Open the incident in the Defender portal for the detail."
        }
    }

    /// The sign-in address, when this evidence is a person, for the Sign-in Triage link.
    public var userPrincipalName: String? {
        switch kind {
        case .user(let account):    return account.userPrincipalName
        case .mailbox(let mailbox): return mailbox.userAccount?.userPrincipalName ?? mailbox.primaryAddress
        case .process(let process): return process.userAccount?.userPrincipalName
        default:                    return nil
        }
    }

    /// The host name, when this evidence is a device, for the device list link.
    public var deviceHostName: String? {
        if case .device(let device) = kind { return device.hostName }
        return nil
    }

    /// `kubernetesPodEvidence` reads as "Kubernetes pod".
    static func humanize(_ typeName: String) -> String {
        let base = typeName.hasSuffix("Evidence") ? String(typeName.dropLast("Evidence".count)) : typeName
        var words: [String] = []
        var current = ""
        for ch in base {
            if ch.isUppercase, !current.isEmpty {
                words.append(current)
                current = String(ch).lowercased()
            } else {
                current.append(ch)
            }
        }
        if !current.isEmpty { words.append(current) }
        guard let first = words.first else { return typeName }
        return ([first.prefix(1).uppercased() + first.dropFirst()] + words.dropFirst()).joined(separator: " ")
    }
}

extension AlertEvidence.Mailbox {
    var label: String { primaryAddress ?? displayName ?? userAccount?.label ?? "Unknown mailbox" }
}

extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}

// MARK: - filters

/// What the list shows. Open only by default: the resolved ones are the portal's history,
/// not the phone's job.
public struct SecurityFilter: Sendable, Equatable {
    public enum SeverityFloor: String, Sendable, Equatable, CaseIterable, Identifiable {
        case all
        case mediumAndUp
        case highOnly
        public var id: String { rawValue }
        public var label: String {
            switch self {
            case .all:         return "All severities"
            case .mediumAndUp: return "Medium and up"
            case .highOnly:    return "High only"
            }
        }
        public var minimum: SecuritySeverity {
            switch self {
            case .all:         return .unknown
            case .mediumAndUp: return .medium
            case .highOnly:    return .high
            }
        }
    }

    public var openOnly: Bool
    public var severity: SeverityFloor

    public init(openOnly: Bool = true, severity: SeverityFloor = .all) {
        self.openOnly = openOnly
        self.severity = severity
    }

    public static let standard = SecurityFilter()

    public func apply(_ incidents: [SecurityIncident]) -> [SecurityIncident] {
        incidents.filter { incident in
            (!openOnly || incident.isOpen) && incident.severity >= severity.minimum
        }
    }
}

// MARK: - scopes and errors

/// The delegated scopes this module asks for. Spec section 5.
public enum SecurityScopes {
    /// Incidents with their alerts expanded, which carries the evidence.
    public static let incidents = "SecurityIncident.Read.All"
    /// The alert list on its own. Held in reserve and not requested: the expanded
    /// incident carries the alerts, and a scope nobody needs is a scope nobody consents to.
    public static let alerts = "SecurityAlert.Read.All"

    /// Requested when the module is first opened.
    public static let module = [incidents]
}

public enum SecurityError: Error, Sendable, Equatable {
    case consentRequired
    case notAuthorized
    case throttled(retryAfter: TimeInterval?)
    case serviceUnavailable(status: Int)
    case transport(status: Int)
    case decodeFailure
    case cancelled

    public init(_ error: GraphError) {
        switch error {
        case .consentRequired:                 self = .consentRequired
        case .notAuthorized:                   self = .notAuthorized
        case .notFound:                        self = .transport(status: 404)
        case .badRequest:                      self = .transport(status: 400)
        case .throttled(let retryAfter):       self = .throttled(retryAfter: retryAfter)
        case .serviceUnavailable(let status):  self = .serviceUnavailable(status: status)
        case .transport(let status):           self = .transport(status: status)
        case .decodeFailure:                   self = .decodeFailure
        case .cancelled:                       self = .cancelled
        }
    }
}
