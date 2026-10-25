import Foundation

// Tenant pulse: the screen an administrator opens every morning. Spec section 3.6.
//
// Four cards, four Graph surfaces, each read-only and each able to fail on its own:
// service health, Message Center, things that expire, and Secure Score. The models keep
// Graph's names so the portal and the app read the same, and every enum tolerates a value
// Microsoft adds later by falling through to a string.

// MARK: - service health

/// One subscribed service and its current status, from healthOverviews.
public struct ServiceHealthOverview: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let service: String
    /// Graph's serviceHealthStatus value, such as `serviceOperational` or `serviceDegradation`.
    public let status: String

    public init(id: String, service: String, status: String) {
        self.id = id
        self.service = service
        self.status = status
    }

    public var isOperational: Bool { status == "serviceOperational" }

    public var statusLabel: String { TenantPulseVocabulary.healthStatusLabel(status) }
}

/// An incident or advisory, from issues.
public struct ServiceIssue: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let title: String?
    public let service: String?
    public let feature: String?
    /// `incident` or `advisory`.
    public let classification: String?
    public let status: String?
    public let startDateTime: Date?
    public let lastModifiedDateTime: Date?
    public let isResolved: Bool?
    public let impactDescription: String?

    public init(id: String, title: String?, service: String?, feature: String? = nil, classification: String?,
                status: String?, startDateTime: Date?, lastModifiedDateTime: Date?, isResolved: Bool?,
                impactDescription: String?) {
        self.id = id
        self.title = title
        self.service = service
        self.feature = feature
        self.classification = classification
        self.status = status
        self.startDateTime = startDateTime
        self.lastModifiedDateTime = lastModifiedDateTime
        self.isResolved = isResolved
        self.impactDescription = impactDescription
    }

    public var isIncident: Bool { classification?.lowercased() == "incident" }
    public var isActive: Bool { isResolved != true }
}

public struct ServiceHealthReport: Sendable, Equatable {
    public let overviews: [ServiceHealthOverview]
    /// Unresolved issues, newest change first.
    public let activeIssues: [ServiceIssue]

    public init(overviews: [ServiceHealthOverview], activeIssues: [ServiceIssue]) {
        self.overviews = overviews
        self.activeIssues = activeIssues
    }

    public var degraded: [ServiceHealthOverview] { overviews.filter { !$0.isOperational } }
    public var operationalCount: Int { overviews.count - degraded.count }
}

// MARK: - Message Center

public struct ServiceMessage: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let title: String?
    /// `planForChange`, `stayInformed`, `preventOrFixIssue`. Graph has sent these
    /// capitalised in samples; compare case-insensitively.
    public let category: String?
    /// `normal`, `high`, `critical`.
    public let severity: String?
    public let isMajorChange: Bool?
    public let actionRequiredByDateTime: Date?
    public let startDateTime: Date?
    public let lastModifiedDateTime: Date?
    public let services: [String]?
    public let tags: [String]?

    public init(id: String, title: String?, category: String?, severity: String? = nil, isMajorChange: Bool?,
                actionRequiredByDateTime: Date?, startDateTime: Date? = nil, lastModifiedDateTime: Date?,
                services: [String]? = nil, tags: [String]? = nil) {
        self.id = id
        self.title = title
        self.category = category
        self.severity = severity
        self.isMajorChange = isMajorChange
        self.actionRequiredByDateTime = actionRequiredByDateTime
        self.startDateTime = startDateTime
        self.lastModifiedDateTime = lastModifiedDateTime
        self.services = services
        self.tags = tags
    }

    public var isActionRequired: Bool {
        actionRequiredByDateTime != nil || category?.lowercased() == "preventorfixissue"
    }
    public var isPlanForChange: Bool { category?.lowercased() == "planforchange" }

    /// What the card shows: action required, plan for change, or a major change. Stay
    /// informed posts without a deadline are noise for somebody on call.
    public var isWorthShowing: Bool {
        isActionRequired || isPlanForChange || isMajorChange == true
    }

    public var categoryLabel: String { TenantPulseVocabulary.messageCategoryLabel(category) }
}

public enum MessageOrdering {
    /// Deadlines first, soonest first; then major changes; then by last change, newest first.
    public static func sort(_ messages: [ServiceMessage]) -> [ServiceMessage] {
        messages.sorted { a, b in
            switch (a.actionRequiredByDateTime, b.actionRequiredByDateTime) {
            case let (x?, y?) where x != y: return x < y
            case (_?, nil): return true
            case (nil, _?): return false
            default:
                if (a.isMajorChange ?? false) != (b.isMajorChange ?? false) { return a.isMajorChange ?? false }
                return (a.lastModifiedDateTime ?? .distantPast) > (b.lastModifiedDateTime ?? .distantPast)
            }
        }
    }
}

// MARK: - expiring items

/// Something with an end date that pages somebody when it passes.
public struct ExpiringItem: Sendable, Equatable, Identifiable, Hashable {
    public enum Kind: String, Sendable, CaseIterable {
        case appSecret
        case appCertificate
        case samlCertificate
        case applePushCertificate
        case vppToken

        public var label: String {
            switch self {
            case .appSecret:            return "App registration secret"
            case .appCertificate:       return "App registration certificate"
            case .samlCertificate:      return "SAML signing certificate"
            case .applePushCertificate: return "Apple MDM push certificate"
            case .vppToken:             return "Apple VPP token"
            }
        }
    }

    public let id: String
    public let kind: Kind
    /// The app, service principal, Apple ID or organization it belongs to.
    public let owner: String
    /// The credential's own name or identifier, when it has one.
    public let detail: String?
    public let expiresAt: Date

    public init(id: String, kind: Kind, owner: String, detail: String?, expiresAt: Date) {
        self.id = id
        self.kind = kind
        self.owner = owner
        self.detail = detail
        self.expiresAt = expiresAt
    }

    public func daysLeft(now: Date = Date()) -> Int {
        Int((expiresAt.timeIntervalSince(now) / 86_400).rounded(.down))
    }

    public enum Bucket: Int, Sendable, CaseIterable, Comparable {
        case expired
        case within30Days
        case within90Days
        case later

        public static func < (lhs: Bucket, rhs: Bucket) -> Bool { lhs.rawValue < rhs.rawValue }

        public var label: String {
            switch self {
            case .expired:      return "Expired"
            case .within30Days: return "Within 30 days"
            case .within90Days: return "Within 90 days"
            case .later:        return "Later"
            }
        }
    }

    public func bucket(now: Date = Date()) -> Bucket {
        let seconds = expiresAt.timeIntervalSince(now)
        if seconds < 0 { return .expired }
        if seconds <= 30 * 86_400 { return .within30Days }
        if seconds <= 90 * 86_400 { return .within90Days }
        return .later
    }
}

public enum ExpiryWindow {
    /// What the card shows: anything expiring within 90 days, and anything that expired in
    /// the last 30, because a secret that lapsed last week is still the reason for a page.
    public static func relevant(_ items: [ExpiringItem], now: Date = Date()) -> [ExpiringItem] {
        items
            .filter { $0.expiresAt <= now.addingTimeInterval(90 * 86_400) && $0.expiresAt >= now.addingTimeInterval(-30 * 86_400) }
            .sorted { $0.expiresAt < $1.expiresAt }
    }
}

// MARK: - Secure Score

public struct SecureScoreSnapshot: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let createdDateTime: Date?
    public let currentScore: Double?
    public let maxScore: Double?
    public let controlScores: [ControlScore]?

    public struct ControlScore: Codable, Sendable, Equatable {
        public let controlCategory: String?
        public let controlName: String?
        public let score: Double?
        public init(controlCategory: String?, controlName: String?, score: Double?) {
            self.controlCategory = controlCategory
            self.controlName = controlName
            self.score = score
        }
    }

    public init(id: String, createdDateTime: Date?, currentScore: Double?, maxScore: Double?, controlScores: [ControlScore]?) {
        self.id = id
        self.createdDateTime = createdDateTime
        self.currentScore = currentScore
        self.maxScore = maxScore
        self.controlScores = controlScores
    }

    /// The identity part of the score: the sum of the controls Microsoft files under
    /// Identity. There is no separate endpoint for it; this is how the portal's Identity
    /// Secure Score is built.
    public var identityScore: Double? {
        guard let controls = controlScores else { return nil }
        let identity = controls.filter { $0.controlCategory?.lowercased() == "identity" }
        guard !identity.isEmpty else { return nil }
        return identity.reduce(0) { $0 + ($1.score ?? 0) }
    }
}

public struct SecureScoreSummary: Sendable, Equatable {
    public let latest: SecureScoreSnapshot
    /// Every dated snapshot that came back, newest first, the latest included. Graph
    /// keeps one per day, so thirty-one of them cover a month.
    public let history: [SecureScoreSnapshot]

    public init(latest: SecureScoreSnapshot, history: [SecureScoreSnapshot]) {
        self.latest = latest
        self.history = history
    }

    /// The snapshot nearest to `daysBack` days before the latest, when there is one that
    /// is at least half that distance away. A comparison against yesterday labelled
    /// "thirty days" would be a lie.
    public func comparison(daysBack: Int) -> SecureScoreSnapshot? {
        guard let latestDate = latest.createdDateTime, daysBack > 0 else { return nil }
        let target = latestDate.addingTimeInterval(-Double(daysBack) * 86_400)
        let candidate = history.dropFirst().min { a, b in
            abs(a.createdDateTime!.timeIntervalSince(target)) < abs(b.createdDateTime!.timeIntervalSince(target))
        }
        guard let candidate else { return nil }
        let distance = latestDate.timeIntervalSince(candidate.createdDateTime!)
        return distance >= Double(daysBack) * 86_400 / 2 ? candidate : nil
    }

    public func change(overDays days: Int) -> Double? {
        guard let now = latest.currentScore, let then = comparison(daysBack: days)?.currentScore else { return nil }
        return now - then
    }

    public func identityChange(overDays days: Int) -> Double? {
        guard let now = latest.identityScore, let then = comparison(daysBack: days)?.identityScore else { return nil }
        return now - then
    }

    /// The seven-day comparison, the card's default.
    public var weekAgo: SecureScoreSnapshot? { comparison(daysBack: 7) }
    public var change: Double? { change(overDays: 7) }
    public var identityChange: Double? { identityChange(overDays: 7) }

    /// Orders the dated snapshots newest first and keeps them all.
    public static func make(from snapshots: [SecureScoreSnapshot]) -> SecureScoreSummary? {
        let dated = snapshots.filter { $0.createdDateTime != nil }.sorted { $0.createdDateTime! > $1.createdDateTime! }
        guard let latest = dated.first else { return nil }
        return SecureScoreSummary(latest: latest, history: dated)
    }
}

// MARK: - vocabulary

public enum TenantPulseVocabulary {
    public static func healthStatusLabel(_ status: String) -> String {
        switch status {
        case "serviceOperational":          return "Operational"
        case "investigating":               return "Investigating"
        case "restoringService":            return "Restoring service"
        case "verifyingService":            return "Verifying service"
        case "serviceRestored":             return "Service restored"
        case "postIncidentReviewPublished": return "Post-incident review published"
        case "serviceDegradation":          return "Service degradation"
        case "serviceInterruption":         return "Service interruption"
        case "extendedRecovery":            return "Extended recovery"
        case "falsePositive":               return "False positive"
        case "investigationSuspended":      return "Investigation suspended"
        case "resolved":                    return "Resolved"
        case "mitigatedExternal", "mitigated": return "Mitigated"
        case "resolvedExternal":            return "Resolved"
        case "confirmed":                   return "Confirmed"
        case "reported":                    return "Reported"
        default:                            return status
        }
    }

    public static func messageCategoryLabel(_ category: String?) -> String {
        switch category?.lowercased() {
        case "planforchange":     return "Plan for change"
        case "stayinformed":      return "Stay informed"
        case "preventorfixissue": return "Prevent or fix issue"
        default:                  return category ?? "Message"
        }
    }
}
