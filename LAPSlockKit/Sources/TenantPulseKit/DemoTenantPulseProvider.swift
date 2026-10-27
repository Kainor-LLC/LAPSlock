import Foundation

// Demo tenant pulse. One degraded service with an active incident, an advisory, Message
// Center posts with and without deadlines, expiring items in every bucket and of every
// kind, and a Secure Score that moved this week.

public actor DemoTenantPulseProvider: TenantPulseProviding {

    private let latency: Duration
    private let now: Date
    /// The second sample customer in demo mode: a calm tenant with nothing open, so switching
    /// customers shows different data and anything left over from the first stands out.
    private let quiet: Bool
    /// The large demo tenant: 200 Message Center posts and 600 expiring items.
    private let large: Bool

    public init(latency: Duration = .milliseconds(400), now: Date = Date(), quiet: Bool = false, large: Bool = false) {
        self.latency = latency
        self.now = now
        self.quiet = quiet
        self.large = large
    }

    static func days(_ d: Double, from now: Date) -> Date { now.addingTimeInterval(d * 86_400) }

    public func health() async throws -> ServiceHealthReport {
        try await Task.sleep(for: latency)
        return quiet ? Self.quietHealth : Self.health(now: now)
    }

    public func messages() async throws -> [ServiceMessage] {
        try await Task.sleep(for: latency)
        if quiet { return [] }
        let messages = large ? Self.largeMessages(now: now) : Self.messages(now: now)
        return MessageOrdering.sort(messages.filter(\.isWorthShowing))
    }

    public func expiringItems() async throws -> [ExpiringItem] {
        try await Task.sleep(for: latency)
        if quiet { return [] }
        let items = large ? Self.largeExpiringItems(now: now) : Self.expiring(now: now)
        return items.sorted { $0.expiresAt < $1.expiresAt }
    }

    public func secureScore() async throws -> SecureScoreSummary? {
        try await Task.sleep(for: latency)
        return SecureScoreSummary.make(from: quiet ? Self.quietScores(now: now) : Self.scores(now: now))
    }

    /// Every service operational and nothing open.
    public static let quietHealth = ServiceHealthReport(
        overviews: [
            .init(id: "Exchange", service: "Exchange Online", status: "serviceOperational"),
            .init(id: "Intune", service: "Microsoft Intune", status: "serviceOperational"),
            .init(id: "OSDPPlatform", service: "Microsoft 365 suite", status: "serviceOperational"),
            .init(id: "SharePoint", service: "SharePoint Online", status: "serviceOperational"),
            .init(id: "microsoftteams", service: "Microsoft Teams", status: "serviceOperational"),
            .init(id: "Entra", service: "Microsoft Entra", status: "serviceOperational"),
        ],
        activeIssues: [])

    /// A flat month at 842, so the score card differs from the first customer's at a glance.
    public static func quietScores(now: Date) -> [SecureScoreSnapshot] {
        (0...30).map { day in
            SecureScoreSnapshot(
                id: "quiet-score-" + String(day),
                createdDateTime: days(-Double(day), from: now),
                currentScore: 842, maxScore: 1176,
                controlScores: [.init(controlCategory: "Identity", controlName: "AdminMFAV2", score: 120)])
        }
    }

    public static func health(now: Date) -> ServiceHealthReport {
        ServiceHealthReport(
            overviews: [
                .init(id: "Exchange", service: "Exchange Online", status: "serviceDegradation"),
                .init(id: "Intune", service: "Microsoft Intune", status: "serviceOperational"),
                .init(id: "OSDPPlatform", service: "Microsoft 365 suite", status: "serviceOperational"),
                .init(id: "SharePoint", service: "SharePoint Online", status: "serviceOperational"),
                .init(id: "microsoftteams", service: "Microsoft Teams", status: "restoringService"),
                .init(id: "Entra", service: "Microsoft Entra", status: "serviceOperational"),
            ],
            activeIssues: [
                ServiceIssue(
                    id: "EX900001", title: "Users may be unable to send email from Outlook on the web",
                    service: "Exchange Online", feature: "E-Mail and calendar access",
                    classification: "incident", status: "serviceDegradation",
                    startDateTime: days(-0.2, from: now), lastModifiedDateTime: days(-0.05, from: now),
                    isResolved: false,
                    impactDescription: "Users may be intermittently unable to send email from Outlook on the web. Desktop Outlook is not affected."),
                ServiceIssue(
                    id: "TM700002", title: "Some users may see delays joining meetings",
                    service: "Microsoft Teams", feature: "Meetings",
                    classification: "incident", status: "restoringService",
                    startDateTime: days(-1.1, from: now), lastModifiedDateTime: days(-0.3, from: now),
                    isResolved: false,
                    impactDescription: "A subset of users may experience delays of up to a minute when joining scheduled meetings."),
                ServiceIssue(
                    id: "IT500003", title: "Advisory: device compliance reports may be delayed",
                    service: "Microsoft Intune", feature: "Reporting",
                    classification: "advisory", status: "investigating",
                    startDateTime: days(-2, from: now), lastModifiedDateTime: days(-1, from: now),
                    isResolved: false,
                    impactDescription: "Compliance reports in the admin center may lag the device state by several hours."),
            ])
    }

    public static func messages(now: Date) -> [ServiceMessage] {
        [
            ServiceMessage(
                id: "MC900101", title: "(Updated) Retirement of legacy MFA and SSPR policies",
                category: "planForChange", severity: "high", isMajorChange: true,
                actionRequiredByDateTime: days(12, from: now), startDateTime: days(-30, from: now),
                lastModifiedDateTime: days(-2, from: now), services: ["Microsoft Entra"], tags: ["Admin impact"]),
            ServiceMessage(
                id: "MC900102", title: "Action required: update the Apple MDM push certificate before it expires",
                category: "preventOrFixIssue", severity: "critical", isMajorChange: false,
                actionRequiredByDateTime: days(25, from: now), startDateTime: days(-5, from: now),
                lastModifiedDateTime: days(-5, from: now), services: ["Microsoft Intune"], tags: ["Admin impact"]),
            ServiceMessage(
                id: "MC900103", title: "Teams: new meeting join experience rolling out",
                category: "planForChange", severity: "normal", isMajorChange: false,
                actionRequiredByDateTime: nil, startDateTime: days(-8, from: now),
                lastModifiedDateTime: days(-8, from: now), services: ["Microsoft Teams"], tags: ["User impact"]),
            ServiceMessage(
                id: "MC900104", title: "Outlook: new icon",
                category: "stayInformed", severity: "normal", isMajorChange: false,
                actionRequiredByDateTime: nil, startDateTime: days(-3, from: now),
                lastModifiedDateTime: days(-3, from: now), services: ["Exchange Online"], tags: []),
            ServiceMessage(
                id: "MC900105", title: "Conditional Access: authentication strength changes for external users",
                category: "planForChange", severity: "high", isMajorChange: true,
                actionRequiredByDateTime: days(45, from: now), startDateTime: days(-14, from: now),
                lastModifiedDateTime: days(-1, from: now), services: ["Microsoft Entra"], tags: ["Admin impact"]),
        ]
    }

    public static func expiring(now: Date) -> [ExpiringItem] {
        [
            ExpiringItem(id: "secret:hr", kind: .appSecret, owner: "HR Sync", detail: "Prod secret 2025", expiresAt: days(-4, from: now)),
            ExpiringItem(id: "apns:1", kind: .applePushCertificate, owner: "mdm@demo.example", detail: nil, expiresAt: days(25, from: now)),
            ExpiringItem(id: "secret:ticketing", kind: .appSecret, owner: "Ticketing Connector", detail: "Client secret", expiresAt: days(9, from: now)),
            ExpiringItem(id: "saml:payroll", kind: .samlCertificate, owner: "Payroll Portal", detail: "CN=Microsoft Azure Federated SSO Certificate", expiresAt: days(41, from: now)),
            ExpiringItem(id: "cert:backup", kind: .appCertificate, owner: "Backup Agent", detail: "CN=backup-agent", expiresAt: days(62, from: now)),
            ExpiringItem(id: "vpp:edu", kind: .vppToken, owner: "Demo Org", detail: "apps@demo.example", expiresAt: days(77, from: now)),
            ExpiringItem(id: "secret:reporting", kind: .appSecret, owner: "Reporting", detail: "Dashboard secret", expiresAt: days(140, from: now)),
        ]
    }

    public static func scores(now: Date) -> [SecureScoreSnapshot] {
        func snapshot(_ daysAgo: Double, _ score: Double, identity: Double) -> SecureScoreSnapshot {
            SecureScoreSnapshot(
                id: "score-\(Int(daysAgo))",
                createdDateTime: days(-daysAgo, from: now),
                currentScore: score, maxScore: 1176,
                controlScores: [
                    .init(controlCategory: "Identity", controlName: "AdminMFAV2", score: identity * 0.6),
                    .init(controlCategory: "Identity", controlName: "MFARegistrationV2", score: identity * 0.4),
                    .init(controlCategory: "Device", controlName: "IntuneCompliance", score: 40),
                ])
        }
        // A month of daily scores: 612 today, 598 a week ago, 571 a month ago, so both
        // windows show a change and they differ.
        let recent: [(Double, Double, Double)] = [
            (0, 612, 180), (1, 612, 180), (2, 605, 173), (3, 605, 173), (4, 605, 173),
            (5, 598, 166), (6, 598, 166), (7, 598, 166), (8, 590, 158), (9, 590, 158),
        ]
        var snapshots = recent.map { snapshot($0.0, $0.1, identity: $0.2) }
        for day in 10...30 {
            let drift = Double(30 - day)
            snapshots.append(snapshot(Double(day), 571 + drift * 0.9, identity: 145 + drift * 0.6))
        }
        return snapshots
    }
}
