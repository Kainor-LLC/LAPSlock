import Foundation
import AuthKit

// Tenant pulse over Microsoft Graph, through the shared GraphClient. Read-only.
//
// Every endpoint here is v1.0 and was checked against the reference before it was written:
//   healthOverviews, issues            ServiceHealth.Read.All
//   serviceAnnouncement/messages       ServiceMessage.Read.All
//   applications, servicePrincipals    Application.Read.All
//   applePushNotificationCertificate   DeviceManagementServiceConfig.Read.All
//   deviceAppManagement/vppTokens      DeviceManagementServiceConfig.Read.All
//   security/secureScores              SecurityEvents.Read.All
//
// Each request carries only its own scope, so a tenant that consented to four of the five
// sees four cards and one that says what it needs, rather than nothing.
//
// Two filters are not documented as supported and are tried, not relied on: `isResolved`
// on issues and `preferredSingleSignOnMode` on service principals. A 400 on either falls
// back to the unfiltered form, or to leaving SAML certificates out, with the fallback
// recorded in the result rather than hidden.
//
// The screen's reads ask for the fields the models decode, and Message Center for the
// card's rule, narrowest form first (OPTIMIZATION-PLAN.md, step G). A form Graph refuses
// with a 400 is not sent again for the life of this service, and the last form is always
// the plain read every tenant takes.

public actor TenantPulseService: TenantPulseProviding {

    private let graph: GraphClient
    /// By read, the index of the narrowest form this tenant has not refused.
    private var acceptedForm: [String: Int] = [:]

    public init(graph: GraphClient) {
        self.graph = graph
    }

    public static let healthOverviewsPath = "/admin/serviceAnnouncement/healthOverviews"
    public static let issuesPath = "/admin/serviceAnnouncement/issues"
    public static let messagesPath = "/admin/serviceAnnouncement/messages"
    public static let applicationsPath = "/applications"
    public static let servicePrincipalsPath = "/servicePrincipals"
    public static let applePushCertificatePath = "/deviceManagement/applePushNotificationCertificate"
    public static let vppTokensPath = "/deviceAppManagement/vppTokens"
    public static let secureScoresPath = "/security/secureScores"

    /// The ten fields `ServiceIssue` decodes, leaving out the posts each issue carries.
    static let issueFields = "id,title,service,feature,classification,status,startDateTime,lastModifiedDateTime,isResolved,impactDescription"
    /// The ten fields `ServiceMessage` decodes, leaving out the HTML body.
    static let messageFields = "id,title,category,severity,isMajorChange,actionRequiredByDateTime,startDateTime,lastModifiedDateTime,services,tags"
    /// `ServiceMessage.isWorthShowing` as Graph's filter. The phone applies the rule as
    /// well, so a tenant where Graph reads the filter more loosely shows nothing extra.
    static let worthShowingFilter = "actionRequiredByDateTime ne null or category eq 'preventOrFixIssue' or category eq 'planForChange' or isMajorChange eq true"
    /// A snapshot without its control scores, which are most of its size.
    static let scoreHistoryFields = "id,createdDateTime,currentScore,maxScore"

    /// The first of `forms` Graph accepts, narrowest first. A 400 moves on to the next and
    /// is remembered; the last form's 400 is thrown like any other error.
    private func firstAccepted<T: Decodable & Sendable>(
        _ type: T.Type, _ key: String, _ forms: [(request: GraphRequest, maxPages: Int)]
    ) async throws -> [T] {
        var index = min(acceptedForm[key, default: 0], forms.count - 1)
        while true {
            do {
                return try await graph.collection(T.self, from: forms[index].request, maxPages: forms[index].maxPages).items
            } catch GraphError.badRequest where index < forms.count - 1 {
                index += 1
                acceptedForm[key] = max(acceptedForm[key, default: 0], index)
            }
        }
    }

    // MARK: - health

    public func health() async throws -> ServiceHealthReport {
        do {
            async let overviews = graph.collection(
                ServiceHealthOverview.self,
                from: GraphRequest(path: Self.healthOverviewsPath, scopes: [TenantPulseScopes.health]),
                maxPages: 2)
            let issues = try await activeIssues()
            let report = ServiceHealthReport(
                overviews: try await overviews.items.sorted { $0.service < $1.service },
                activeIssues: issues)
            return report
        } catch let error as GraphError {
            throw TenantPulseError(error)
        }
    }

    /// Unresolved issues, newest change first. Tries the filter with the model's fields,
    /// then the filter alone; a tenant where Graph refuses both gets the last hundred
    /// issues filtered here.
    private func activeIssues() async throws -> [ServiceIssue] {
        let unresolved = URLQueryItem(name: "$filter", value: "isResolved eq false")
        let fields = URLQueryItem(name: "$select", value: Self.issueFields)
        let scopes = [TenantPulseScopes.health]
        let items = try await firstAccepted(ServiceIssue.self, "issues", [
            (GraphRequest(path: Self.issuesPath, template: Self.issuesPath + "?unresolved&select", query: [unresolved, fields], scopes: scopes), 2),
            (GraphRequest(path: Self.issuesPath, template: Self.issuesPath + "?unresolved", query: [unresolved], scopes: scopes), 2),
            (GraphRequest(path: Self.issuesPath, query: [URLQueryItem(name: "$top", value: "100")], scopes: scopes), 1),
        ])
        return items
            .filter(\.isActive)
            .sorted { ($0.lastModifiedDateTime ?? .distantPast) > ($1.lastModifiedDateTime ?? .distantPast) }
    }

    // MARK: - Message Center

    /// The card's messages, filtered by Graph where it can be, so a deadline older than the
    /// newest two hundred posts still reaches the card.
    public func messages() async throws -> [ServiceMessage] {
        let top = URLQueryItem(name: "$top", value: "100")
        let fields = URLQueryItem(name: "$select", value: Self.messageFields)
        let rule = URLQueryItem(name: "$filter", value: Self.worthShowingFilter)
        let scopes = [TenantPulseScopes.messages]
        do {
            let items = try await firstAccepted(ServiceMessage.self, "messages", [
                (GraphRequest(path: Self.messagesPath, template: Self.messagesPath + "?worthShowing&select", query: [rule, fields, top], scopes: scopes), 2),
                (GraphRequest(path: Self.messagesPath, template: Self.messagesPath + "?select", query: [fields, top], scopes: scopes), 2),
                (GraphRequest(path: Self.messagesPath, query: [top], scopes: scopes), 2),
            ])
            return MessageOrdering.sort(items.filter(\.isWorthShowing))
        } catch let error as GraphError {
            throw TenantPulseError(error)
        }
    }

    // MARK: - expiring

    public func expiringItems() async throws -> [ExpiringItem] {
        // The app registrations are the card. The rest are extras that fail quietly: a
        // tenant without Intune has no push certificate, and that is not an error. All
        // four start together; the extras used to wait for every page of the walk.
        async let saml = samlCertificates()
        async let push = applePushCertificate()
        async let vpp = vppTokens()
        let registrations = try await applicationCredentials()
        let extras = await [saml, push, vpp].flatMap { $0 }
        return (registrations + extras).sorted { $0.expiresAt < $1.expiresAt }
    }

    private struct ApplicationRecord: Decodable, Sendable {
        struct Credential: Decodable, Sendable {
            let keyId: String?
            let displayName: String?
            let endDateTime: Date?
        }
        let id: String
        let appId: String?
        let displayName: String?
        let passwordCredentials: [Credential]?
        let keyCredentials: [Credential]?
    }

    private func applicationCredentials() async throws -> [ExpiringItem] {
        let request = GraphRequest(
            path: Self.applicationsPath,
            query: [
                URLQueryItem(name: "$select", value: "id,appId,displayName,passwordCredentials,keyCredentials"),
                URLQueryItem(name: "$top", value: "999")
            ],
            scopes: [TenantPulseScopes.applications])
        do {
            let page = try await graph.collection(ApplicationRecord.self, from: request, maxPages: 10)
            return page.items.flatMap { app -> [ExpiringItem] in
                let owner = app.displayName ?? app.appId ?? app.id
                let secrets = (app.passwordCredentials ?? []).enumerated().compactMap { index, credential -> ExpiringItem? in
                    guard let end = credential.endDateTime else { return nil }
                    return ExpiringItem(
                        id: "secret:" + app.id + ":" + Self.credentialKey(credential.keyId, end: end, name: credential.displayName, index: index),
                        kind: .appSecret, owner: owner, detail: credential.displayName, expiresAt: end)
                }
                let certificates = (app.keyCredentials ?? []).enumerated().compactMap { index, credential -> ExpiringItem? in
                    guard let end = credential.endDateTime else { return nil }
                    return ExpiringItem(
                        id: "cert:" + app.id + ":" + Self.credentialKey(credential.keyId, end: end, name: credential.displayName, index: index),
                        kind: .appCertificate, owner: owner, detail: credential.displayName, expiresAt: end)
                }
                return secrets + certificates
            }
        } catch let error as GraphError {
            throw TenantPulseError(error)
        }
    }

    private struct ServicePrincipalRecord: Decodable, Sendable {
        struct Credential: Decodable, Sendable {
            let keyId: String?
            let displayName: String?
            let usage: String?
            let endDateTime: Date?
        }
        let id: String
        let displayName: String?
        let keyCredentials: [Credential]?
    }

    /// SAML signing certificates on enterprise apps. The filter is an advanced query, so it
    /// carries the consistency header; if Graph refuses it, the card goes without.
    private func samlCertificates() async -> [ExpiringItem] {
        let request = GraphRequest(
            path: Self.servicePrincipalsPath,
            template: Self.servicePrincipalsPath + "?saml",
            query: [
                URLQueryItem(name: "$filter", value: "preferredSingleSignOnMode eq 'saml'"),
                URLQueryItem(name: "$select", value: "id,displayName,keyCredentials"),
                URLQueryItem(name: "$count", value: "true")
            ],
            headers: ["ConsistencyLevel": "eventual"],
            scopes: [TenantPulseScopes.applications])
        guard let page = try? await graph.collection(ServicePrincipalRecord.self, from: request, maxPages: 5) else { return [] }
        return page.items.flatMap { principal -> [ExpiringItem] in
            let owner = principal.displayName ?? principal.id
            // One certificate appears twice on a SAML app, as Sign and Verify. One row.
            let signing = (principal.keyCredentials ?? []).filter { $0.usage?.lowercased() != "verify" }
            return signing.enumerated().compactMap { index, credential in
                guard let end = credential.endDateTime else { return nil }
                return ExpiringItem(
                    id: "saml:" + principal.id + ":" + Self.credentialKey(credential.keyId, end: end, name: credential.displayName, index: index),
                    kind: .samlCertificate, owner: owner, detail: credential.displayName, expiresAt: end)
            }
        }
    }

    /// A credential's key for its id. Graph's keyId when there is one; otherwise one built
    /// from what does not change between reads. A random fallback made the background
    /// check announce the same credential as new on every run.
    static func credentialKey(_ keyId: String?, end: Date, name: String?, index: Int) -> String {
        if let keyId, !keyId.isEmpty { return keyId }
        return "end" + String(Int(end.timeIntervalSince1970)) + ":" + (name ?? "") + ":" + String(index)
    }

    private struct ApplePushCertificate: Decodable, Sendable {
        let id: String?
        let appleIdentifier: String?
        let expirationDateTime: Date?
    }

    private func applePushCertificate() async -> [ExpiringItem] {
        let request = GraphRequest(path: Self.applePushCertificatePath, scopes: [TenantPulseScopes.deviceConfig])
        guard let certificate = try? await graph.decode(ApplePushCertificate.self, from: request),
              let end = certificate.expirationDateTime
        else { return [] }
        return [ExpiringItem(
            id: "apns:" + (certificate.id ?? "certificate"),
            kind: .applePushCertificate,
            owner: certificate.appleIdentifier ?? "Apple MDM push certificate",
            detail: nil,
            expiresAt: end)]
    }

    private struct VppToken: Decodable, Sendable {
        let id: String
        let organizationName: String?
        let appleId: String?
        let state: String?
        let expirationDateTime: Date?
    }

    private func vppTokens() async -> [ExpiringItem] {
        let request = GraphRequest(path: Self.vppTokensPath, scopes: [TenantPulseScopes.deviceConfig])
        guard let page = try? await graph.collection(VppToken.self, from: request, maxPages: 2) else { return [] }
        return page.items.compactMap { token in
            guard let end = token.expirationDateTime else { return nil }
            return ExpiringItem(
                id: "vpp:" + token.id,
                kind: .vppToken,
                owner: token.organizationName ?? token.appleId ?? "VPP token",
                detail: token.appleId,
                expiresAt: end)
        }
    }

    // MARK: - Secure Score

    /// One snapshot per day; thirty-one covers the screen's thirty-day comparison. The
    /// history comes without control scores, and the snapshots the screen compares are
    /// read again whole, because the identity score is built from their controls. A
    /// tenant that refuses either read gets the thirty-one whole snapshots, as before.
    public func secureScore() async throws -> SecureScoreSummary? {
        do {
            return try await leanSecureScore(snapshots: 31, comparing: SecureScoreSummary.windows)
        } catch let error as GraphError {
            throw TenantPulseError(error)
        }
    }

    private func leanSecureScore(snapshots: Int, comparing windows: [Int]) async throws -> SecureScoreSummary? {
        guard acceptedForm["scores", default: 0] == 0 else { return try await secureScore(snapshots: snapshots) }
        let lean = GraphRequest(
            path: Self.secureScoresPath,
            template: Self.secureScoresPath + "?select",
            query: [URLQueryItem(name: "$top", value: String(snapshots)), URLQueryItem(name: "$select", value: Self.scoreHistoryFields)],
            scopes: [TenantPulseScopes.security])
        let history: [SecureScoreSnapshot]
        do {
            history = try await graph.collection(SecureScoreSnapshot.self, from: lean, maxPages: 1).items
        } catch GraphError.badRequest {
            acceptedForm["scores"] = 1
            return try await secureScore(snapshots: snapshots)
        }
        guard let summary = SecureScoreSummary.make(from: history) else { return nil }
        let compared = Set(([summary.latest] + windows.compactMap { summary.comparison(daysBack: $0) }).map(\.id))
        let whole: [String: SecureScoreSnapshot]
        do {
            whole = try await withThrowingTaskGroup(of: SecureScoreSnapshot.self, returning: [String: SecureScoreSnapshot].self) { group in
                for id in compared { group.addTask { try await self.snapshot(id) } }
                var found: [String: SecureScoreSnapshot] = [:]
                for try await snapshot in group { found[snapshot.id] = snapshot }
                return found
            }
        } catch GraphError.badRequest, GraphError.notFound {
            acceptedForm["scores"] = 1
            return try await secureScore(snapshots: snapshots)
        }
        return SecureScoreSummary.make(from: history.map { whole[$0.id] ?? $0 })
    }

    /// One whole snapshot, control scores included.
    private func snapshot(_ id: String) async throws -> SecureScoreSnapshot {
        try await graph.decode(SecureScoreSnapshot.self, from: GraphRequest(
            path: Self.secureScoresPath + "/" + id,
            template: Self.secureScoresPath + "/{id}",
            scopes: [TenantPulseScopes.security]))
    }

    /// The latest `snapshots` days, whole. For the few the background check (two, for
    /// yesterday's change), the watch and the Mac menu (one) need, a single read is
    /// cheaper than the lean history and a second read.
    public func secureScore(snapshots: Int) async throws -> SecureScoreSummary? {
        let request = GraphRequest(
            path: Self.secureScoresPath,
            query: [URLQueryItem(name: "$top", value: String(max(1, snapshots)))],
            scopes: [TenantPulseScopes.security])
        do {
            let page = try await graph.collection(SecureScoreSnapshot.self, from: request, maxPages: 1)
            return SecureScoreSummary.make(from: page.items)
        } catch let error as GraphError {
            throw TenantPulseError(error)
        }
    }
}

// MARK: - lean reads

// For the background check and the watch, which need a few fields where the screens need
// everything (OPTIMIZATION-PLAN.md, step F). Each asks Graph for less and, where Graph
// refuses the narrower request with a 400, falls back to the screen's own read, so a tenant
// is never worse off than before. The screens keep the full reads.
extension TenantPulseService {

    /// Unresolved issues with the fields a background key needs, without the posts each
    /// issue carries. The same issues `health()` reports as active.
    public func activeIssueStamps() async throws -> [ServiceIssue] {
        let request = GraphRequest(
            path: Self.issuesPath,
            template: Self.issuesPath + "?unresolved&select",
            query: [
                URLQueryItem(name: "$filter", value: "isResolved eq false"),
                URLQueryItem(name: "$select", value: "id,classification,isResolved,lastModifiedDateTime"),
            ],
            scopes: [TenantPulseScopes.health])
        do {
            return try await graph.collection(ServiceIssue.self, from: request, maxPages: 2).items.filter(\.isActive)
        } catch GraphError.badRequest {
            return try await health().activeIssues
        } catch let error as GraphError {
            throw TenantPulseError(error)
        }
    }

    /// Messages whose action is due between now and `horizon`, with only the id and the
    /// date, rather than two hundred posts with their HTML bodies.
    public func messageDeadlines(from now: Date, through horizon: Date) async throws -> [ServiceMessage] {
        let request = GraphRequest(
            path: Self.messagesPath,
            template: Self.messagesPath + "?deadlines",
            query: [
                URLQueryItem(name: "$filter", value: "actionRequiredByDateTime ge " + Self.stamp(now)
                             + " and actionRequiredByDateTime le " + Self.stamp(horizon)),
                URLQueryItem(name: "$select", value: "id,actionRequiredByDateTime"),
                URLQueryItem(name: "$top", value: "100"),
            ],
            scopes: [TenantPulseScopes.messages])
        do {
            return try await graph.collection(ServiceMessage.self, from: request, maxPages: 2).items
        } catch GraphError.badRequest {
            return try await messages()
        } catch let error as GraphError {
            throw TenantPulseError(error)
        }
    }

    /// The per-service status only, for the watch's count of degraded services.
    public func healthOverviews() async throws -> [ServiceHealthOverview] {
        do {
            return try await graph.collection(
                ServiceHealthOverview.self,
                from: GraphRequest(path: Self.healthOverviewsPath, scopes: [TenantPulseScopes.health]),
                maxPages: 2).items
        } catch let error as GraphError {
            throw TenantPulseError(error)
        }
    }

    static func stamp(_ date: Date) -> String { filterStamp.string(from: date) }

    private static let filterStamp: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}
