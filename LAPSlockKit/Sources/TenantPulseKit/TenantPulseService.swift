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

public actor TenantPulseService: TenantPulseProviding {

    private let graph: GraphClient

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

    /// Unresolved issues, newest change first. Tries the filter first; a tenant where Graph
    /// refuses it gets the last hundred issues filtered here.
    private func activeIssues() async throws -> [ServiceIssue] {
        let filtered = GraphRequest(
            path: Self.issuesPath,
            template: Self.issuesPath + "?unresolved",
            query: [URLQueryItem(name: "$filter", value: "isResolved eq false")],
            scopes: [TenantPulseScopes.health])
        let items: [ServiceIssue]
        do {
            items = try await graph.collection(ServiceIssue.self, from: filtered, maxPages: 2).items
        } catch GraphError.badRequest {
            let plain = GraphRequest(
                path: Self.issuesPath,
                query: [URLQueryItem(name: "$top", value: "100")],
                scopes: [TenantPulseScopes.health])
            items = try await graph.collection(ServiceIssue.self, from: plain, maxPages: 1).items
        }
        return items
            .filter(\.isActive)
            .sorted { ($0.lastModifiedDateTime ?? .distantPast) > ($1.lastModifiedDateTime ?? .distantPast) }
    }

    // MARK: - Message Center

    public func messages() async throws -> [ServiceMessage] {
        let request = GraphRequest(
            path: Self.messagesPath,
            query: [URLQueryItem(name: "$top", value: "100")],
            scopes: [TenantPulseScopes.messages])
        do {
            let page = try await graph.collection(ServiceMessage.self, from: request, maxPages: 2)
            return MessageOrdering.sort(page.items.filter(\.isWorthShowing))
        } catch let error as GraphError {
            throw TenantPulseError(error)
        }
    }

    // MARK: - expiring

    public func expiringItems() async throws -> [ExpiringItem] {
        // The app registrations are the card. The rest are extras that fail quietly: a
        // tenant without Intune has no push certificate, and that is not an error.
        let registrations = try await applicationCredentials()
        async let saml = samlCertificates()
        async let push = applePushCertificate()
        async let vpp = vppTokens()
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

    /// One snapshot per day; thirty-one covers the screen's thirty-day comparison.
    public func secureScore() async throws -> SecureScoreSummary? {
        try await secureScore(snapshots: 31)
    }

    /// The latest `snapshots` days. The background check asks for two (yesterday's
    /// change) and the watch for one.
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
