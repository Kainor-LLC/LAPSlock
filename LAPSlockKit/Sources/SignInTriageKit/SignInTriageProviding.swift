import Foundation
import AuthKit

public protocol SignInTriageProviding: Sendable {
    /// People whose name or sign-in address starts with the text, at most ten.
    func searchUsers(prefix: String) async throws -> [DirectoryUser]
    /// Recent sign-ins for one person, newest first.
    func signIns(_ query: SignInQuery) async throws -> [SignInEvent]
}

/// What the screen asks for. Built once, so the filter string is testable on its own.
public struct SignInQuery: Sendable, Equatable {
    public var userPrincipalName: String
    public var failuresOnly: Bool
    public var last24Hours: Bool
    /// How many rows the screen shows.
    public var limit: Int

    public init(userPrincipalName: String, failuresOnly: Bool = false, last24Hours: Bool = false, limit: Int = 20) {
        self.userPrincipalName = userPrincipalName
        self.failuresOnly = failuresOnly
        self.last24Hours = last24Hours
        self.limit = limit
    }

    /// The OData filter. The sign-in address goes in with its quotes doubled, which is the
    /// only escaping OData string literals have, so an address containing a quote cannot
    /// change the shape of the query. Graph's `errorCode` supports `eq` only, so "failures
    /// only" is applied after the fetch rather than here.
    public func filter(now: Date = Date()) -> String {
        var clauses = ["userPrincipalName eq '" + Self.escape(userPrincipalName) + "'"]
        if last24Hours {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime]
            clauses.append("createdDateTime ge " + formatter.string(from: now.addingTimeInterval(-86_400)))
        }
        return clauses.joined(separator: " and ")
    }

    /// How many to fetch: more than the screen shows when failures are being filtered out
    /// afterwards, so a person with one failure among fifty successes still sees it.
    public var fetchCount: Int { failuresOnly ? max(limit * 5, 100) : limit }

    public func apply(_ events: [SignInEvent]) -> [SignInEvent] {
        let kept = failuresOnly ? events.filter(\.isFailure) : events
        return Array(kept.prefix(limit))
    }

    static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "'", with: "''")
    }
}

public enum SignInTriageError: Error, Sendable, Equatable {
    case consentRequired
    case notAuthorized
    /// The tenant has no Entra ID P1, which the sign-in log needs. Graph answers 403 for
    /// that too; the screen says both.
    case throttled(retryAfter: TimeInterval?)
    case serviceUnavailable(status: Int)
    case transport(status: Int)
    case decodeFailure
    case cancelled

    public init(_ error: GraphError) {
        switch error {
        case .consentRequired:                self = .consentRequired
        case .notAuthorized:                  self = .notAuthorized
        case .notFound:                       self = .transport(status: 404)
        case .badRequest:                     self = .transport(status: 400)
        case .throttled(let retryAfter):      self = .throttled(retryAfter: retryAfter)
        case .serviceUnavailable(let status): self = .serviceUnavailable(status: status)
        case .transport(let status):          self = .transport(status: status)
        case .decodeFailure:                  self = .decodeFailure
        case .cancelled:                      self = .cancelled
        }
    }
}

/// Scopes, verified against the Graph reference on 2026-10-25. Spec section 5 named
/// `AuditLog.Read.All` and `Directory.Read.All`; the reference lists only the first for
/// the sign-in log, user search takes the narrower `User.ReadBasic.All`, and the applied
/// Conditional Access policies are omitted unless the app may read policy, so that scope
/// joins. Risk columns need no scope of their own: they are on the sign-in record and come
/// back as `hidden` without P2.
public enum SignInTriageScopes {
    public static let signIns = "AuditLog.Read.All"
    public static let policies = "Policy.Read.All"
    public static let users = "User.ReadBasic.All"

    public static let module = [signIns, policies, users]
}
