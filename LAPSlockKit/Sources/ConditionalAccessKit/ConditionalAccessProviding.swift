import Foundation
import AuthKit

// The seam between the Conditional Access screens and Microsoft Graph, so the screens can
// be built and reviewed against demo data (App Store Review Guideline 2.1) and tested
// without a tenant.

public protocol ConditionalAccessProviding: Sendable {
    /// Every policy in the tenant, newest change first.
    func policies() async throws -> [ConditionalAccessPolicy]
    /// Display names for the ids a policy points at. Best effort: a reference that could
    /// not be resolved is simply absent, and the caller shows the id instead.
    func names(for references: Set<DirectoryReference>) async throws -> [DirectoryReference: String]
    /// Directory audit entries that touched one policy, newest first.
    func changes(forPolicyId policyId: String) async throws -> [PolicyChange]
    /// Drops cached names. Called on sign-out and tenant switch.
    func reset() async
}

/// One line of "who changed this".
public struct PolicyChange: Sendable, Equatable, Identifiable {
    public let id: String
    /// Graph's activity name, such as "Update conditional access policy".
    public let activity: String
    public let at: Date?
    /// Who did it: a user principal name, a display name, or an application name.
    public let actor: String?
    /// `success` or `failure`, as Graph reports it.
    public let result: String?
    /// Names of the properties the entry says changed, as Graph lists them.
    public let changedProperties: [String]

    public init(id: String, activity: String, at: Date?, actor: String?, result: String?, changedProperties: [String]) {
        self.id = id
        self.activity = activity
        self.at = at
        self.actor = actor
        self.result = result
        self.changedProperties = changedProperties
    }
}

public enum ConditionalAccessError: Error, Sendable, Equatable {
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

/// The delegated scopes this module asks for, and when. Spec section 5.
public enum ConditionalAccessScopes {
    /// The policies and named locations.
    public static let policies = "Policy.Read.All"
    /// Resolving the users, groups, roles and applications a policy names.
    public static let directory = "Directory.Read.All"
    /// The directory audit log, for "who changed this". Requested only when that is
    /// tapped, never when the module opens.
    public static let auditLog = "AuditLog.Read.All"

    /// Requested when the module is first opened.
    public static let module = [policies, directory]
    /// Requested on the first "who changed this".
    public static let changes = [auditLog, directory]
}
