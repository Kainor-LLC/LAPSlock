import Foundation
import AuthKit
import ActionGateKit
import PrivilegedAccessKit

// PIM approvals, phase 4 step A, pulled forward from phase 5 so the Apple Watch has a
// decision to make. Requests waiting for the signed-in admin's approval, for directory
// roles and for PIM groups, and the approve or deny that answers one.
//
// Approving is a write, so it goes through the action runner at the confirm tier with a
// justification. No role template is required up front: the approver is whoever the
// role's policy names, so Graph decides, and the gate turns a 403 into plain words.
//
// Where Microsoft put it: the lists are v1.0 for both. Deciding a group request is v1.0.
// Deciding a directory role request exists only on beta, so those two calls are pinned to
// beta and the Graph change watch carries them.
//
// Imports Foundation, AuthKit, ActionGateKit and PrivilegedAccessKit (for the consented
// scope names). The isolation guard keeps CredentialKit out of its link graph.

public enum ApprovalScopes {
    /// The same scopes activation already consents; approving needs nothing new.
    public static let roles = PrivilegedAccessGraph.roleActivateScope
    public static let groups = PrivilegedAccessGraph.groupActivateScope
    public static let module = [roles, groups]
}

public struct PendingApproval: Sendable, Equatable, Identifiable {
    public enum Kind: String, Sendable, Equatable { case role, group }

    /// The schedule request's id.
    public let id: String
    public let kind: Kind
    public let approvalId: String
    public let requester: String
    public let requesterUPN: String?
    /// The role or the group.
    public let target: String
    /// For a group: member or owner.
    public let access: String?
    public let justification: String?
    public let ticket: String?
    public let requested: Date?
    public let start: Date?
    /// ISO 8601 duration as Graph sent it, "PT8H".
    public let duration: String?
    public let end: Date?

    public init(id: String, kind: Kind, approvalId: String, requester: String, requesterUPN: String?, target: String,
                access: String? = nil, justification: String?, ticket: String?, requested: Date?, start: Date?,
                duration: String?, end: Date? = nil) {
        self.id = id
        self.kind = kind
        self.approvalId = approvalId
        self.requester = requester
        self.requesterUPN = requesterUPN
        self.target = target
        self.access = access
        self.justification = justification
        self.ticket = ticket
        self.requested = requested
        self.start = start
        self.duration = duration
        self.end = end
    }

    /// "Global Reader", "Ops On-Call (PIM), member".
    public var targetLabel: String { access.map { target + ", " + $0 } ?? target }

    /// "8 hours", "30 minutes", "until 27 Oct 18:00", or nil.
    public var durationText: String? {
        if let duration, let text = Self.words(isoDuration: duration) { return text }
        return nil
    }

    static func words(isoDuration: String) -> String? {
        guard isoDuration.hasPrefix("P") else { return nil }
        var days = 0, hours = 0, minutes = 0
        var number = ""
        var inTime = false
        for ch in isoDuration.dropFirst() {
            if ch == "T" { inTime = true; continue }
            if ch.isNumber { number.append(ch); continue }
            let n = Int(number) ?? 0
            number = ""
            switch ch {
            case "D": days = n
            case "H": hours = n
            case "M": if inTime { minutes = n }
            default: break
            }
        }
        var parts: [String] = []
        if days > 0 { parts.append(days == 1 ? "1 day" : String(days) + " days") }
        if hours > 0 { parts.append(hours == 1 ? "1 hour" : String(hours) + " hours") }
        if minutes > 0 { parts.append(minutes == 1 ? "1 minute" : String(minutes) + " minutes") }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }
}

public enum ApprovalDecision: String, Sendable, Equatable {
    case approve = "Approve"
    case deny = "Deny"

    public var title: String { self == .approve ? "Approve" : "Deny" }
}

public enum ApprovalsError: Error, Sendable, Equatable {
    case consentRequired
    case notAuthorized
    case unavailable
    case nothingToDecide

    public var message: String {
        switch self {
        case .consentRequired: return "This organization hasn't granted TenantKeep the PIM permissions yet. Turn on role activation in Settings, under Actions and Permissions."
        case .notAuthorized:   return "Your account can't read PIM approvals here."
        case .unavailable:     return "Microsoft Entra isn't answering right now. Try again shortly."
        case .nothingToDecide: return "This request no longer needs your decision. Someone may have answered it already."
        }
    }
}

public protocol ApprovalsProviding: Sendable {
    func pending() async throws -> [PendingApproval]
    /// The decision sheet opened: finds my stage now, so the tap sends at once. Nil when
    /// there is something to decide or it could not tell; the error when there is not.
    func prepare(_ approval: PendingApproval) async -> ApprovalsError?
    func decide(_ approval: PendingApproval, _ decision: ApprovalDecision, justification: String) async -> ActionOutcome
    func lastLogEntry(requestId: String) async -> ShiftLogEntry?
}

public extension ApprovalsProviding {
    func prepare(_ approval: PendingApproval) async -> ApprovalsError? { nil }
}

// MARK: - wire models

struct RequestRecord: Decodable, Sendable {
    struct Principal: Decodable, Sendable { let displayName: String?; let userPrincipalName: String? }
    struct Named: Decodable, Sendable { let displayName: String? }
    struct Schedule: Decodable, Sendable {
        struct Expiration: Decodable, Sendable { let duration: String?; let endDateTime: Date? }
        let startDateTime: Date?
        let expiration: Expiration?
    }
    struct Ticket: Decodable, Sendable { let ticketNumber: String?; let ticketSystem: String? }

    let id: String
    let approvalId: String?
    let status: String?
    let justification: String?
    let createdDateTime: Date?
    let accessId: String?
    let principal: Principal?
    let roleDefinition: Named?
    let group: Named?
    let scheduleInfo: Schedule?
    let ticketInfo: Ticket?

    func model(_ kind: PendingApproval.Kind) -> PendingApproval? {
        guard let approvalId, !approvalId.isEmpty, (status ?? "PendingApproval") == "PendingApproval" else { return nil }
        let ticket = [ticketInfo?.ticketSystem, ticketInfo?.ticketNumber].compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: " ")
        return PendingApproval(
            id: id, kind: kind, approvalId: approvalId,
            requester: principal?.displayName ?? principal?.userPrincipalName ?? "Someone",
            requesterUPN: principal?.userPrincipalName,
            target: (kind == .role ? roleDefinition?.displayName : group?.displayName) ?? (kind == .role ? "A directory role" : "A PIM group"),
            access: kind == .group ? accessId : nil,
            justification: justification?.isEmpty == false ? justification : nil,
            ticket: ticket.isEmpty ? nil : ticket,
            requested: createdDateTime,
            start: scheduleInfo?.startDateTime,
            duration: scheduleInfo?.expiration?.duration,
            end: scheduleInfo?.expiration?.endDateTime)
    }
}

struct StageRecord: Decodable, Sendable {
    let id: String
    let assignedToMe: Bool?
    let status: String?
}

// MARK: - live

public actor ApprovalsService: ApprovalsProviding {
    public static let rolePendingPath = "/roleManagement/directory/roleAssignmentScheduleRequests/filterByCurrentUser(on='approver')"
    public static let groupPendingPath = "/identityGovernance/privilegedAccess/group/assignmentScheduleRequests/filterByCurrentUser(on='approver')"

    private let graph: GraphClient
    private let runner: ActionRunner?
    private let log: any ShiftLogging
    private let tenantId: @Sendable () async -> String
    private let now: @Sendable () -> Date
    /// Set when Graph refused the trimmed `$expand` once; the session then expands whole objects.
    private var trimmedExpandRefused = false
    /// The stage found when a decision sheet opened, by request id, and when.
    private var prepared: [String: (path: String, readAt: Date)] = [:]
    /// How long a stage found at sheet open is used before it is looked up again.
    static let preparedFor: TimeInterval = 120

    public init(graph: GraphClient, runner: ActionRunner, log: any ShiftLogging, tenantId: @escaping @Sendable () async -> String,
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.graph = graph
        self.runner = runner
        self.log = log
        self.tenantId = tenantId
        self.now = now
    }

    /// Read only, for the background notification check. `decide` refuses without sending.
    public init(readingWith graph: GraphClient) {
        self.graph = graph
        self.runner = nil
        self.log = InMemoryShiftLog()
        self.tenantId = { "" }
        self.now = { Date() }
    }

    /// Both lists. One failing does not hide the other: a tenant may use PIM for roles and
    /// not for groups. Only when both fail does this throw.
    public func pending() async throws -> [PendingApproval] {
        async let roles = list(.role)
        async let groups = list(.group)
        let (r, g) = await (roles, groups)
        switch (r, g) {
        case (.failure(let error), .failure):
            throw error
        default:
            let all = ((try? r.get()) ?? []) + ((try? g.get()) ?? [])
            return all.sorted { ($0.requested ?? .distantPast) > ($1.requested ?? .distantPast) }
        }
    }

    /// What the list expands. Trimmed, the role or group comes with its name only: a whole
    /// role definition carries every permission it grants (OPTIMIZATION-PLAN.md, step G).
    /// The principal stays whole, because it is a directory object and its name is not a
    /// property Graph can select on that type.
    static func expand(_ kind: PendingApproval.Kind, trimmed: Bool) -> String {
        switch (kind, trimmed) {
        case (.role, true):   return "principal,roleDefinition($select=id,displayName)"
        case (.group, true):  return "principal,group($select=id,displayName)"
        case (.role, false):  return "principal,roleDefinition"
        case (.group, false): return "principal,group"
        }
    }

    private static func listRequest(_ kind: PendingApproval.Kind, query: [URLQueryItem], suffix: String = "") -> GraphRequest {
        GraphRequest(
            path: kind == .role ? rolePendingPath : groupPendingPath,
            template: (kind == .role ? "/roleManagement/directory/roleAssignmentScheduleRequests/filterByCurrentUser(approver)"
                                     : "/identityGovernance/privilegedAccess/group/assignmentScheduleRequests/filterByCurrentUser(approver)") + suffix,
            query: [URLQueryItem(name: "$filter", value: "status eq 'PendingApproval'")] + query,
            scopes: [kind == .role ? ApprovalScopes.roles : ApprovalScopes.groups])
    }

    private func list(_ kind: PendingApproval.Kind) async -> Result<[PendingApproval], ApprovalsError> {
        let trimmed = !trimmedExpandRefused
        let request = Self.listRequest(kind, query: [URLQueryItem(name: "$expand", value: Self.expand(kind, trimmed: trimmed))])
        do {
            let items = try await graph.collection(RequestRecord.self, from: request, maxPages: 3).items
            return .success(items.compactMap { $0.model(kind) })
        } catch GraphError.badRequest where trimmed {
            trimmedExpandRefused = true
            return await list(kind)
        } catch let error as GraphError {
            switch error {
            case .consentRequired: return .failure(.consentRequired)
            case .notAuthorized:   return .failure(.notAuthorized)
            default:               return .failure(.unavailable)
            }
        } catch {
            return .failure(.unavailable)
        }
    }

    /// The ids of the requests waiting for me, with nothing expanded: for the background
    /// check, which needs only to tell a new one. The same rules as `pending()`: one list
    /// failing does not hide the other, and a 400 falls back to that list's full read.
    public func pendingIds() async throws -> Set<String> {
        async let roles = ids(.role)
        async let groups = ids(.group)
        let (r, g) = await (roles, groups)
        switch (r, g) {
        case (.failure(let error), .failure):
            throw error
        default:
            return ((try? r.get()) ?? []).union((try? g.get()) ?? [])
        }
    }

    private struct IdRecord: Decodable, Sendable {
        let id: String
        let approvalId: String?
        let status: String?
    }

    private func ids(_ kind: PendingApproval.Kind) async -> Result<Set<String>, ApprovalsError> {
        let request = Self.listRequest(kind, query: [URLQueryItem(name: "$select", value: "id,approvalId,status")], suffix: "?ids")
        do {
            let items = try await graph.collection(IdRecord.self, from: request, maxPages: 3).items
            // The same test `RequestRecord.model` applies, so the keys match the full read's.
            return .success(Set(items.filter { !($0.approvalId ?? "").isEmpty && ($0.status ?? "PendingApproval") == "PendingApproval" }.map(\.id)))
        } catch GraphError.badRequest {
            return await list(kind).map { Set($0.map(\.id)) }
        } catch let error as GraphError {
            switch error {
            case .consentRequired: return .failure(.consentRequired)
            case .notAuthorized:   return .failure(.notAuthorized)
            default:               return .failure(.unavailable)
            }
        } catch {
            return .failure(.unavailable)
        }
    }

    private struct Route {
        let base: String
        let version: GraphAPIVersion
        let collection: String
        let scope: String
    }

    private static func route(_ approval: PendingApproval) -> Route {
        switch approval.kind {
        case .group:
            return Route(base: "/identityGovernance/privilegedAccess/group/assignmentApprovals/" + approval.approvalId,
                         version: .v1_0, collection: "stages", scope: ApprovalScopes.groups)
        case .role:
            return Route(base: "/roleManagement/directory/roleAssignmentApprovals/" + approval.approvalId,
                         version: .beta, collection: "steps", scope: ApprovalScopes.roles)
        }
    }

    private enum StageLookup {
        case mine(path: String)
        case nothingToDecide
        case unavailable
    }

    /// The stage or step assigned to me that is still in progress.
    private func lookUpStage(_ approval: PendingApproval) async -> StageLookup {
        let route = Self.route(approval)
        let lookup = GraphRequest(version: route.version, path: route.base + "/" + route.collection,
                                  template: approval.kind == .role ? "/roleManagement/directory/roleAssignmentApprovals/{id}/steps"
                                                                   : "/identityGovernance/privilegedAccess/group/assignmentApprovals/{id}/stages",
                                  scopes: [route.scope])
        guard let stages = try? await graph.collection(StageRecord.self, from: lookup, maxPages: 1).items else { return .unavailable }
        guard let mine = stages.first(where: { ($0.assignedToMe ?? false) && ($0.status ?? "") == "InProgress" }) else {
            return .nothingToDecide
        }
        return .mine(path: route.base + "/" + route.collection + "/" + mine.id)
    }

    public func prepare(_ approval: PendingApproval) async -> ApprovalsError? {
        switch await lookUpStage(approval) {
        case .mine(let path):
            prepared[approval.id] = (path, now())
            return nil
        case .nothingToDecide:
            prepared[approval.id] = nil
            return .nothingToDecide
        case .unavailable:
            return nil
        }
    }

    /// Sends the decision through the gate, to the stage found when the sheet opened if
    /// that was in the last `preparedFor` seconds, or to the one found now. A stage that
    /// changed meanwhile fails the write as it always could; it is never sent twice.
    public func decide(_ approval: PendingApproval, _ decision: ApprovalDecision, justification: String) async -> ActionOutcome {
        let stagePath: String
        if let ready = prepared[approval.id], now().timeIntervalSince(ready.readAt) < Self.preparedFor {
            stagePath = ready.path
        } else {
            switch await lookUpStage(approval) {
            case .mine(let path):   stagePath = path
            case .nothingToDecide:  return .failed(.refused(reason: ApprovalsError.nothingToDecide.message))
            case .unavailable:      return .failed(.notFound)
            }
        }
        prepared[approval.id] = nil
        let route = Self.route(approval)
        let action = Self.action(approval, decision, justification: justification, stagePath: stagePath, version: route.version, scope: route.scope)
        guard let runner else { return .failed(.refused(reason: "This copy of the service only reads.")) }
        return await runner.run(action)
    }

    static func action(_ approval: PendingApproval, _ decision: ApprovalDecision, justification: String,
                       stagePath: String, version: GraphAPIVersion, scope: String) -> WriteAction {
        let body = try? JSONSerialization.data(withJSONObject: ["reviewResult": decision.rawValue, "justification": justification])
        let template = approval.kind == .role ? "/roleManagement/directory/roleAssignmentApprovals/{id}/steps/{stepId}"
                                              : "/identityGovernance/privilegedAccess/group/assignmentApprovals/{id}/stages/{stageId}"
        let request = GraphRequest(method: .patch, version: version, path: stagePath, template: template, body: body, scopes: [scope])
        let words = decision == .approve
            ? "Approved. " + approval.requester + " can activate " + approval.targetLabel + " once every approver has agreed."
            : "Denied. " + approval.requester + " is told their request for " + approval.targetLabel + " was denied."
        return WriteAction(id: "pim." + decision.rawValue.lowercased(), title: decision.title + " PIM request",
                           tier: .confirm,
                           target: ActionTarget(label: approval.requester + " for " + approval.targetLabel, id: approval.id),
                           request: request, successCopy: words)
    }

    public func lastLogEntry(requestId: String) async -> ShiftLogEntry? {
        let tenant = await tenantId()
        return await log.entries(tenantId: tenant).first { $0.targetId == requestId }
    }
}

// MARK: - demo

public actor DemoApprovalsProvider: ApprovalsProviding {
    public static let tenant = "demo"
    private let latency: Duration
    private let log = InMemoryShiftLog()
    private var decided: Set<String> = []
    /// The second sample customer in demo mode: a calm tenant with nothing open, so switching
    /// customers shows different data and anything left over from the first stands out.
    private let quiet: Bool

    public init(latency: Duration = .milliseconds(600), quiet: Bool = false) {
        self.latency = latency
        self.quiet = quiet
    }

    public static func samples(now: Date = Date()) -> [PendingApproval] {
        [
            PendingApproval(id: "req-1", kind: .role, approvalId: "ap-1", requester: "Sam Reyes", requesterUPN: "sam.reyes@demo.example",
                            target: "Exchange Administrator", justification: "Mail flow rule for the finance migration, change CHG-2207",
                            ticket: "ServiceNow CHG-2207", requested: now.addingTimeInterval(-6 * 60), start: now, duration: "PT4H"),
            PendingApproval(id: "req-2", kind: .group, approvalId: "ap-2", requester: "Priya Natarajan", requesterUPN: "priya.n@demo.example",
                            target: "Ops On-Call (PIM)", access: "member", justification: "Covering the overnight rota",
                            ticket: nil, requested: now.addingTimeInterval(-38 * 60), start: now, duration: "PT8H"),
            PendingApproval(id: "req-3", kind: .role, approvalId: "ap-3", requester: "Jane Okafor", requesterUPN: "jane.okafor@demo.example",
                            target: "Global Administrator", justification: nil, ticket: nil,
                            requested: now.addingTimeInterval(-3 * 3600), start: now, duration: "PT1H")
        ]
    }

    /// The second sample customer's one request: someone the first customer does not have,
    /// so a switch that left the first customer's list on screen would show.
    public static func quietSamples(now: Date = Date()) -> [PendingApproval] {
        [
            PendingApproval(id: "req-f1", kind: .role, approvalId: "ap-f1", requester: "Alex Kim", requesterUPN: "alex.kim@fabrikam.example",
                            target: "Helpdesk Administrator", justification: "Password resets for the Monday intake",
                            ticket: nil, requested: now.addingTimeInterval(-12 * 60), start: now, duration: "PT2H")
        ]
    }

    public func pending() async throws -> [PendingApproval] {
        try? await Task.sleep(for: latency)
        return (quiet ? Self.quietSamples() : Self.samples()).filter { !decided.contains($0.id) }
    }

    public func decide(_ approval: PendingApproval, _ decision: ApprovalDecision, justification: String) async -> ActionOutcome {
        try? await Task.sleep(for: latency)
        decided.insert(approval.id)
        let action = ApprovalsService.action(approval, decision, justification: justification, stagePath: "/demo", version: .v1_0, scope: ApprovalScopes.roles)
        await log.append(ShiftLogEntry(at: Date(), tenantId: Self.tenant, actionId: action.id, actionTitle: action.title,
                                       targetLabel: action.target.label, targetId: approval.id, outcome: "requested", requestId: "demo"))
        return .requested(requestId: "demo")
    }

    public func lastLogEntry(requestId: String) async -> ShiftLogEntry? {
        await log.entries(tenantId: Self.tenant).first { $0.targetId == requestId }
    }
}
