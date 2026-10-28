import Foundation
import AuthKit
import PrivilegedAccessKit

// The one path for a write. Role gate, then the call, then the log, and every outcome
// handed back as something the screen can act on. The confirmation tier is enforced by
// the screen, which has the sheet, the keyboard and the app lock; the runner's part is to
// refuse anything that is not a POST, to send exactly once, and to write the log line
// whatever happened.
//
// Never retries. A 429 on a write is a failure with a retry-after, not a loop. A claims
// challenge is handed back as `.challenged`; the screen asks the person, and only their tap
// calls `resume`, which sends once more with the claims satisfied and then stops.

public actor ActionRunner {

    private let graph: GraphClient
    private let gate: any RoleGateChecking
    private let log: any ShiftLogging
    private let tenantId: @Sendable () async -> String
    private let now: @Sendable () -> Date
    /// Set when the role check could not get a token for its scope, which is what a tenant
    /// that never opted in to PIM looks like. Every write then goes to Graph without the
    /// check, as it already did when the check failed, minus a silent token attempt each
    /// time. Cleared by `roleCheckMayWork()` once the opt-in is granted.
    private var roleCheckUnavailable = false

    public init(
        graph: GraphClient,
        gate: any RoleGateChecking,
        log: any ShiftLogging,
        tenantId: @escaping @Sendable () async -> String,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.graph = graph
        self.gate = gate
        self.log = log
        self.tenantId = tenantId
        self.now = now
    }

    /// Gate, send once, log.
    ///
    /// `checkingRoles: false` is for one change made of several writes, such as removing
    /// every sign-in method a person has: the caller runs `checkRoles` once for the whole
    /// change, then sends each write with this, and stops at the first refusal. Each write
    /// is still sent once and logged.
    public func run(_ action: WriteAction, checkingRoles: Bool = true) async -> ActionOutcome {
        guard action.request.method.isWrite else {
            return await record(action, .failed(.refused(reason: "A read is not a write action.")), requestId: nil)
        }
        if checkingRoles, let outcome = await preflight(action) {
            return await record(action, outcome, requestId: nil)
        }
        return await send(action, request: action.request)
    }

    /// The PIM opt-in was granted: the role check is tried again on the next write.
    public func roleCheckMayWork() {
        roleCheckUnavailable = false
    }

    /// After `.challenged`, and only on the person's tap: one more send with the claims,
    /// interactive so the tenant's MFA or authentication context can be satisfied.
    public func resume(_ action: WriteAction, satisfying challenge: ClaimsChallenge) async -> ActionOutcome {
        var request = action.request
        request.claims = challenge.json
        request.allowInteractive = true
        let outcome = await send(action, request: request)
        // A second challenge means re-authentication did not satisfy it, and asking again
        // would loop behind a prompt the person cannot escape.
        if case .challenged = outcome {
            return await record(action, .failed(.refused(reason: "Your organization asked for another sign-in step and it did not clear. Try again from the portal.")), requestId: nil)
        }
        return outcome
    }

    // MARK: - for the one write that does not pass through here

    /// The role gate on its own, for the Temporary Access Pass, which is issued on the
    /// credential path because its response is a credential this target must never hold.
    /// Same rule as `run`: eligible but not active comes back as `.needsActivation`; nil
    /// means go ahead.
    public func checkRoles(_ action: WriteAction) async -> ActionOutcome? {
        await preflight(action)
    }

    /// A shift-log line for a write made elsewhere, carrying no value from its response.
    public func log(_ action: WriteAction, outcome: ActionOutcome, requestId: String?) async {
        _ = await record(action, outcome, requestId: requestId)
    }

    // MARK: - gate

    private func preflight(_ action: WriteAction) async -> ActionOutcome? {
        guard !action.requiredRoleTemplateIds.isEmpty, !roleCheckUnavailable else { return nil }
        let required = Set(action.requiredRoleTemplateIds.map { $0.lowercased() })
        let active: Set<String>
        do {
            active = try await gate.activeRoleTemplateIds()
        } catch GraphError.consentRequired {
            roleCheckUnavailable = true
            return nil
        } catch {
            return nil
        }
        if !active.isDisjoint(with: required) { return nil }
        let eligible = await gate.eligibleAccess().filter { access in
            if case .directoryRole(let roleDefinitionId, _) = access.kind {
                return required.contains(roleDefinitionId.lowercased())
            }
            return false
        }
        // Nothing active and nothing eligible: a group may still carry the role, so let
        // Graph decide rather than refusing on a guess.
        return eligible.isEmpty ? nil : .needsActivation(eligible: eligible)
    }

    // MARK: - send

    private func send(_ action: WriteAction, request: GraphRequest) async -> ActionOutcome {
        // `readOnly` gives a POST a read's retries in the Graph client. A write carrying it
        // could be sent twice, so it is never sent at all.
        guard !request.readOnly else {
            return await record(action, .failed(.refused(reason: "A write cannot be marked as a read.")), requestId: nil)
        }
        let response: GraphResponse
        do {
            response = try await graph.sendUnvalidated(request)
        } catch let error as GraphError {
            return await record(action, .failed(Self.failure(for: error)), requestId: nil)
        } catch {
            return await record(action, .failed(.transport(status: -1)), requestId: nil)
        }
        let outcome = await classify(response)
        return await record(action, outcome, requestId: response.requestId)
    }

    private func classify(_ response: GraphResponse) async -> ActionOutcome {
        switch response.status {
        case 200...299:
            return .requested(requestId: response.requestId)
        case 401:
            if let header = Self.header("WWW-Authenticate", in: response.headers),
               let challenge = ClaimsChallenge.parse(wwwAuthenticate: header) {
                return .challenged(challenge)
            }
            return .failed(.consentRequired)
        case 403:
            return .notAuthorized(eligible: await gate.eligibleAccess())
        case 400:
            if let message = Self.errorMessage(response.data),
               let challenge = ClaimsChallenge.parse(graphErrorMessage: message) {
                return .challenged(challenge)
            }
            return .failed(.badRequest(code: Self.errorCode(response.data)))
        case 404:
            return .failed(.notFound)
        case 429:
            let retryAfter = Self.header("Retry-After", in: response.headers).flatMap { TimeInterval($0.trimmingCharacters(in: .whitespaces)) }
            return .failed(.throttled(retryAfter: retryAfter))
        case 500...599:
            return .failed(.serviceUnavailable(status: response.status))
        default:
            return .failed(.transport(status: response.status))
        }
    }

    private func record(_ action: WriteAction, _ outcome: ActionOutcome, requestId: String?) async -> ActionOutcome {
        let tenant = await tenantId()
        await log.append(ShiftLogEntry(
            at: now(),
            tenantId: tenant,
            actionId: action.id,
            actionTitle: action.title,
            targetLabel: action.target.label,
            targetId: action.target.id,
            outcome: Self.word(for: outcome),
            requestId: requestId))
        return outcome
    }

    static func word(for outcome: ActionOutcome) -> String {
        switch outcome {
        case .requested:        return "requested"
        case .needsActivation:  return "needsActivation"
        case .notAuthorized:    return "notAuthorized"
        case .challenged:       return "challenged"
        case .failed(let f):
            switch f {
            case .consentRequired:    return "failed: consent required"
            case .notFound:           return "failed: not found"
            case .badRequest(let c):  return "failed: bad request" + (c.map { " " + $0 } ?? "")
            case .throttled:          return "failed: throttled"
            case .serviceUnavailable: return "failed: service unavailable"
            case .transport:          return "failed: transport"
            case .cancelled:          return "cancelled"
            case .refused:            return "refused"
            }
        }
    }

    static func failure(for error: GraphError) -> ActionFailure {
        switch error {
        case .consentRequired:                return .consentRequired
        case .notAuthorized:                  return .transport(status: 403)
        case .notFound:                       return .notFound
        case .badRequest(let code):           return .badRequest(code: code)
        case .throttled(let retryAfter):      return .throttled(retryAfter: retryAfter)
        case .serviceUnavailable(let status): return .serviceUnavailable(status: status)
        case .transport(let status):          return .transport(status: status)
        case .decodeFailure:                  return .transport(status: -1)
        case .cancelled:                      return .cancelled
        }
    }

    static func header(_ name: String, in headers: [String: String]) -> String? {
        headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    static func errorCode(_ data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let error = json["error"] as? [String: Any],
              let code = error["code"] as? String, !code.isEmpty else { return nil }
        return code
    }

    static func errorMessage(_ data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let error = json["error"] as? [String: Any] else { return nil }
        return error["message"] as? String
    }
}
