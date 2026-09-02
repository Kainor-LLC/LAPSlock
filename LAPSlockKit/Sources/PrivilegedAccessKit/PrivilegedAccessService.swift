import Foundation
import AuthKit

// The Graph client for PIM. Both surfaces, and the claims-challenge retry.
//
// THE RETRY IS THE WHOLE DESIGN. Graph refuses self-activation unless MFA was satisfied in
// the current session, and says so with a claims challenge. The flow is: attempt → 401 with
// a challenge → re-authenticate carrying those claims, which triggers whatever MFA the
// tenant requires → attempt once more. Exactly once more: a second challenge means
// re-authentication did not satisfy it, and trying again would loop forever behind a
// biometric prompt the user cannot escape.
//
// EVERY REQUEST HERE IS THE USER'S OWN. `selfActivate` acts on the caller's existing
// eligibility and nothing else. There is no code path in this module that can read, request
// or grant anybody else's access, and there should never be one.

public protocol PrivilegedAccessProviding: Sendable {
    func eligibleAccess() async throws -> [EligibleAccess]
    /// The tenant's activation rules for one piece of eligible access.
    func policy(for access: EligibleAccess) async -> ActivationPolicy
    func activate(
        _ access: EligibleAccess,
        justification: String,
        ticketNumber: String?,
        duration: String
    ) async throws -> ActivationOutcome
}

public struct PrivilegedAccessService: PrivilegedAccessProviding {

    private let auth: any AuthManaging
    private let session: URLSession
    private let base: String

    public init(
        auth: any AuthManaging,
        base: String = "https://graph.microsoft.com",
        session: URLSession? = nil
    ) {
        self.auth = auth
        self.base = base
        self.session = session ?? Self.makeSession()
    }

    /// Ephemeral: no disk cache, no cookie store. Nothing about a privileged operation is
    /// written to the app container by the networking layer.
    static func makeSession() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.urlCache = nil
        cfg.httpCookieAcceptPolicy = .never
        cfg.httpShouldSetCookies = false
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        cfg.timeoutIntervalForRequest = 30
        return URLSession(configuration: cfg)
    }

    // MARK: - reading eligibility

    /// Everything the signed-in user could activate, from both PIM surfaces.
    ///
    /// A failure on ONE surface does not fail the whole call. A tenant may use PIM for
    /// Groups and not roles, or the reverse, and one of the two scopes may be unconsented
    /// while the other is fine. Returning what we could read beats returning nothing —
    /// except when both fail, which is a real error and is thrown.
    public func eligibleAccess() async throws -> [EligibleAccess] {
        async let rolesResult = attemptList(.roles)
        async let groupsResult = attemptList(.groups)

        let roles = await rolesResult
        let groups = await groupsResult

        switch (roles, groups) {
        case (.failure(let error), .failure):
            throw error
        default:
            let combined = ActivationRequest.combined(
                roles: (try? roles.get()) ?? [],
                groups: (try? groups.get()) ?? [])
            guard !combined.isEmpty else { throw PrivilegedAccessError.noEligibleAccess }
            return combined
        }
    }

    /// One of the two PIM surfaces.
    ///
    /// A discriminator rather than four separate arguments, so the path, the `$expand`, the
    /// scope and the parser cannot drift apart. Reading a group schedule with the role
    /// parser would silently return an empty list, which reads as "no eligible access" —
    /// the exact failure that is hardest to notice.
    private enum Surface {
        case roles
        case groups

        var path: String {
            switch self {
            case .roles:  return PrivilegedAccessGraph.roleEligibilityPath
            case .groups: return PrivilegedAccessGraph.groupEligibilityPath
            }
        }

        /// `$expand` so Graph returns display names, not just ids. Without it every entry
        /// falls back to a generic label.
        var expand: String {
            switch self {
            case .roles:  return "roleDefinition"
            case .groups: return "group"
            }
        }

        var scope: String {
            switch self {
            case .roles:  return PrivilegedAccessGraph.roleReadScope
            case .groups: return PrivilegedAccessGraph.groupReadScope
            }
        }

        func parse(_ json: [String: Any]) -> [EligibleAccess] {
            switch self {
            case .roles:  return ActivationRequest.eligibleRoles(from: json)
            case .groups: return ActivationRequest.eligibleGroups(from: json)
            }
        }
    }

    private func attemptList(_ surface: Surface) async -> Result<[EligibleAccess], PrivilegedAccessError> {
        do {
            // Reading eligibility never needs interaction: it is a plain read, and a consent
            // prompt here would appear before the user has asked to activate anything.
            let token = try await auth.token(scopes: [surface.scope], allowInteractive: false)
            let request = Request.get(
                url(surface.path, [URLQueryItem(name: "$expand", value: surface.expand)]),
                token: token)
            let (data, response) = try await send(request)
            let json = try decode(data, response)
            return .success(surface.parse(json))
        } catch let error as PrivilegedAccessError {
            return .failure(error)
        } catch let error as AuthError {
            // interactionRequired matters as much as consentRequired here. A SILENT request
            // for a scope nobody has consented to throws interactionRequired, not
            // consentRequired — so mapping only the latter reported "not authorized" for
            // what is really "permission not granted yet", which points the user at the
            // wrong problem.
            switch error {
            case .consentRequired, .interactionRequired:
                return .failure(.consentRequired)
            default:
                return .failure(.notAuthorized)
            }
        } catch {
            return .failure(.transport)
        }
    }

    // MARK: - reading the policy

    /// Reads the activation rules the tenant has set for this access.
    ///
    /// **Never throws.** A policy read that fails leaves the UI exactly as it behaved before
    /// this existed — standard durations, justification asked for anyway. The read is here to
    /// stop offering choices the tenant will refuse; it must not become a new way for
    /// activation to be unavailable, particularly since the policy scopes may not be
    /// consented in a tenant where activation itself is fine.
    public func policy(for access: EligibleAccess) async -> ActivationPolicy {
        let scopeId: String
        let scopeType: String
        let scope: String

        switch access.kind {
        case .directoryRole(_, let directoryScopeId):
            scopeId = directoryScopeId
            scopeType = "DirectoryRole"
            scope = PrivilegedAccessGraph.rolePolicyReadScope
        case .group(let groupId, _):
            scopeId = groupId
            scopeType = "Group"
            scope = PrivilegedAccessGraph.groupPolicyReadScope
        }

        do {
            let token = try await auth.token(scopes: [scope], allowInteractive: false)
            let url = url(PrivilegedAccessGraph.policyPath, [
                URLQueryItem(name: "$filter", value: "scopeId eq '\(scopeId)' and scopeType eq '\(scopeType)'"),
                URLQueryItem(name: "$expand", value: "rules"),
            ])
            let (data, response) = try await send(.get(url, token: token))
            return ActivationPolicy.from(policiesResponse: try decode(data, response))
        } catch {
            return .unknown
        }
    }

    // MARK: - activating

    public func activate(
        _ access: EligibleAccess,
        justification: String,
        ticketNumber: String? = nil,
        duration: String = ActivationRequest.defaultDuration
    ) async throws -> ActivationOutcome {
        guard let principalId = await auth.currentAccount?.objectId, !principalId.isEmpty else {
            // The oid claim, not the MSAL account identifier. Without it there is no
            // principal to activate for, and guessing would target a nonexistent object.
            throw PrivilegedAccessError.notAuthorized
        }

        let prepared = ActivationRequest.selfActivate(
            access,
            principalId: principalId,
            justification: justification,
            duration: duration,
            ticketNumber: ticketNumber)

        // If the policy already told us an authentication context is required, carry the
        // claim on the FIRST attempt rather than waiting to be refused. Graph reports that
        // refusal as a plain 400, so the reactive path costs a round trip and a failure the
        // user sees momentarily; this avoids both when the policy could be read.
        let upfrontClaims = (try? await policy(for: access))?
            .authenticationContextClaim
            .map(Self.claimsRequest(forAcrs:)) ?? nil

        do {
            return try await post(prepared, claims: upfrontClaims)
        } catch PrivilegedAccessError.claimsChallenge(let challenge) {
            // Once, and only once. A second challenge means re-authentication did not
            // satisfy it, and retrying would loop behind a prompt the user cannot escape.
            return try await post(prepared, claims: challenge.json)
        }
    }

    private func post(_ prepared: ActivationRequest.Prepared, claims: String?) async throws -> ActivationOutcome {
        // Interactive: activation is an explicit user action, and the consent prompt for the
        // activation scope belongs here rather than at app launch.
        let token = try await auth.token(
            scopes: PrivilegedAccessGraph.activateScopes,
            claims: claims,
            allowInteractive: true)

        let body = try JSONSerialization.data(withJSONObject: prepared.json)
        let (data, response) = try await send(.post(url(prepared.path, []), token: token, body: body))
        let json = try decode(data, response)
        return ActivationRequest.outcome(from: json)
    }

    /// Builds the claims request for an `acrs` value, matching the shape Graph asks for when
    /// it refuses: `{"access_token":{"acrs":{"essential":true,"value":"c1"}}}`.
    static func claimsRequest(forAcrs value: String) -> String? {
        // Built with JSONSerialization rather than string interpolation, so a policy value
        // containing a quote cannot produce malformed JSON that MSAL then rejects.
        let object: [String: Any] = [
            "access_token": ["acrs": ["essential": true, "value": value]]
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - HTTP

    private enum Request {
        case get(URL, token: String)
        case post(URL, token: String, body: Data)

        var urlRequest: URLRequest {
            switch self {
            case .get(let url, let token):
                var r = URLRequest(url: url)
                r.httpMethod = "GET"
                r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                r.setValue("application/json", forHTTPHeaderField: "Accept")
                return r
            case .post(let url, let token, let body):
                var r = URLRequest(url: url)
                r.httpMethod = "POST"
                r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                r.setValue("application/json", forHTTPHeaderField: "Content-Type")
                r.setValue("application/json", forHTTPHeaderField: "Accept")
                r.httpBody = body
                return r
            }
        }
    }

    private func url(_ path: String, _ query: [URLQueryItem]) -> URL {
        var comps = URLComponents(string: base)!
        comps.path = path
        if !query.isEmpty { comps.queryItems = query }
        return comps.url!
    }

    private func send(_ request: Request) async throws -> (Data, HTTPURLResponse) {
        do {
            let (data, response) = try await session.data(for: request.urlRequest)
            guard let http = response as? HTTPURLResponse else { throw PrivilegedAccessError.transport }
            return (data, http)
        } catch let error as PrivilegedAccessError {
            throw error
        } catch {
            throw PrivilegedAccessError.transport
        }
    }

    /// Maps a response onto either JSON or a typed error.
    ///
    /// The claims challenge is checked FIRST, because it arrives as a 401 and would
    /// otherwise be indistinguishable from an ordinary expired token. Getting that order
    /// wrong is the difference between activation working and activation reporting "not
    /// authorized" forever.
    private func decode(_ data: Data, _ response: HTTPURLResponse) throws -> [String: Any] {
        if response.statusCode == 401 || response.statusCode == 403 {
            let header = response.value(forHTTPHeaderField: "WWW-Authenticate") ?? ""
            if let challenge = ClaimsChallenge.parse(wwwAuthenticate: header) {
                throw PrivilegedAccessError.claimsChallenge(challenge)
            }
        }

        switch response.statusCode {
        case 200...299:
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw PrivilegedAccessError.decodeFailure
            }
            return json
        case 401, 403:
            throw PrivilegedAccessError.notAuthorized
        case 400:
            let haystack = Self.graphErrorHaystack(data)

            // A CLAIMS CHALLENGE ARRIVES HERE, not as a 401. When a PIM policy requires a
            // Conditional Access authentication context, Graph answers 400 with
            // `RoleAssignmentRequestAcrsValidationFailed` and puts the required claim in the
            // message. Checked before anything else in this branch, because to every other
            // reading it is an indistinguishable bad request — which is exactly how it
            // presented before this existed.
            if haystack.contains("acrsvalidationfailed") || haystack.contains("acrs") {
                if let message = Self.graphErrorMessage(data),
                   let challenge = ClaimsChallenge.parse(graphErrorMessage: message) {
                    throw PrivilegedAccessError.claimsChallenge(challenge)
                }
                // The code said authentication context but no claim came with it. Retrying
                // would be guessing at what to ask for.
                throw PrivilegedAccessError.serviceError(status: 400, code: Self.graphErrorCode(data))
            }

            // Graph answers 400 for "role is already active", which is not a failure worth
            // an alarming message. Detected by the error code rather than by matching prose,
            // which is localised.
            if haystack.contains("roleassignmentexists") || haystack.contains("activeassignment") {
                throw PrivilegedAccessError.alreadyActive
            }
            throw PrivilegedAccessError.serviceError(status: 400, code: Self.graphErrorCode(data))
        default:
            throw PrivilegedAccessError.serviceError(
                status: response.statusCode, code: Self.graphErrorCode(data))
        }
    }

    /// Code and message together, lowercased, for MATCHING only. Never shown or recorded:
    /// Graph nests a machine-readable code inside `message` on some endpoints, so both have
    /// to be searched, and the message is prose that must not leave this function.
    static func graphErrorHaystack(_ data: Data) -> String {
        guard let error = errorObject(data) else { return "" }
        let code = (error["code"] as? String ?? "")
        let message = (error["message"] as? String ?? "")
        return (code + " " + message).lowercased()
    }

    /// Graph's error code alone, for the diagnostics report. Just the identifier — the
    /// message beside it is prose and stays out.
    static func graphErrorCode(_ data: Data) -> String? {
        guard let code = errorObject(data)?["code"] as? String, !code.isEmpty else { return nil }
        return code
    }

    /// Graph's error message, used ONLY to extract a claims challenge from it. It is prose
    /// and never recorded or displayed — `graphErrorCode` is what reaches the report.
    static func graphErrorMessage(_ data: Data) -> String? {
        errorObject(data)?["message"] as? String
    }

    private static func errorObject(_ data: Data) -> [String: Any]? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return json["error"] as? [String: Any]
    }
}
