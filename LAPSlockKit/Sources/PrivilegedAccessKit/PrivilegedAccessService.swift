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
    func activate(
        _ access: EligibleAccess,
        justification: String,
        ticketNumber: String?
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
            return .failure(error == .consentRequired ? .consentRequired : .notAuthorized)
        } catch {
            return .failure(.transport)
        }
    }

    // MARK: - activating

    public func activate(
        _ access: EligibleAccess,
        justification: String,
        ticketNumber: String? = nil
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
            ticketNumber: ticketNumber)

        do {
            return try await post(prepared, claims: nil)
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
            // Graph answers 400 for "role is already active", which is not a failure worth
            // an alarming message. Detected by the error code rather than by matching prose,
            // which is localised.
            let code = Self.graphErrorCode(data)
            throw code.contains("roleassignmentexists") || code.contains("activeassignment")
                ? PrivilegedAccessError.alreadyActive
                : PrivilegedAccessError.serviceError(status: 400)
        default:
            throw PrivilegedAccessError.serviceError(status: response.statusCode)
        }
    }

    static func graphErrorCode(_ data: Data) -> String {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let error = json["error"] as? [String: Any]
        else { return "" }
        // Graph nests a machine-readable code inside `message` on some endpoints, so both
        // are searched. Lowercased for comparison; never shown to the user.
        let code = (error["code"] as? String ?? "")
        let message = (error["message"] as? String ?? "")
        return (code + " " + message).lowercased()
    }
}
