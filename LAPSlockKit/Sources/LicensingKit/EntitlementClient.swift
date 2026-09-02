import Foundation

// Build Spec — the one call this app makes to a Kainor server. Contract sections 2 to 4.
//
// EVERYTHING THAT GOES ON THE WIRE IS DECIDED HERE, NOT BY THE HTTP STACK.
//
// The request body is a version and a tenant ID. The headers are the four in contract
// section 2. URLSession's default User-Agent carries the bundle identifier, build number and
// OS version, so it is overridden with a string that names only the app and its version.
// The session is ephemeral — no cookie store, no cache — so there is no persistent client
// identifier and two requests from the same install are not linkable beyond a source address.
//
// An administrator with a proxy is supposed to be able to confirm all of that in ten
// minutes. This file is what they are confirming.

/// The success body, contract section 4.1. Unknown fields are ignored on decode so that a
/// server adding one later is additive rather than breaking (section 12).
public struct EntitlementResponse: Sendable, Equatable, Decodable {
    public let version: Int
    /// Compact JWS. The ONLY field with any authority; see `EntitlementVerifier`.
    public let token: String
    /// Advisory. Parsed leniently and clamped by the manager; never overrides a verified `exp`.
    public let refreshAfter: String?

    public init(version: Int, token: String, refreshAfter: String?) {
        self.version = version
        self.token = token
        self.refreshAfter = refreshAfter
    }
}

/// Why a fetch failed. The manager cares about exactly one distinction: was this the
/// NETWORK, or was it the SERVER giving an answer? Only a network failure earns the offline
/// grace in contract section 7.5. A server that answered — with anything — did not.
public enum EntitlementFetchError: Error, Sendable, Equatable {
    /// No response reached us: offline, DNS, TLS, timeout. Grace applies.
    case network
    /// The server answered with an error status. Grace does NOT apply.
    case server(status: Int, code: String?)
    /// The server answered 200 with something that was not the contract. Grace does not apply.
    case malformedResponse
}

public protocol EntitlementFetching: Sendable {
    func fetch(tenantId: String) async throws -> EntitlementResponse
}

public struct EntitlementClient: EntitlementFetching {

    public static let productionEndpoint = URL(string: "https://kainor-lapslock-prod-func.azurewebsites.net/entitlement")!

    /// Contract section 3.1 caps the body at 4 KiB. Ours is under 100 bytes; the cap on the
    /// RESPONSE is defensive, so a hostile or broken server cannot make the phone buffer
    /// something enormous.
    static let maxResponseBytes = 16 * 1024

    private let endpoint: URL
    private let userAgent: String
    private let session: URLSession

    /// - Parameter appVersion: goes into the User-Agent and nothing else does. Read from
    ///   the main bundle by default so a library consumer does not have to plumb it.
    public init(
        endpoint: URL = EntitlementClient.productionEndpoint,
        appVersion: String? = nil,
        timeout: TimeInterval = 10
    ) {
        self.endpoint = endpoint

        let version = appVersion
            ?? (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String)
            ?? "0"
        self.userAgent = "LAPSlock/\(version) (iOS)"

        // Ephemeral, and then some. No cookies means no session identifier can be set on us.
        // No cache means the token is never written to disk by the networking layer; the
        // Keychain store is the only place it lives. The URL cache in particular would put
        // a copy of the response into the app container, which is exactly where a token
        // should not be.
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        config.waitsForConnectivity = false
        // Explicit and exhaustive: nothing else gets to add a header.
        config.httpAdditionalHeaders = nil
        self.session = URLSession(configuration: config)
    }

    public func fetch(tenantId: String) async throws -> EntitlementResponse {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

        // Contract section 3: this is the entire request. Hand-built rather than via an
        // Encodable so that nothing can grow into it without being visible right here.
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "version": 1,
            "tenantId": tenantId.lowercased(),
        ])

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            // Anything URLSession throws is "the network did not deliver an answer".
            throw EntitlementFetchError.network
        }

        guard let http = response as? HTTPURLResponse else { throw EntitlementFetchError.network }
        guard data.count <= Self.maxResponseBytes else { throw EntitlementFetchError.malformedResponse }

        guard http.statusCode == 200 else {
            // Best-effort read of the contract's error code, for diagnostics only.
            let body = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            throw EntitlementFetchError.server(status: http.statusCode, code: body?["error"] as? String)
        }

        guard let decoded = try? JSONDecoder().decode(EntitlementResponse.self, from: data),
              decoded.version == 1,
              !decoded.token.isEmpty
        else { throw EntitlementFetchError.malformedResponse }

        return decoded
    }
}
