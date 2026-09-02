import Foundation

// Resolving a customer's domain to a tenant GUID, for the MSP tenant switcher.
//
// An MSP knows their customers by domain, not by GUID. Typing
// `4470dc21-a4b7-4729-a232-56d4c0eedf73` from memory is not a workflow; typing `contoso.com`
// is. This turns one into the other.
//
// It uses unauthenticated OpenID Connect discovery against `login.microsoftonline.com`, a
// host the app already talks to, so this adds no new network destination and nothing changes
// in the privacy policy or the transparency doc. The response is public information: any
// domain's tenant GUID is discoverable this way by anyone, which is the same fact the
// entitlement contract leans on in §9.1 when it accepts that a bare tenant ID is not a
// secret.
//
// Foundation only. It sits in AuthKit so it can be tested on macOS; the parsing and the
// input validation, which are the parts that can be got wrong, are pure and covered.

public enum TenantDirectoryError: Error, Sendable, Equatable {
    /// The input was neither a GUID nor a plausible domain.
    case malformedInput
    /// Discovery returned nothing usable — usually a domain with no Entra tenant behind it.
    case notFound
    case network
}

public enum TenantDirectory {

    /// Resolves a domain or a GUID to a lowercase tenant GUID.
    ///
    /// A GUID passes straight through after validation: somebody who already has the tenant
    /// ID should not need a network round trip to use it.
    public static func resolve(
        _ input: String,
        session: URLSession = .shared
    ) async throws -> String {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        if TenantPin.isCanonicalGUID(trimmed) { return trimmed }
        guard let domain = sanitizedDomain(trimmed) else { throw TenantDirectoryError.malformedInput }

        let url = URL(string: "https://login.microsoftonline.com/\(domain)/v2.0/.well-known/openid-configuration")!
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw TenantDirectoryError.network
        }

        guard let http = response as? HTTPURLResponse else { throw TenantDirectoryError.network }
        // A domain with no tenant behind it answers 400, which is a "not found" for our
        // purposes rather than an error worth showing a status code for.
        guard http.statusCode == 200 else { throw TenantDirectoryError.notFound }

        guard let tenantId = tenantId(fromDiscovery: data) else { throw TenantDirectoryError.notFound }
        return tenantId
    }

    /// Pulls the tenant GUID out of a discovery document's `issuer`.
    ///
    /// The issuer is `https://login.microsoftonline.com/{tid}/v2.0`. Extracted by GUID shape
    /// rather than by splitting on slashes, so a change to the surrounding URL structure
    /// cannot silently yield a wrong value — it yields nothing, and that surfaces.
    static func tenantId(fromDiscovery data: Data) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let issuer = object["issuer"] as? String
        else { return nil }
        return tenantId(fromIssuer: issuer)
    }

    static func tenantId(fromIssuer issuer: String) -> String? {
        let pattern = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        guard let range = issuer.range(of: pattern, options: .regularExpression) else { return nil }
        return String(issuer[range]).lowercased()
    }

    /// Accepts only something that looks like a domain, because the value is interpolated
    /// into a URL path. A slash, a dot-dot or a space here would be a path-traversal
    /// attempt against the discovery endpoint.
    static func sanitizedDomain(_ value: String) -> String? {
        guard value.count >= 4, value.count <= 253 else { return nil }
        guard value.range(of: "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$",
                          options: .regularExpression) != nil
        else { return nil }
        return value
    }
}
