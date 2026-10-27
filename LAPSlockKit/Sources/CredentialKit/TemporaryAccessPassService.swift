import Foundation
import AuthKit

// The Temporary Access Pass. Spec section 3.5, decided 2026-10-26: issued here, on the
// credential path, because the response to the write that creates it carries the pass
// itself, a credential, and a target that sends writes must never hold one. The caller
// runs Face ID before calling, shows the pass with the reveal timer and the clearing
// clipboard, and wipes it; this type never writes it anywhere, never logs it, and hands it
// over only as a SensitiveValue. The gate's role check and shift-log line happen in the
// app around this call, without the value.

public struct IssuedTemporaryAccessPass {
    public let pass: SensitiveValue
    public let lifetimeMinutes: Int
    public let isUsableOnce: Bool
    public let startDateTime: Date?
}

public protocol TemporaryAccessPassIssuing: Sendable {
    /// Creates a one-time pass for another person. Replaces any pass they already have.
    func issue(userId: String, lifetimeMinutes: Int) async throws -> IssuedTemporaryAccessPass
}

public struct TemporaryAccessPassService: TemporaryAccessPassIssuing {

    public static let scope = "UserAuthMethod-TAP.ReadWrite.All"
    /// Microsoft's bounds: 10 minutes to 30 days.
    public static let lifetimeRange = 10...43_200

    private let auth: AuthManaging
    private let session: URLSession

    public init(auth: AuthManaging) {
        self.auth = auth
        self.session = GraphHTTP.makeSession()
    }

    public func issue(userId: String, lifetimeMinutes: Int) async throws -> IssuedTemporaryAccessPass {
        guard !userId.isEmpty, !userId.contains("/") else { throw CredentialError.missingIdentifier("Missing user identifier.") }
        let lifetime = min(max(lifetimeMinutes, Self.lifetimeRange.lowerBound), Self.lifetimeRange.upperBound)
        let token = try await auth.token(scopes: [Self.scope], allowInteractive: true)
        var request = URLRequest(url: GraphHTTP.url(version: "v1.0", path: "/users/" + userId + "/authentication/temporaryAccessPassMethods"))
        request.httpMethod = "POST"
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["isUsableOnce": true, "lifetimeInMinutes": lifetime])
        let (data, response) = try await session.data(for: request)
        try GraphHTTP.validate(response)
        return try Self.parse(data)
    }

    /// The pass goes straight into a SensitiveValue; the parsed dictionary holding it is
    /// discarded on return and nothing else keeps a copy.
    static func parse(_ data: Data) throws -> IssuedTemporaryAccessPass {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let value = json["temporaryAccessPass"] as? String, !value.isEmpty else {
            throw CredentialError.decodeFailure
        }
        return IssuedTemporaryAccessPass(
            pass: SensitiveValue(bytes: [UInt8](value.utf8), encoding: .utf8),
            lifetimeMinutes: json["lifetimeInMinutes"] as? Int ?? 60,
            isUsableOnce: json["isUsableOnce"] as? Bool ?? true,
            startDateTime: GraphHTTP.date(json["startDateTime"]))
    }
}

/// Demo: a pass that is plainly not real.
public struct DemoTemporaryAccessPassService: TemporaryAccessPassIssuing {
    public init() {}
    public func issue(userId: String, lifetimeMinutes: Int) async throws -> IssuedTemporaryAccessPass {
        try await Task.sleep(for: .milliseconds(600))
        return IssuedTemporaryAccessPass(pass: SensitiveValue(bytes: [UInt8]("DEMO-NOT-REAL".utf8), encoding: .utf8),
                                         lifetimeMinutes: 60, isUsableOnce: true, startDateTime: nil)
    }
}
