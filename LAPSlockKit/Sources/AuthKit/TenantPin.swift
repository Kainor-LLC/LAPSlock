import Foundation

// Build Spec §3.3 — the tenant guard, made explicit.
//
// WHAT THIS REPLACES, AND WHY IT IS NOT A WEAKENING.
//
// The guard used to compare a returned token's `tid` against the signed-in account's OWN
// tenant. That is correct for a single-organization admin and wrong for an MSP, who
// legitimately operates in a customer's tenant with an account whose home tenant is their
// own. The naive fix — deleting the comparison — would remove the only thing stopping a
// token for the wrong organization being used against it.
//
// So the comparison stays and the EXPECTATION becomes explicit. Before: "this token must be
// for the account's home tenant." Now: "this token must be for the tenant we deliberately
// selected." Strictly more expressive, exactly as strict, and the selection is a deliberate
// act rather than an implicit default.
//
// It lives in AuthKit rather than AuthKitMSAL on purpose. AuthKitMSAL is wrapped in
// `#if os(iOS)` and its types cannot be constructed on macOS, so a comparison living there
// could not be unit tested. This one is Foundation-only and platform-agnostic, which means
// the single most security-relevant line in the auth path is covered by tests that run on
// every `swift test`.

/// The tenant the app has deliberately chosen to operate in.
public struct TenantPin: Sendable, Equatable, Hashable {

    /// Lowercase canonical GUID.
    public let expected: String

    /// Fails for anything that is not an exact `D`-format GUID.
    ///
    /// Exact format only, for the same reason `TenantId.TryNormalise` on the server side
    /// rejects braces and hyphenless forms: several spellings of one directory would mean
    /// several pins that all claim to mean the same thing.
    public init?(expected: String) {
        let trimmed = expected.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard Self.isCanonicalGUID(trimmed) else { return nil }
        self.expected = trimmed
    }

    /// Throws `AuthError.tenantMismatch` unless the token came back for the pinned tenant.
    ///
    /// A missing `tid` is a mismatch, not a pass. A token that will not say which tenant it
    /// is for is exactly the token this guard exists to refuse.
    public func validate(returnedTenantId: String?) throws {
        guard let returned = returnedTenantId?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
              !returned.isEmpty,
              returned == expected
        else { throw AuthError.tenantMismatch }
    }

    public var authorityURL: URL {
        // Force-unwrap is safe: `expected` is a validated GUID, so this interpolation can
        // only produce a well-formed URL.
        URL(string: "https://login.microsoftonline.com/\(expected)")!
    }

    static func isCanonicalGUID(_ value: String) -> Bool {
        let pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        return value.range(of: pattern, options: .regularExpression) != nil
    }
}
