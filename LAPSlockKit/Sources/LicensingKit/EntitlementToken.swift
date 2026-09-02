import Foundation

// Build Spec — the verified entitlement.
//
// Nothing in this file is trusted until `EntitlementVerifier` has checked a signature. The
// types exist so that a VERIFIED token and an unverified blob cannot be confused: if you are
// holding a `VerifiedEntitlement`, the signature passed.

/// What the product sells. Contract section 5.3.
///
/// Decoded from the `tier` claim. An unrecognized value becomes `.free`, deliberately:
/// failing to the metered tier rather than the unlocked one is the only safe direction for a
/// value that arrived over a network.
public enum EntitlementTier: String, Sendable, Equatable, CaseIterable {
    case free
    case pro
    case msp
    case enterprise

    public init(claim: String?) {
        guard let claim, let known = EntitlementTier(rawValue: claim.lowercased()) else {
            self = .free
            return
        }
        self = known
    }

    /// Whether this tier unlocks the paid features. Contract section 7.7.
    public var isPaid: Bool { self != .free }

    /// Only the MSP tier switches tenants, so only it is exempt from the signed-in tenant
    /// check. Contract section 7.4.
    public var allowsTenantSwitching: Bool { self == .msp }
}

/// The eight claims from contract section 5.2, after the signature has been verified.
public struct VerifiedEntitlement: Sendable, Equatable {
    public let issuer: String
    public let audience: String
    /// The licensed tenant. Bound to `sub`.
    public let subject: String
    public let tier: EntitlementTier
    public let issuedAt: Date
    public let notBefore: Date
    public let expiresAt: Date
    public let tokenId: String

    public init(
        issuer: String,
        audience: String,
        subject: String,
        tier: EntitlementTier,
        issuedAt: Date,
        notBefore: Date,
        expiresAt: Date,
        tokenId: String
    ) {
        self.issuer = issuer
        self.audience = audience
        self.subject = subject
        self.tier = tier
        self.issuedAt = issuedAt
        self.notBefore = notBefore
        self.expiresAt = expiresAt
        self.tokenId = tokenId
    }
}

/// Why a token was not accepted.
///
/// Every case means the same thing to the user — the free tier — and none of them is shown
/// as an error. Contract section 7.6: failure degrades, never blocks, and never interrupts.
/// The distinctions exist for the diagnostics report, not for a dialog.
public enum EntitlementVerificationFailure: Error, Sendable, Equatable {
    case malformedToken
    case unsupportedAlgorithm(String?)
    case unknownKeyIdentifier(String?)
    case badSignature
    case issuerMismatch
    case audienceMismatch
    case subjectMismatch
    case notYetValid
    case expired(at: Date)
    case missingClaim(String)
}
