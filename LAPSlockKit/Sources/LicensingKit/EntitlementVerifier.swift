import Foundation
import CryptoKit

// Build Spec — entitlement verification, contract section 7.4.
//
// THE ORDER OF THE CHECKS BELOW IS THE CONTRACT, NOT A STYLE CHOICE.
//
// Nothing reads a claim before the signature has been verified. That is the whole reason
// this reads as a sequence of small steps rather than a decode-then-validate: a decoded
// claim from an unverified token is attacker-controlled data, and the classic JWT failures
// all come from acting on one.
//
// Specifically, `alg` must equal ES256 by exact comparison. It is NEVER used to select an
// algorithm. Choosing a verification algorithm from a field the attacker writes is the
// alg-confusion bug, and "none" is its punchline.

public struct EntitlementVerifier: Sendable {

    /// Contract section 7.4 step 7. Two minutes each way, matching the server's own 60
    /// seconds of `nbf` slack with room to spare, because the phone's clock is the one more
    /// likely to be wrong.
    public static let clockSkewTolerance: TimeInterval = 120

    private let keyring: EntitlementKeyring
    private let expectedIssuer: String
    private let expectedAudience: String

    public init(
        keyring: EntitlementKeyring = .shipping,
        expectedIssuer: String = "https://kainor.com/lapslock",
        expectedAudience: String = "com.kainor.lapslock"
    ) {
        self.keyring = keyring
        self.expectedIssuer = expectedIssuer
        self.expectedAudience = expectedAudience
    }

    /// Verifies a compact JWS.
    ///
    /// - Parameter boundTenantId: the tenant the license was activated against. `sub` must
    ///   equal this. Whether it must ALSO be the tenant currently signed in is a separate
    ///   question the caller answers, because the answer differs by tier — see
    ///   `EntitlementManager`.
    public func verify(
        token: String,
        boundTenantId: String,
        now: Date = Date()
    ) throws -> VerifiedEntitlement {

        // 1. Exactly three segments.
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else { throw EntitlementVerificationFailure.malformedToken }

        let headerSegment = String(segments[0])
        let payloadSegment = String(segments[1])
        let signatureSegment = String(segments[2])

        guard
            let headerData = Self.base64URLDecode(headerSegment),
            let payloadData = Self.base64URLDecode(payloadSegment),
            let signatureData = Self.base64URLDecode(signatureSegment)
        else { throw EntitlementVerificationFailure.malformedToken }

        // 2. alg must BE ES256. It is not consulted to choose anything.
        guard let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            throw EntitlementVerificationFailure.malformedToken
        }
        let algorithm = header["alg"] as? String
        guard algorithm == "ES256" else {
            throw EntitlementVerificationFailure.unsupportedAlgorithm(algorithm)
        }

        // 3. The kid must name a key this build already has.
        let kid = header["kid"] as? String
        guard let kid, let publicKey = keyring.key(for: kid) else {
            throw EntitlementVerificationFailure.unknownKeyIdentifier(kid)
        }

        // 4. Verify over the ASCII bytes of "header.payload". Only after this is any claim
        //    worth reading.
        let signingInput = "\(headerSegment).\(payloadSegment)"
        guard let signingBytes = signingInput.data(using: .ascii) else {
            throw EntitlementVerificationFailure.malformedToken
        }
        // JOSE ES256 signatures are raw r||s, which is exactly `rawRepresentation`. If this
        // ever needs DER handling, the server changed and the contract did not.
        guard
            let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureData),
            publicKey.isValidSignature(signature, for: signingBytes)
        else { throw EntitlementVerificationFailure.badSignature }

        guard let claims = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw EntitlementVerificationFailure.malformedToken
        }

        // 5. iss, exact string comparison.
        guard let issuer = claims["iss"] as? String else {
            throw EntitlementVerificationFailure.missingClaim("iss")
        }
        guard issuer == expectedIssuer else { throw EntitlementVerificationFailure.issuerMismatch }

        // 6. aud equals this bundle.
        guard let audience = claims["aud"] as? String else {
            throw EntitlementVerificationFailure.missingClaim("aud")
        }
        guard audience == expectedAudience else { throw EntitlementVerificationFailure.audienceMismatch }

        // 7. Time window, with skew.
        guard let notBefore = Self.date(claims["nbf"]) else {
            throw EntitlementVerificationFailure.missingClaim("nbf")
        }
        guard let expiresAt = Self.date(claims["exp"]) else {
            throw EntitlementVerificationFailure.missingClaim("exp")
        }
        guard let issuedAt = Self.date(claims["iat"]) else {
            throw EntitlementVerificationFailure.missingClaim("iat")
        }
        guard notBefore <= now.addingTimeInterval(Self.clockSkewTolerance) else {
            throw EntitlementVerificationFailure.notYetValid
        }
        guard now < expiresAt.addingTimeInterval(Self.clockSkewTolerance) else {
            // Reported rather than swallowed: expiry is the ONE failure the grace window in
            // section 7.5 is allowed to forgive, and only when a refresh actually failed.
            // Every other failure here is final.
            throw EntitlementVerificationFailure.expired(at: expiresAt)
        }

        // 8. sub equals the tenant this license was activated against, compared lowercase.
        guard let subject = claims["sub"] as? String else {
            throw EntitlementVerificationFailure.missingClaim("sub")
        }
        guard subject.lowercased() == boundTenantId.lowercased() else {
            throw EntitlementVerificationFailure.subjectMismatch
        }

        guard let tokenId = claims["jti"] as? String else {
            throw EntitlementVerificationFailure.missingClaim("jti")
        }

        // 9. Unrecognized tier becomes free. Unknown CLAIMS are ignored entirely, so that a
        //    server adding one later is additive rather than breaking (section 12).
        return VerifiedEntitlement(
            issuer: issuer,
            audience: audience,
            subject: subject.lowercased(),
            tier: EntitlementTier(claim: claims["tier"] as? String),
            issuedAt: issuedAt,
            notBefore: notBefore,
            expiresAt: expiresAt,
            tokenId: tokenId
        )
    }

    // MARK: - decoding

    /// base64url, padding restored. Rejects standard-base64 input rather than trying to be
    /// helpful about it: `+` and `/` are not valid here, and quietly accepting them would
    /// mean accepting a token no conforming server would produce.
    static func base64URLDecode(_ value: String) -> Data? {
        guard !value.contains("+"), !value.contains("/"), !value.contains("=") else { return nil }
        var padded = value.replacingOccurrences(of: "-", with: "+")
                          .replacingOccurrences(of: "_", with: "/")
        let remainder = padded.count % 4
        if remainder > 0 { padded += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: padded)
    }

    /// NumericDate. Accepts an integer or a fractional value, per RFC 7519.
    static func date(_ claim: Any?) -> Date? {
        if let seconds = claim as? Double { return Date(timeIntervalSince1970: seconds) }
        if let seconds = claim as? Int { return Date(timeIntervalSince1970: TimeInterval(seconds)) }
        if let number = claim as? NSNumber { return Date(timeIntervalSince1970: number.doubleValue) }
        return nil
    }
}
