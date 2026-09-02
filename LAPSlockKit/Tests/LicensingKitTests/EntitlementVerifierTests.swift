import XCTest
import CryptoKit
@testable import LicensingKit

/// Entitlement verification, against contract section 7.4.
///
/// These tests build and sign tokens at runtime with a throwaway key rather than embedding
/// fixture strings. Two reasons: a literal token in the repo would be flagged by
/// `pre-push-scan.sh` as a JWT-shaped string, correctly, and a fixture would freeze a moment
/// in time while the thing worth testing is the algorithm.
final class EntitlementVerifierTests: XCTestCase {

    private let tenant = "4470dc21-a4b7-4729-a232-56d4c0eedf73"
    private let kid = "test-key"
    private let now = Date(timeIntervalSince1970: 1_788_321_139)

    private var signingKey = P256.Signing.PrivateKey()

    private func makeVerifier() -> EntitlementVerifier {
        EntitlementVerifier(keyring: EntitlementKeyring(keys: [kid: signingKey.publicKey]))
    }

    // MARK: - token construction

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func makeToken(
        header: [String: Any]? = nil,
        claims claimOverrides: [String: Any?] = [:],
        signWith key: P256.Signing.PrivateKey? = nil
    ) -> String {
        let head = header ?? ["alg": "ES256", "typ": "JWT", "kid": kid]

        var claims: [String: Any] = [
            "iss": "https://kainor.com/lapslock",
            "aud": "com.kainor.lapslock",
            "sub": tenant,
            "tier": "enterprise",
            "iat": Int(now.timeIntervalSince1970),
            "nbf": Int(now.timeIntervalSince1970) - 60,
            "exp": Int(now.timeIntervalSince1970) + 30 * 86_400,
            "jti": UUID().uuidString,
        ]
        for (key, value) in claimOverrides {
            if let value { claims[key] = value } else { claims.removeValue(forKey: key) }
        }

        let headerSegment = base64URL(try! JSONSerialization.data(withJSONObject: head))
        let payloadSegment = base64URL(try! JSONSerialization.data(withJSONObject: claims))
        let signingInput = "\(headerSegment).\(payloadSegment)"
        let signature = try! (key ?? signingKey).signature(for: signingInput.data(using: .ascii)!)

        return "\(signingInput).\(base64URL(signature.rawRepresentation))"
    }

    private func assertRejected(
        _ token: String,
        _ expected: EntitlementVerificationFailure,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try makeVerifier().verify(token: token, boundTenantId: tenant, now: now),
            file: file, line: line
        ) { error in
            XCTAssertEqual(error as? EntitlementVerificationFailure, expected, file: file, line: line)
        }
    }

    // MARK: - the happy path

    func test_aValidTokenVerifies() throws {
        let entitlement = try makeVerifier().verify(token: makeToken(), boundTenantId: tenant, now: now)

        XCTAssertEqual(entitlement.tier, .enterprise)
        XCTAssertEqual(entitlement.subject, tenant)
        XCTAssertEqual(entitlement.issuer, "https://kainor.com/lapslock")
        XCTAssertEqual(entitlement.audience, "com.kainor.lapslock")
        XCTAssertEqual(entitlement.expiresAt, now.addingTimeInterval(30 * 86_400))
    }

    // MARK: - signature and algorithm

    func test_aTamperedPayloadIsRejected() {
        // The forgery that matters: swap free for enterprise, keep the signature.
        let free = makeToken(claims: ["tier": "free"])
        let paid = makeToken(claims: ["tier": "enterprise"])

        let freeParts = free.split(separator: ".").map(String.init)
        let paidParts = paid.split(separator: ".").map(String.init)
        let spliced = "\(freeParts[0]).\(paidParts[1]).\(freeParts[2])"

        assertRejected(spliced, .badSignature)
    }

    func test_aTokenSignedByAnotherKeyIsRejected() {
        assertRejected(makeToken(signWith: P256.Signing.PrivateKey()), .badSignature)
    }

    func test_algNoneIsRejected() {
        // The punchline of the alg-confusion family. `alg` is compared, never consulted to
        // choose an algorithm, so this cannot degrade into "no verification".
        assertRejected(
            makeToken(header: ["alg": "none", "typ": "JWT", "kid": kid]),
            .unsupportedAlgorithm("none")
        )
    }

    func test_otherAlgorithmsAreRejected() {
        for algorithm in ["RS256", "HS256", "ES384", "es256", "ES256 "] {
            assertRejected(
                makeToken(header: ["alg": algorithm, "typ": "JWT", "kid": kid]),
                .unsupportedAlgorithm(algorithm)
            )
        }
    }

    func test_aMissingAlgIsRejected() {
        assertRejected(makeToken(header: ["typ": "JWT", "kid": kid]), .unsupportedAlgorithm(nil))
    }

    func test_anUnknownKeyIdentifierIsRejected() {
        // A token signed by a key this build does not carry, even a real one, is refused.
        // This is what makes rotation a deliberate three-release process.
        assertRejected(
            makeToken(header: ["alg": "ES256", "typ": "JWT", "kid": "lapslock-ent-2099-01"]),
            .unknownKeyIdentifier("lapslock-ent-2099-01")
        )
        assertRejected(makeToken(header: ["alg": "ES256", "typ": "JWT"]), .unknownKeyIdentifier(nil))
    }

    // MARK: - binding

    func test_aTokenForAnotherTenantIsRejected() {
        // Section 9.1: this check is why a stolen entitlement is useless to anyone who is not
        // already inside the licensed tenant.
        let other = makeToken(claims: ["sub": "11111111-2222-3333-4444-555555555555"])
        assertRejected(other, .subjectMismatch)
    }

    func test_subjectComparisonIsCaseInsensitive() throws {
        let upper = makeToken(claims: ["sub": tenant.uppercased()])
        let entitlement = try makeVerifier().verify(token: upper, boundTenantId: tenant, now: now)
        XCTAssertEqual(entitlement.subject, tenant)
    }

    func test_aWrongIssuerIsRejected() {
        assertRejected(makeToken(claims: ["iss": "https://evil.example/lapslock"]), .issuerMismatch)
        // A prefix match would pass this one. Exact comparison is the requirement.
        assertRejected(makeToken(claims: ["iss": "https://kainor.com/lapslock/extra"]), .issuerMismatch)
    }

    func test_aWrongAudienceIsRejected() {
        assertRejected(makeToken(claims: ["aud": "com.kainor.someotherapp"]), .audienceMismatch)
    }

    // MARK: - time

    func test_anExpiredTokenIsRejected() {
        let expiry = Int(now.timeIntervalSince1970) - 3600
        assertRejected(
            makeToken(claims: ["exp": expiry, "nbf": expiry - 86_400, "iat": expiry - 86_400]),
            .expired(at: Date(timeIntervalSince1970: TimeInterval(expiry)))
        )
    }

    func test_aTokenFromTheFutureIsRejected() {
        let start = Int(now.timeIntervalSince1970) + 3600
        assertRejected(
            makeToken(claims: ["nbf": start, "iat": start, "exp": start + 86_400]),
            .notYetValid
        )
    }

    func test_clockSkewIsToleratedInBothDirections() throws {
        let verifier = makeVerifier()

        // Just expired, inside tolerance: still accepted, so a phone whose clock runs a
        // minute fast does not lose its licence.
        let justExpired = Int(now.timeIntervalSince1970) - 60
        _ = try verifier.verify(
            token: makeToken(claims: ["exp": justExpired, "nbf": justExpired - 86_400, "iat": justExpired - 86_400]),
            boundTenantId: tenant,
            now: now)

        // Just starting, inside tolerance.
        let justStarted = Int(now.timeIntervalSince1970) + 60
        _ = try verifier.verify(
            token: makeToken(claims: ["nbf": justStarted, "iat": justStarted, "exp": justStarted + 86_400]),
            boundTenantId: tenant,
            now: now)
    }

    func test_skewToleranceIsBounded() {
        // Tolerance must not become an open door: an hour past expiry is expired.
        let expiry = Int(now.timeIntervalSince1970) - 3600
        assertRejected(
            makeToken(claims: ["exp": expiry, "nbf": expiry - 86_400, "iat": expiry - 86_400]),
            .expired(at: Date(timeIntervalSince1970: TimeInterval(expiry)))
        )
    }

    // MARK: - claims

    func test_anUnrecognisedTierBecomesFree() throws {
        for tier in ["platinum", "PRO ULTIMATE", "", "admin"] {
            let entitlement = try makeVerifier().verify(
                token: makeToken(claims: ["tier": tier]), boundTenantId: tenant, now: now)
            XCTAssertEqual(entitlement.tier, .free, "tier \(tier) should degrade to free")
        }
    }

    func test_aMissingTierBecomesFree() throws {
        let entitlement = try makeVerifier().verify(
            token: makeToken(claims: ["tier": nil]), boundTenantId: tenant, now: now)
        XCTAssertEqual(entitlement.tier, .free)
    }

    func test_tierIsCaseInsensitive() throws {
        let entitlement = try makeVerifier().verify(
            token: makeToken(claims: ["tier": "Enterprise"]), boundTenantId: tenant, now: now)
        XCTAssertEqual(entitlement.tier, .enterprise)
    }

    func test_unknownClaimsAreIgnored() throws {
        // Section 12: a server adding a claim must not break an older client.
        let entitlement = try makeVerifier().verify(
            token: makeToken(claims: ["seats": 500, "somethingNew": "value"]),
            boundTenantId: tenant, now: now)
        XCTAssertEqual(entitlement.tier, .enterprise)
    }

    func test_missingRequiredClaimsAreRejected() {
        assertRejected(makeToken(claims: ["iss": nil]), .missingClaim("iss"))
        assertRejected(makeToken(claims: ["aud": nil]), .missingClaim("aud"))
        assertRejected(makeToken(claims: ["sub": nil]), .missingClaim("sub"))
        assertRejected(makeToken(claims: ["exp": nil]), .missingClaim("exp"))
        assertRejected(makeToken(claims: ["nbf": nil]), .missingClaim("nbf"))
        assertRejected(makeToken(claims: ["jti": nil]), .missingClaim("jti"))
    }

    // MARK: - shape

    func test_malformedTokensAreRejected() {
        for bad in ["", "onlyonesegment", "two.segments", "a.b.c.d", "not base64!.x.y"] {
            assertRejected(bad, .malformedToken)
        }
    }

    func test_standardBase64IsNotAccepted() {
        // A segment containing + / or = is not base64url. Accepting it would mean accepting
        // a token no conforming server produces, and it is exactly the encoding the Azure
        // CLI prints public keys in.
        XCTAssertNil(EntitlementVerifier.base64URLDecode("abc+def"))
        XCTAssertNil(EntitlementVerifier.base64URLDecode("abc/def"))
        XCTAssertNil(EntitlementVerifier.base64URLDecode("abcd="))
        XCTAssertNotNil(EntitlementVerifier.base64URLDecode("abc-def_gh"))
    }

    // MARK: - the shipping keyring

    func test_theShippingKeyringCarriesTheProductionKey() {
        let keyring = EntitlementKeyring.shipping
        XCTAssertEqual(keyring.keyIdentifiers, ["lapslock-ent-2026-09"])
        XCTAssertNotNil(keyring.key(for: "lapslock-ent-2026-09"))
        XCTAssertNil(keyring.key(for: "lapslock-ent-2099-01"))
    }

    func test_theShippingKeyIsAValidP256Point() throws {
        // The constant is transcribed by hand from the vault's JWK, whose x and y the Azure
        // CLI prints in STANDARD base64. A transcription slip produces a key that parses but
        // verifies nothing, which would look like every customer silently dropping to free.
        let key = try XCTUnwrap(EntitlementKeyring.shipping.key(for: "lapslock-ent-2026-09"))
        let representation = key.x963Representation
        XCTAssertEqual(representation.count, 65)
        XCTAssertEqual(representation.first, 0x04, "expected an uncompressed point")
    }
}
