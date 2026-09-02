import Foundation
import CryptoKit

// Build Spec — entitlement verification keys.
//
// THE PUBLIC KEYS ARE COMPILED IN, AND THE CLIENT NEVER FETCHES ONE.
//
// Contract section 6.1. Fetching keys from the same server that signs the tokens would mean
// that server could hand a client any key it liked, and it would make a licensing decision
// depend on the network. Embedding is strictly stronger and it is why verification works
// offline during the grace period.
//
// A JWKS is published at kainor.com for auditors and for anyone verifying a token by hand.
// It is a human-readable artifact. Nothing in this app reads it, and nothing should.
//
// ROTATION (contract 6.2) is a three-release dance, slow on purpose:
//   1. ship a release whose keyring holds both the current key and the next one
//   2. wait for that release to reach the field
//   3. switch the Function to sign with the next key
// Old tokens stay valid until they expire. Adding a key here is step 1.

/// The public keys this build will accept a token from, by `kid`.
public struct EntitlementKeyring: Sendable {

    private let keys: [String: P256.Signing.PublicKey]

    public init(keys: [String: P256.Signing.PublicKey]) {
        self.keys = keys
    }

    public func key(for kid: String) -> P256.Signing.PublicKey? { keys[kid] }

    public var keyIdentifiers: [String] { keys.keys.sorted() }

    /// The keys this build ships with.
    ///
    /// `lapslock-ent-2026-09` was generated inside `kainor-lapslock-prod-kv` on 2026-09-02,
    /// is marked non-exportable, and can only sign and verify. The bytes below are the X9.63
    /// uncompressed public point: `0x04` then the 32-byte X, then the 32-byte Y.
    ///
    /// These bytes were transcribed from the vault's JWK, whose `x` and `y` the Azure CLI
    /// prints in STANDARD base64 rather than base64url — a trap worth naming, because those
    /// values contain `+` and `/` and pasting them into a base64url decoder produces a
    /// different, silently wrong key. The point below was checked against the P-256 curve
    /// equation before it was written down.
    public static let shipping: EntitlementKeyring = {
        let publicPoint = Data([
            0x04, 0xe6, 0x71, 0xf3, 0x25, 0x81, 0xb2, 0xe7, 0xb3, 0x90, 0x1c, 0xed,
            0xe6, 0x31, 0x71, 0xbe, 0x2f, 0x26, 0xbc, 0xd3, 0x80, 0x88, 0xf5, 0xbd,
            0xca, 0x66, 0xc9, 0xed, 0x6d, 0xed, 0x9b, 0x99, 0x12, 0xcc, 0xe6, 0xc8,
            0x89, 0x76, 0x94, 0xa3, 0x66, 0x48, 0x94, 0x44, 0xc5, 0xbe, 0x88, 0x90,
            0xdc, 0x8f, 0xba, 0x6e, 0xd0, 0x3f, 0x3f, 0x1f, 0x4c, 0xf8, 0x2e, 0x9e,
            0xa4, 0x5f, 0x5f, 0xe1, 0x55,
        ])

        // A malformed constant here would mean every entitlement in the field fails to
        // verify. Failing loudly at startup is better than shipping a build that silently
        // treats every paying customer as free.
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicPoint) else {
            preconditionFailure("The compiled-in entitlement public key is not a valid P-256 point.")
        }

        return EntitlementKeyring(keys: ["lapslock-ent-2026-09": key])
    }()
}
