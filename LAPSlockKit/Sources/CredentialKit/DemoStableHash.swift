import Foundation

/// Stable, non-cryptographic hash for DEMO DATA ONLY.
///
/// Foundation only, no CryptoKit: CredentialKit's isolation boundary (Spec §3.1) permits
/// Foundation and AuthKit and nothing else. Nothing here needs cryptographic strength —
/// only stability.
///
/// WHY THIS EXISTS. The demo providers derived their fake values from `String.hashValue`,
/// which Swift seeds randomly per process. Two consequences, both wrong:
///
///   1. The values were NOT stable across launches, contradicting the comments beside them
///      that promised the same device shows the same value.
///   2. `DemoBitLockerService` reduced that hash to a seed in 1...9, so two distinct key
///      identifiers collided about one run in nine and produced identical "different" keys.
///      That made `test_demoDifferentKeysDifferentValues` fail intermittently — roughly 8%
///      of runs, which is frequent enough to erode trust in the suite and rare enough to be
///      dismissed as noise.
///
/// FNV-1a, 64-bit. Same input, same output, every process, forever.
func demoStableHash(_ string: String) -> UInt64 {
    var hash: UInt64 = 14_695_981_039_346_656_037
    for byte in string.utf8 {
        hash ^= UInt64(byte)
        hash = hash &* 1_099_511_628_211
    }
    return hash
}
