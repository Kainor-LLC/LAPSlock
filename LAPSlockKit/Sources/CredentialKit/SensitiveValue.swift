import Foundation

// Build Spec §3.2 — the boundary type for LAPS plaintext.
// Deliberately NOT Codable, NOT Equatable-on-value, no value-exposing description.
// The only way to the plaintext is `withValue`, and the value must not escape the closure.
public enum SensitiveEncoding: Sendable { case utf16LE, utf8 }

public final class SensitiveValue {
    private var storage: [UInt8]
    private let declaredEncoding: SensitiveEncoding
    public private(set) var isWiped = false

    public init(bytes: [UInt8], encoding: SensitiveEncoding) {
        self.storage = bytes
        self.declaredEncoding = encoding
    }

    /// Decodes base64 into guarded bytes. `encoding` describes the *decoded* bytes.
    public convenience init?(base64: String, encoding: SensitiveEncoding) {
        guard let data = Data(base64Encoded: base64) else { return nil }
        self.init(bytes: [UInt8](data), encoding: encoding)
    }

    /// Heuristic for Windows LAPS payloads (Spec §2.3 + verification checklist item 2):
    /// UTF-16LE text has a NUL high byte for ASCII-range characters. If the byte count
    /// is even and ≥60% of odd indices are 0x00, decode as UTF-16LE; otherwise UTF-8.
    /// Confirm against a known tenant value before GA (checklist).
    public static func detectEncoding(of bytes: [UInt8]) -> SensitiveEncoding {
        guard bytes.count >= 2, bytes.count % 2 == 0 else { return .utf8 }
        var nulHighBytes = 0
        var i = 1
        while i < bytes.count {
            if bytes[i] == 0 { nulHighBytes += 1 }
            i += 2
        }
        let ratio = Double(nulHighBytes) / Double(bytes.count / 2)
        return ratio >= 0.6 ? .utf16LE : .utf8
    }

    public convenience init?(base64AutoDetect base64: String) {
        guard let data = Data(base64Encoded: base64) else { return nil }
        let bytes = [UInt8](data)
        self.init(bytes: bytes, encoding: SensitiveValue.detectEncoding(of: bytes))
    }

    /// Access the plaintext only inside the closure. Never return or store it.
    public func withValue<R>(_ body: (String) -> R) -> R {
        precondition(!isWiped, "SensitiveValue used after wipe()")
        let s: String
        switch declaredEncoding {
        case .utf8:
            s = String(decoding: storage, as: UTF8.self)
        case .utf16LE:
            var units = [UInt16]()
            units.reserveCapacity(storage.count / 2)
            var i = 0
            while i + 1 < storage.count {
                units.append(UInt16(storage[i]) | (UInt16(storage[i + 1]) << 8))
                i += 2
            }
            if units.first == 0xFEFF { units.removeFirst() } // strip BOM if present
            s = String(decoding: units, as: UTF16.self)
        }
        return body(s)
    }

    /// Overwrite backing bytes. Call on remask, onDisappear, and scenePhase changes.
    public func wipe() {
        for i in storage.indices { storage[i] = 0 }
        storage.removeAll(keepingCapacity: false)
        isWiped = true
    }

    deinit { wipe() }
}
