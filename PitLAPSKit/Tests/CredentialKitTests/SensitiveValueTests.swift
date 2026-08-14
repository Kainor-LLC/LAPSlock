import XCTest
@testable import CredentialKit

// Build Spec §13 unit tests for the security core.
// These run with ZERO Microsoft dependencies — the whole point of the AuthKit seam.

final class SensitiveValueTests: XCTestCase {

    // MARK: - decoding (verification checklist item 2: passwordBase64 encoding)

    func test_utf8_roundTrip() {
        // "P@ssw0rd!" as UTF-8, base64-encoded.
        let plaintext = "P@ssw0rd!"
        let b64 = Data(plaintext.utf8).base64EncodedString()
        let sv = SensitiveValue(base64: b64, encoding: .utf8)
        XCTAssertNotNil(sv)
        sv?.withValue { XCTAssertEqual($0, plaintext) }
    }

    func test_utf16LE_roundTrip() {
        // Windows LAPS values are typically UTF-16LE. Build a known LE byte sequence.
        let plaintext = "Aa1!Zz9?"
        var bytes = [UInt8]()
        for unit in plaintext.utf16 {
            bytes.append(UInt8(unit & 0xFF))         // low byte
            bytes.append(UInt8((unit >> 8) & 0xFF))  // high byte
        }
        let b64 = Data(bytes).base64EncodedString()
        let sv = SensitiveValue(base64: b64, encoding: .utf16LE)
        XCTAssertNotNil(sv)
        sv?.withValue { XCTAssertEqual($0, plaintext) }
    }

    func test_utf16LE_stripsBOM() {
        let plaintext = "Secret9"
        var bytes: [UInt8] = [0xFF, 0xFE]            // BOM
        for unit in plaintext.utf16 {
            bytes.append(UInt8(unit & 0xFF))
            bytes.append(UInt8((unit >> 8) & 0xFF))
        }
        let b64 = Data(bytes).base64EncodedString()
        let sv = SensitiveValue(base64: b64, encoding: .utf16LE)
        sv?.withValue { XCTAssertEqual($0, plaintext) }
    }

    // MARK: - auto-detect heuristic

    func test_autoDetect_choosesUTF16_forAsciiUTF16LE() {
        // ASCII-range chars in UTF-16LE → every high byte is 0x00 → should detect UTF-16LE.
        let plaintext = "abcdEFGH1234"
        var bytes = [UInt8]()
        for unit in plaintext.utf16 {
            bytes.append(UInt8(unit & 0xFF))
            bytes.append(0x00)
        }
        XCTAssertEqual(SensitiveValue.detectEncoding(of: bytes), .utf16LE)
        let sv = SensitiveValue(base64AutoDetect: Data(bytes).base64EncodedString())
        sv?.withValue { XCTAssertEqual($0, plaintext) }
    }

    func test_autoDetect_choosesUTF8_forPlainUTF8() {
        // Dense UTF-8 (no NUL high bytes) → should detect UTF-8.
        let plaintext = "Zx9!Qw8@Er7#"
        let bytes = [UInt8](plaintext.utf8)
        XCTAssertEqual(SensitiveValue.detectEncoding(of: bytes), .utf8)
        let sv = SensitiveValue(base64AutoDetect: Data(bytes).base64EncodedString())
        sv?.withValue { XCTAssertEqual($0, plaintext) }
    }

    func test_autoDetect_oddLength_fallsBackToUTF8() {
        let bytes: [UInt8] = [0x41, 0x42, 0x43]      // odd count, can't be UTF-16
        XCTAssertEqual(SensitiveValue.detectEncoding(of: bytes), .utf8)
    }

    // MARK: - wipe semantics (§3.2)

    func test_wipe_marksWiped() {
        let sv = SensitiveValue(bytes: [0x41, 0x42], encoding: .utf8)
        XCTAssertFalse(sv.isWiped)
        sv.wipe()
        XCTAssertTrue(sv.isWiped)
    }

    func test_valueAvailableBeforeWipe() {
        let sv = SensitiveValue(bytes: [UInt8]("hi".utf8), encoding: .utf8)
        sv.withValue { XCTAssertEqual($0, "hi") }
        sv.wipe()
        XCTAssertTrue(sv.isWiped)
    }

    // Note: calling withValue after wipe() traps by precondition (by design).
    // That is verified manually / in a crash-test target, not here, since XCTest
    // cannot catch a precondition failure in-process.

    // MARK: - invalid input

    func test_invalidBase64_returnsNil() {
        XCTAssertNil(SensitiveValue(base64: "not base64!!!", encoding: .utf8))
        XCTAssertNil(SensitiveValue(base64AutoDetect: "@@@@"))
    }
}
