import XCTest
@testable import PlatformSecurity

final class ConfirmMethodTests: XCTestCase {

    func test_theDevicesBiometryNamesTheMethod() {
        XCTAssertEqual(ConfirmMethod(.biometricsAvailable(kind: .faceID)), .faceID)
        XCTAssertEqual(ConfirmMethod(.biometricsAvailable(kind: .touchID)), .touchID)
    }

    func test_everythingElseIsThePasscode() {
        // Locked out, unknown or absent biometrics: the system prompt asks for the passcode.
        for availability: BiometricAvailability in [.passcodeOnly, .biometricsLockedOut, .noneConfigured, .biometricsAvailable(kind: .unknown)] {
            XCTAssertEqual(ConfirmMethod(availability), .passcode, "\(availability)")
        }
    }

    func test_wordsAndSymbols() {
        XCTAssertEqual(ConfirmMethod.faceID.name, "Face ID")
        XCTAssertEqual(ConfirmMethod.touchID.title, "Touch ID")
        XCTAssertEqual(ConfirmMethod.passcode.name, "your passcode")
        XCTAssertEqual(ConfirmMethod.passcode.title, "Your passcode")
        XCTAssertEqual([ConfirmMethod.faceID, .touchID, .passcode].map(\.symbol), ["faceid", "touchid", "lock"])
    }
}
