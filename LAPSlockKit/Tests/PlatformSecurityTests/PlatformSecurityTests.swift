import XCTest
@testable import PlatformSecurity

// Build Spec §13 — tests for the security behaviors around a revealed credential.
//
// These are deterministic: RevealSession runs on an injected clock, so the auto-hide
// window is tested by advancing time rather than sleeping. That matters because the
// alternative (real timers in tests) is flaky, and a flaky test on the "does the
// password actually disappear" behavior would be worse than no test.

final class RevealSessionTests: XCTestCase {

    private func makeSession(duration: TimeInterval = 60) -> (RevealSession, ManualRevealClock) {
        let clock = ManualRevealClock()
        let session = RevealSession(visibleDuration: duration, clock: clock)
        return (session, clock)
    }

    // MARK: - basic lifecycle

    func test_startsMasked() {
        let (s, _) = makeSession()
        XCTAssertEqual(s.state, .masked)
        XCTAssertFalse(s.isVisible)
        XCTAssertEqual(s.secondsRemaining, 0)
    }

    func test_revealMakesVisible() {
        let (s, _) = makeSession(duration: 60)
        s.reveal()
        XCTAssertTrue(s.isVisible)
        XCTAssertEqual(s.secondsRemaining, 60)
    }

    func test_tickBeforeExpiry_doesNothing() {
        let (s, clock) = makeSession(duration: 60)
        s.reveal()
        clock.advance(30)
        XCTAssertFalse(s.tick())
        XCTAssertTrue(s.isVisible)
        XCTAssertEqual(s.secondsRemaining, 30)
    }

    func test_tickAtExpiry_expiresAndWipes() {
        let (s, clock) = makeSession(duration: 60)
        var wipeCount = 0
        s.onWipe = { wipeCount += 1 }

        s.reveal()
        clock.advance(60)
        XCTAssertTrue(s.tick())
        XCTAssertEqual(s.state, .expired)
        XCTAssertFalse(s.isVisible)
        XCTAssertEqual(wipeCount, 1, "Expiry must wipe the credential exactly once.")
    }

    func test_expiredIsDistinctFromMasked() {
        // The UI needs to explain "it timed out" rather than looking like the value
        // was lost, so these are different states.
        let (s, clock) = makeSession(duration: 10)
        s.reveal()
        clock.advance(10)
        s.tick()
        XCTAssertEqual(s.state, .expired)
        XCTAssertNotEqual(s.state, .masked)
    }

    func test_minimumDurationEnforced() {
        // A 0- or 1-second window would be unusable and effectively a bug.
        let s = RevealSession(visibleDuration: 0, clock: ManualRevealClock())
        XCTAssertGreaterThanOrEqual(s.visibleDuration, 5)
    }

    // MARK: - manual masking

    func test_maskWipes() {
        let (s, _) = makeSession()
        var wiped = false
        s.onWipe = { wiped = true }
        s.reveal()
        s.mask()
        XCTAssertEqual(s.state, .masked)
        XCTAssertTrue(wiped)
    }

    func test_maskWhenNotVisible_doesNotWipe() {
        let (s, _) = makeSession()
        var wipeCount = 0
        s.onWipe = { wipeCount += 1 }
        s.mask()
        XCTAssertEqual(wipeCount, 0)
    }

    // MARK: - safety revocation

    func test_backgroundingRevokesAndWipes() {
        let (s, _) = makeSession()
        var wiped = false
        s.onWipe = { wiped = true }
        s.reveal()
        s.revoke(.appBackgrounded)
        XCTAssertEqual(s.state, .revokedForSafety(reason: .appBackgrounded))
        XCTAssertTrue(wiped)
        XCTAssertFalse(s.isVisible)
    }

    func test_screenRecordingRevokes() {
        let (s, _) = makeSession()
        s.reveal()
        s.revoke(.screenRecording)
        XCTAssertEqual(s.state, .revokedForSafety(reason: .screenRecording))
    }

    func test_screenshotRevokesEvenWhenNotVisible() {
        // A screenshot may land a frame after masking. The pixels already escaped, so
        // the user still needs to be told.
        let (s, _) = makeSession()
        s.revoke(.screenshotTaken)
        XCTAssertEqual(s.state, .revokedForSafety(reason: .screenshotTaken))
    }

    func test_otherRevocationsIgnoredWhenNotVisible() {
        let (s, _) = makeSession()
        s.revoke(.appBackgrounded)
        XCTAssertEqual(s.state, .masked, "No credential was on screen; nothing to revoke.")
    }

    func test_revocationMessagesAreNonEmptyAndSpecific() {
        for reason in [RevealRevocation.appBackgrounded, .screenRecording, .screenshotTaken, .signedOut] {
            XCTAssertFalse(reason.message.isEmpty, "\(reason) needs user-facing copy.")
        }
        // The screenshot message must be honest that the image contains the password.
        XCTAssertTrue(RevealRevocation.screenshotTaken.message.lowercased().contains("screenshot"))
        XCTAssertTrue(RevealRevocation.screenshotTaken.message.lowercased().contains("rotat"),
                      "A screenshot warrants a rotation recommendation.")
    }

    // MARK: - reveal again after expiry

    func test_canRevealAgainAfterExpiry_andWipesAgain() {
        let (s, clock) = makeSession(duration: 10)
        var wipeCount = 0
        s.onWipe = { wipeCount += 1 }

        s.reveal()
        clock.advance(10)
        s.tick()
        XCTAssertEqual(wipeCount, 1)

        s.reveal()
        XCTAssertTrue(s.isVisible)
        clock.advance(10)
        s.tick()
        XCTAssertEqual(wipeCount, 2, "A second reveal must also wipe on expiry.")
    }

    // MARK: - countdown display

    func test_progressGoesZeroToOne() {
        let (s, clock) = makeSession(duration: 100)
        s.reveal()
        XCTAssertEqual(s.progress, 0, accuracy: 0.01)
        clock.advance(50)
        XCTAssertEqual(s.progress, 0.5, accuracy: 0.01)
        clock.advance(50)
        XCTAssertEqual(s.progress, 1.0, accuracy: 0.01)
    }

    func test_secondsRemainingRoundsUp() {
        let (s, clock) = makeSession(duration: 60)
        s.reveal()
        clock.advance(0.4)
        XCTAssertEqual(s.secondsRemaining, 60, "Partial seconds round up so the label never jumps.")
    }

    func test_resetClearsAndWipes() {
        let (s, _) = makeSession()
        var wiped = false
        s.onWipe = { wiped = true }
        s.reveal()
        s.reset()
        XCTAssertEqual(s.state, .masked)
        XCTAssertTrue(wiped)
    }
}

final class BiometricPolicyTests: XCTestCase {

    func test_promptReasonNamesTheDevice() {
        let reason = BiometricPolicy.promptReason(deviceName: "WS-4821")
        XCTAssertTrue(reason.contains("WS-4821"),
                      "Naming the device tells the admin exactly what they're approving.")
    }

    func test_promptReasonWithoutDeviceStillReads() {
        let reason = BiometricPolicy.promptReason(deviceName: nil)
        XCTAssertFalse(reason.isEmpty)
        XCTAssertTrue(reason.lowercased().contains("administrator password"))
    }

    func test_promptReasonHandlesEmptyName() {
        let reason = BiometricPolicy.promptReason(deviceName: "")
        XCTAssertFalse(reason.contains("for ."), "An empty name must not produce broken copy.")
    }

    func test_noAuthConfiguredMessageTellsUserWhatToDo() {
        let msg = BiometricPolicy.noAuthConfiguredMessage
        XCTAssertTrue(msg.lowercased().contains("passcode"))
        XCTAssertTrue(msg.lowercased().contains("settings"),
                      "Error copy should name the fix, not just the problem.")
    }

    func test_availabilityCanAuthenticate() {
        XCTAssertTrue(BiometricAvailability.biometricsAvailable(kind: .faceID).canAuthenticate)
        XCTAssertTrue(BiometricAvailability.passcodeOnly.canAuthenticate)
        XCTAssertTrue(BiometricAvailability.biometricsLockedOut.canAuthenticate,
                      "Lockout still permits passcode entry, so the gate can run.")
        XCTAssertFalse(BiometricAvailability.noneConfigured.canAuthenticate)
    }

    func test_biometricKindDisplayNames() {
        XCTAssertEqual(BiometricKind.faceID.rawValue, "Face ID")
        XCTAssertEqual(BiometricKind.touchID.rawValue, "Touch ID")
    }
}
