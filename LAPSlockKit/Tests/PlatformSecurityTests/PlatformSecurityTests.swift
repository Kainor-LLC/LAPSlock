import XCTest
@testable import PlatformSecurity

// Build Spec §13, tests for the security behaviors around a revealed credential.
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

    func test_aScreenshotJustAfterMaskingStillWarns() {
        // A screenshot may land a frame after masking. The pixels may already have
        // escaped, so the user still needs to be told.
        let (s, clock) = makeSession()
        s.reveal()
        s.mask()
        clock.advance(1)
        s.revoke(.screenshotTaken)
        XCTAssertEqual(s.state, .revokedForSafety(reason: .screenshotTaken))
    }

    func test_aScreenshotOfAPageThatNeverRevealedDoesNotWarn() {
        let (s, _) = makeSession()
        s.revoke(.screenshotTaken)
        XCTAssertEqual(s.state, .masked, "a picture of a masked card holds no password")
    }

    func test_aScreenshotLongAfterARevealEndedDoesNotWarn() {
        let (s, clock) = makeSession()
        s.reveal()
        clock.advance(61)
        s.tick()
        XCTAssertEqual(s.state, .expired)
        clock.advance(RevealSession.screenshotGrace + 1)
        s.revoke(.screenshotTaken)
        XCTAssertEqual(s.state, .expired)
    }

    func test_aScreenshotWhileRevealedWarnsAndHides() {
        let (s, _) = makeSession()
        s.reveal()
        s.revoke(.screenshotTaken)
        XCTAssertEqual(s.state, .revokedForSafety(reason: .screenshotTaken))
        XCTAssertFalse(s.isVisible)
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
        let reason = BiometricPolicy.promptReason(for: .revealPassword(device: "WS-4821"))
        XCTAssertEqual(reason, "Confirm it's you to reveal the local administrator password for WS-4821.",
                       "Naming the device tells the admin exactly what they're approving.")
    }

    func test_promptReasonWithoutDeviceStillReads() {
        let reason = BiometricPolicy.promptReason(for: .revealPassword(device: nil))
        XCTAssertEqual(reason, "Confirm it's you to reveal the local administrator password.")
    }

    func test_promptReasonHandlesEmptyName() {
        let reasons = [
            BiometricPolicy.promptReason(for: .revealPassword(device: "")),
            BiometricPolicy.promptReason(for: .revealRecoveryKey(device: " ")),
            BiometricPolicy.promptReason(for: .deviceAction(title: "Retire", device: "")),
            BiometricPolicy.promptReason(for: .userAction(title: "Revoke sessions", person: "")),
            BiometricPolicy.promptReason(for: .issueTemporaryAccessPass(person: nil)),
            BiometricPolicy.promptReason(for: .groupChange(adding: false, member: "", group: nil)),
            BiometricPolicy.promptReason(for: .approval(approve: true, requester: "")),
        ]
        for reason in reasons {
            XCTAssertFalse(reason.contains(" ."), "An empty name must not produce broken copy: \(reason)")
            XCTAssertFalse(reason.contains("  "), reason)
            XCTAssertTrue(reason.hasPrefix("Confirm it's you to ") && reason.hasSuffix("."), reason)
        }
        XCTAssertEqual(reasons[5], "Confirm it's you to remove this person.")
    }

    func test_eachPurposeSaysWhatIsBeingConfirmed() {
        XCTAssertEqual(BiometricPolicy.promptReason(for: .revealRecoveryKey(device: "DESKTOP-FRONT01")),
                       "Confirm it's you to reveal a BitLocker recovery key for DESKTOP-FRONT01.")
        XCTAssertEqual(BiometricPolicy.promptReason(for: .openApp), "Confirm it's you to open TenantKeep.")
        XCTAssertEqual(BiometricPolicy.promptReason(for: .deviceAction(title: "Retire", device: "DESKTOP-FRONT01")),
                       "Confirm it's you to send Retire to DESKTOP-FRONT01.")
        XCTAssertEqual(BiometricPolicy.promptReason(for: .userAction(title: "Remove all sign-in methods", person: "Jane Okafor")),
                       "Confirm it's you to send Remove all sign-in methods for Jane Okafor.")
        XCTAssertEqual(BiometricPolicy.promptReason(for: .issueTemporaryAccessPass(person: "Jane Okafor")),
                       "Confirm it's you to issue a Temporary Access Pass for Jane Okafor.")
        XCTAssertEqual(BiometricPolicy.promptReason(for: .groupChange(adding: false, member: "Jane Okafor", group: "Sales Team")),
                       "Confirm it's you to remove Jane Okafor from Sales Team.")
        XCTAssertEqual(BiometricPolicy.promptReason(for: .groupChange(adding: true, member: "Jane Okafor", group: "Sales Team")),
                       "Confirm it's you to add Jane Okafor to Sales Team.")
        XCTAssertEqual(BiometricPolicy.promptReason(for: .approval(approve: true, requester: "Sam Reyes")),
                       "Confirm it's you to approve the request from Sam Reyes.")
        XCTAssertEqual(BiometricPolicy.promptReason(for: .approval(approve: false, requester: "Sam Reyes")),
                       "Confirm it's you to deny the request from Sam Reyes.")
    }

    func test_onlyARevealedPasswordIsCalledAPassword() {
        let others: [BiometricPurpose] = [
            .revealRecoveryKey(device: "D"), .openApp, .deviceAction(title: "Wipe", device: "D"),
            .userAction(title: "Block sign-in", person: "P"), .issueTemporaryAccessPass(person: "P"),
            .groupChange(adding: true, member: "P", group: "G"), .approval(approve: false, requester: "P"),
        ]
        for purpose in others {
            XCTAssertFalse(BiometricPolicy.promptReason(for: purpose).lowercased().contains("password"), "\(purpose)")
        }
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
