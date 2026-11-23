import XCTest
import Foundation
@testable import AuthKit

/// What a launch restores, and what a sign-out leaves behind. The sign-in manager itself
/// only exists on iOS and cannot run here, so the decision it follows is a pure function
/// tested directly, and two of the manager's shapes are held by reading its source.
final class SessionRestoreTests: XCTestCase {

    // MARK: - the decision

    func testAnInstallOnTheReadRegistrationRestoresThroughItAndNothingElse() {
        XCTAssertEqual(SessionRestore.plan(readAccounts: 1, originalAccounts: 0), .through(.read))
        // The person is still cached on the original registration after finishing the
        // update. That must not make it a fallback: its tokens carry every write.
        XCTAssertEqual(SessionRestore.plan(readAccounts: 1, originalAccounts: 1), .through(.read))
        XCTAssertEqual(SessionRestore.plan(readAccounts: 1, originalAccounts: 3), .through(.read))
    }

    func testOnlyAnInstallThatNeverMovedReadsThroughTheOriginal() {
        XCTAssertEqual(SessionRestore.plan(readAccounts: 0, originalAccounts: 1), .through(.actions))
    }

    func testNothingCachedMeansTheSignInScreen() {
        XCTAssertEqual(SessionRestore.plan(readAccounts: 0, originalAccounts: 0), .signIn)
    }

    /// 1.0 had no same-account check, so its cache can hold an administrator beside the
    /// technician. Picking one could sign the phone in as the wrong person.
    func testMoreThanOnePersonInACacheIsNeverRestored() {
        XCTAssertEqual(SessionRestore.plan(readAccounts: 2, originalAccounts: 0), .clearThenSignIn)
        XCTAssertEqual(SessionRestore.plan(readAccounts: 2, originalAccounts: 1), .clearThenSignIn)
        XCTAssertEqual(SessionRestore.plan(readAccounts: 0, originalAccounts: 2), .clearThenSignIn)
    }

    func testNoPlanFallsBackFromTheReadRegistrationToAWriteOne() {
        for read in 1...3 {
            for original in 0...3 {
                if case .through(let registration) = SessionRestore.plan(readAccounts: read, originalAccounts: original) {
                    XCTAssertEqual(registration, .read)
                }
            }
        }
    }

    // MARK: - the manager follows it

    private func managerSource() throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent("Sources/AuthKitMSAL/MSALAuthManager.swift"), encoding: .utf8)
    }

    private func function(_ signature: String, in source: String) throws -> Substring {
        let start = try XCTUnwrap(source.range(of: signature), signature + " not found")
        let rest = source[start.upperBound...]
        let end = rest.range(of: "\n    }\n")?.upperBound ?? rest.endIndex
        return rest[..<end]
    }

    /// Restore asks the plan, tries one registration, and has no second attempt.
    func testRestoreFollowsThePlanWithNoSecondAttempt() throws {
        let source = try managerSource()
        let restore = try function("public func restoreSession() async -> AdminAccount? {", in: source)
        XCTAssertTrue(restore.contains("SessionRestore.plan("))
        XCTAssertEqual(restore.components(separatedBy: "await restore(through:").count - 1, 1, "restore is attempted through more than one registration")
        XCTAssertFalse(restore.contains("restore(through: .actions)"), "the original registration is named as a fallback again")
        // Whoever else is cached goes when a session is restored, and everyone goes when
        // the cache held more than one person.
        XCTAssertTrue(restore.contains("removeAccounts(except: account.id, keepingPrimary: false)"))
        XCTAssertTrue(restore.contains("removeAccounts(except: nil, keepingPrimary: false)"))
    }

    /// Sign-out empties every registration and clears the session even when Microsoft's
    /// own sign-out throws: both are deferred, ahead of anything that can throw.
    func testSignOutLeavesNobodyCachedEvenWhenItThrows() throws {
        let source = try managerSource()
        let signOut = try function("public func signOut(account: AdminAccount) async throws {", in: source)
        let sweep = try XCTUnwrap(signOut.range(of: "defer { removeAccounts(except: nil, keepingPrimary: false) }"))
        let clear = try XCTUnwrap(signOut.range(of: "defer { if pinnedAccount?.id == account.id { clearSession() } }"))
        let firstThrow = try XCTUnwrap(signOut.range(of: "try "))
        XCTAssertLessThan(sweep.lowerBound, firstThrow.lowerBound)
        XCTAssertLessThan(clear.lowerBound, firstThrow.lowerBound)
    }

    /// When someone else answers a prompt, their session is swept from every registration,
    /// not only removed once with the failure ignored.
    func testADifferentAccountIsSweptFromEveryRegistration() throws {
        let source = try managerSource()
        let guardStart = try XCTUnwrap(source.range(of: "guard result.account.identifier == account.id else {"))
        let thrown = try XCTUnwrap(source.range(of: "throw AuthError.differentAccount", range: guardStart.upperBound..<source.endIndex))
        XCTAssertTrue(source[guardStart.upperBound..<thrown.lowerBound].contains("removeAccounts(except: account.id, keepingPrimary: false)"))
    }
}
