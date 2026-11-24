import XCTest
import Foundation
@testable import AuthKit

/// Which registration a provider's customers read through after an update from before the
/// split. Approval is per organization, so the move is: a customer that has not approved
/// the read registration keeps the original one, and a customer that has moved never goes
/// back. The decision and the list are pure and tested directly; the sign-in manager only
/// exists with the sign-in library, so the shapes it must keep are held by reading its source.
final class ReadRoutesTests: XCTestCase {

    private let home = "11111111-1111-4111-8111-111111111111"
    private let contoso = "22222222-2222-4222-8222-222222222222"
    private let fabrikam = "33333333-3333-4333-8333-333333333333"
    /// Two people in the same organization, as the sign-in library names accounts.
    private let jane = "aaaaaaaa-0000-4000-8000-000000000001.11111111-1111-4111-8111-111111111111"
    private let sam = "aaaaaaaa-0000-4000-8000-000000000002.11111111-1111-4111-8111-111111111111"

    private func store() -> ReadRouteStore {
        let name = "ReadRoutesTests." + UUID().uuidString
        let defaults = UserDefaults(suiteName: name)!
        addTeardownBlock { defaults.removePersistentDomain(forName: name) }
        return ReadRouteStore(defaults: defaults)
    }

    // MARK: - reading a failed silent request

    func testEntrasConsentCodesMeanNotApproved() {
        for code in ["AADSTS65001", "AADSTS90094", "AADSTS900971", "AADSTS700016", "aadsts65001"] {
            XCTAssertEqual(RouteProbe.failure(aadCode: code, subError: nil, interactionRequired: true), .notApproved, code)
        }
        XCTAssertEqual(RouteProbe.failure(aadCode: nil, subError: "consent_required", interactionRequired: true), .notApproved)
    }

    func testAnyOtherPromptIsNotAnAnswerAboutApproval() {
        // Multifactor authentication wanted, a session too old: the registration may be approved.
        XCTAssertEqual(RouteProbe.failure(aadCode: "AADSTS50076", subError: "basic_action", interactionRequired: true), .needsPrompt)
        XCTAssertEqual(RouteProbe.failure(aadCode: nil, subError: nil, interactionRequired: true), .needsPrompt)
    }

    func testAFailureThatIsNotAPromptDecidesNothing() {
        XCTAssertEqual(RouteProbe.failure(aadCode: nil, subError: nil, interactionRequired: false), .failed)
        XCTAssertEqual(RouteProbe.failure(aadCode: "AADSTS90033", subError: "", interactionRequired: false), .failed)
    }

    // MARK: - the decision

    func testTheReadRegistrationWinsWheneverItAnswers() {
        for original in [RouteProbe.token, .notApproved, .needsPrompt, .failed] {
            for asked in [false, true] {
                XCTAssertEqual(ReadRoutes.settle(read: .token, original: original, askedReadBefore: asked), .read)
            }
        }
    }

    func testACustomerThatHasNotApprovedTheReadOneStaysOnTheOriginal() {
        XCTAssertEqual(ReadRoutes.settle(read: .notApproved, original: .token, askedReadBefore: false), .original)
        XCTAssertEqual(ReadRoutes.settle(read: .needsPrompt, original: .token, askedReadBefore: false), .original)
        // Even when the read registration gave no answer at all: the customer is where it
        // already was, and it is tried on the read registration again next time.
        XCTAssertEqual(ReadRoutes.settle(read: .failed, original: .token, askedReadBefore: false), .original)
    }

    func testThePersonIsAskedThroughTheOriginalOnlyWhenTheReadOneIsRuledOut() {
        // Entra said outright that the read registration is not approved there.
        XCTAssertEqual(ReadRoutes.settle(read: .notApproved, original: .needsPrompt, askedReadBefore: false), .ask(.actions))
        // Otherwise the read registration is asked first.
        XCTAssertEqual(ReadRoutes.settle(read: .needsPrompt, original: .needsPrompt, askedReadBefore: false), .ask(.read))
        XCTAssertEqual(ReadRoutes.settle(read: .needsPrompt, original: .notApproved, askedReadBefore: false), .ask(.read))
        XCTAssertEqual(ReadRoutes.settle(read: .needsPrompt, original: .failed, askedReadBefore: false), .ask(.read))
        // And once that has been tried without a token, the second try goes the other way,
        // so a customer whose prompt hides a missing approval is not asked the same thing forever.
        XCTAssertEqual(ReadRoutes.settle(read: .needsPrompt, original: .needsPrompt, askedReadBefore: true), .ask(.actions))
        // Never through the original when it is itself ruled out.
        XCTAssertEqual(ReadRoutes.settle(read: .needsPrompt, original: .notApproved, askedReadBefore: true), .ask(.read))
    }

    func testACustomerThatApprovedNeitherIsSentTheLinkNotAPrompt() {
        XCTAssertEqual(ReadRoutes.settle(read: .notApproved, original: .notApproved, askedReadBefore: false), .notApproved)
    }

    func testNoAnswerChangesNothing() {
        XCTAssertEqual(ReadRoutes.settle(read: .failed, original: .failed, askedReadBefore: false), .fail)
        XCTAssertEqual(ReadRoutes.settle(read: .failed, original: .needsPrompt, askedReadBefore: false), .fail)
        XCTAssertEqual(ReadRoutes.settle(read: .failed, original: .notApproved, askedReadBefore: false), .fail)
        XCTAssertEqual(ReadRoutes.settle(read: .notApproved, original: .failed, askedReadBefore: false), .fail)
    }

    // MARK: - the list

    func testTheCustomersSavedWhenTheOwnOrganizationMovesAreTheOnesThatWait() {
        let routes = store()
        XCTAssertFalse(routes.waits(contoso, home: home), "nothing waits before the person's own organization has moved")

        routes.begin(home: home, person: jane, waiting: [contoso, fabrikam.uppercased(), home])
        XCTAssertTrue(routes.waits(contoso, home: home))
        XCTAssertTrue(routes.waits(fabrikam, home: home.uppercased()))
        XCTAssertFalse(routes.waits(home, home: home), "the person's own organization has just moved")
        XCTAssertFalse(routes.waits("44444444-4444-4444-8444-444444444444", home: home), "a customer added later reads through the read registration")
    }

    func testACustomerThatMovesNeverGoesBack() {
        let routes = store()
        routes.begin(home: home, person: jane, waiting: [contoso, fabrikam])
        routes.remove(contoso, home: home)
        XCTAssertFalse(routes.waits(contoso, home: home))
        XCTAssertTrue(routes.waits(fabrikam, home: home))

        // A second sign-in manager that read the list before the move cannot put it back:
        // the store has no call that adds one customer.
        let stale = routes
        stale.remove(fabrikam, home: home)
        XCTAssertFalse(routes.waits(contoso, home: home))
        XCTAssertEqual(routes.waiting(home: home), [])
    }

    func testTheListIsForOnePersonsOrganizationAndGoesWithTheirSession() {
        let routes = store()
        routes.begin(home: home, person: jane, waiting: [contoso])
        XCTAssertEqual(routes.waiting(home: fabrikam), [], "someone from another organization does not inherit it")

        routes.keep(onlyFor: home, person: jane)
        XCTAssertTrue(routes.waits(contoso, home: home))
        routes.keep(onlyFor: fabrikam, person: jane)
        XCTAssertFalse(routes.waits(contoso, home: home), "restoring someone else drops it")

        routes.begin(home: home, person: jane, waiting: [contoso])
        routes.clear()
        XCTAssertEqual(routes.waiting(home: home), [])
    }

    /// Second review, R2-1: a sign-in the session needed (a sign-in frequency policy, a
    /// changed password, a revoke) went through the sign-in screen, which cleared the list,
    /// and the waiting customers then failed through the read registration.
    func testASignInByThePersonWhoBeganTheListKeepsIt() {
        let routes = store()
        routes.begin(home: home, person: jane, waiting: [contoso, fabrikam])
        routes.keep(onlyFor: home, person: jane.uppercased())
        XCTAssertEqual(routes.waiting(home: home), [contoso, fabrikam])
    }

    func testAnyoneElseInTheSameOrganizationStartsWithNone() {
        let routes = store()
        routes.begin(home: home, person: jane, waiting: [contoso])
        routes.keep(onlyFor: home, person: sam)
        XCTAssertEqual(routes.waiting(home: home), [])
        routes.keep(onlyFor: home, person: jane)
        XCTAssertEqual(routes.waiting(home: home), [], "once dropped it does not come back")
    }

    /// Build 14 kept no person with the list, and cleared it at every sign-in, so the one
    /// session holding it is the one that began it.
    func testAListFromBeforeThePersonWasKeptIsAdoptedOnce() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ReadRoutesTests.adopt." + UUID().uuidString))
        defaults.set(home, forKey: "readRoute.home")
        defaults.set([contoso], forKey: "readRoute.waiting")
        let routes = ReadRouteStore(defaults: defaults)
        routes.keep(onlyFor: home, person: jane)
        XCTAssertEqual(routes.waiting(home: home), [contoso])
        routes.keep(onlyFor: home, person: sam)
        XCTAssertEqual(routes.waiting(home: home), [], "adopted by the first person, so not anyone's after")
    }

    func testTheListDoesNotKeepThePersonsIdentifier() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ReadRoutesTests.digest." + UUID().uuidString))
        ReadRouteStore(defaults: defaults).begin(home: home, person: jane, waiting: [contoso])
        let kept = defaults.dictionaryRepresentation().filter { $0.key.hasPrefix("readRoute.") }
        XCTAssertEqual(Set(kept.keys), ["readRoute.home", "readRoute.waiting", "readRoute.person"])
        XCTAssertFalse(String(describing: kept).contains("aaaaaaaa-0000"), "a digest, not the identifier")
        ReadRouteStore(defaults: defaults).clear()
        XCTAssertTrue(defaults.dictionaryRepresentation().keys.filter { $0.hasPrefix("readRoute.") }.isEmpty)
    }

    func testAProviderWithNoCustomersKeepsNoList() {
        let routes = store()
        routes.begin(home: home, person: jane, waiting: [])
        XCTAssertEqual(routes.waiting(home: home), [])
        XCTAssertFalse(ReadRouteStore.none.waits(contoso, home: home))
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

    /// The list is added to in one place: when the person's own organization moves.
    /// Everything else takes a customer off it.
    func testOnlyFinishingTheUpdateAddsToTheList() throws {
        let source = try managerSource()
        XCTAssertEqual(source.components(separatedBy: "readRoutes.begin(").count - 1, 1)
        let move = try function("public func moveReadsToReadRegistration(customers: [String] = []) async throws {", in: source)
        let signedIn = try XCTUnwrap(move.range(of: "interactiveToken(read, scopes: Self.baseScopes, account: account, pin: home, claims: nil)"))
        let begun = try XCTUnwrap(move.range(of: "readRoutes.begin("))
        XCTAssertLessThan(signedIn.lowerBound, begun.lowerBound, "nothing is recorded until the person's own organization has moved")
    }

    /// A waiting customer is tried on the read registration before the original, and the
    /// original is only where it already was.
    func testAWaitingCustomerIsTriedOnTheReadRegistrationFirst() throws {
        let source = try managerSource()
        let settle = try function("private func settleReadRoute(for pin: TenantPin, account: AdminAccount) async throws {", in: source)
        let read = try XCTUnwrap(settle.range(of: "await probe(.read, pin: pin, account: account)"))
        let original = try XCTUnwrap(settle.range(of: "await probe(.actions, pin: pin, account: account)"))
        XCTAssertLessThan(read.lowerBound, original.lowerBound)
        XCTAssertTrue(settle.contains("ReadRoutes.settle("))

        // Only a customer on the list is settled this way. Everyone else switches as before.
        let switching = try function("public func setActiveTenant(_ tenantId: String?) async throws {", in: source)
        XCTAssertTrue(switching.contains("if waits(pin.expected) {"))
        XCTAssertEqual(source.components(separatedBy: "settleReadRoute(for: ").count - 1, 1, "entering a customer is the only caller")
    }

    /// While the session itself lives on the original registration the list is not
    /// consulted, and a person with no session on the original does not get one to read through.
    func testTheListMeansNothingBeforeTheOwnOrganizationHasMoved() throws {
        let source = try managerSource()
        let waits = try function("private func waits(_ tenant: String) -> Bool {", in: source)
        XCTAssertTrue(waits.contains("guard !sessionOnOriginal,"))
        let probe = try function("private func probe(_ registration: AppRegistration, pin: TenantPin, account: AdminAccount) async -> ProbeAnswer {", in: source)
        XCTAssertTrue(probe.contains("registration == .actions ? .notApproved : .needsPrompt"))
        XCTAssertFalse(probe.contains("acquireInteractive"), "a probe never shows a prompt")
    }

    /// A sign-out drops the list. A sign-in and a restore keep it only for the person who
    /// began it (R2-1).
    func testASignOutDropsTheListAndASignInKeepsItForItsPerson() throws {
        let source = try managerSource()
        let signIn = try function("public func signIn() async throws -> AdminAccount {", in: source)
        XCTAssertTrue(signIn.contains("readRoutes.keep(onlyFor: account.tenantId, person: account.id)"))
        XCTAssertFalse(signIn.contains("forgetReadRoutes()"))
        XCTAssertTrue(try function("private func clearSession() {", in: source).contains("forgetReadRoutes()"))
        XCTAssertTrue(try function("private func restore(through registration: AppRegistration) async -> AdminAccount? {", in: source)
            .contains("readRoutes.keep(onlyFor: account.tenantId, person: account.id)"))
        XCTAssertTrue(source.contains("readRoutes.begin(home: home.expected, person: account.id, waiting: waiting)"))
    }
}
