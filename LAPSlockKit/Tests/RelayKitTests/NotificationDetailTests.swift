import XCTest
@testable import RelayKit

/// How much a notification may show under an organization's Intune app protection policy.
/// The app writes the answer and the notification extension reads it, so the reading has to
/// fail toward showing less.
final class NotificationDetailTests: XCTestCase {

    private var suite = ""
    private var defaults: UserDefaults!

    override func setUp() {
        suite = "NotificationDetailTests-" + UUID().uuidString
        defaults = UserDefaults(suiteName: suite)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suite)
    }

    func testNothingStoredMeansNoPolicyAndEverythingIsShown() {
        XCTAssertEqual(NotificationDetail.current(in: defaults), .full)
        let shown = NotificationDetail.full.shown(title: "Break-glass sign-in", body: "admin signed in from Lagos")
        XCTAssertEqual(shown?.title, "Break-glass sign-in")
        XCTAssertEqual(shown?.body, "admin signed in from Lagos")
    }

    func testEachAnswerIsReadBackAsItWasWritten() {
        for detail in NotificationDetail.allCases {
            detail.store(in: defaults)
            XCTAssertEqual(NotificationDetail.current(in: defaults), detail)
        }
        // Back to no policy leaves nothing behind.
        NotificationDetail.full.store(in: defaults)
        XCTAssertNil(defaults.object(forKey: NotificationDetail.defaultsKey))
    }

    func testADamagedValueShowsLessNotMore() {
        defaults.set("everything", forKey: NotificationDetail.defaultsKey)
        XCTAssertEqual(NotificationDetail.current(in: defaults), .withoutDetails)
    }

    func testWithoutDetailsSaysOnlyThatSomethingHappened() {
        let shown = NotificationDetail.withoutDetails.shown(title: "Break-glass sign-in", body: "admin signed in from Lagos")
        XCTAssertEqual(shown?.title, "TenantKeep")
        XCTAssertEqual(shown?.body, "You have an alert. Open TenantKeep to read it.")
        XCTAssertNil(NotificationDetail.none.shown(title: "Break-glass sign-in", body: "admin signed in from Lagos"))
    }
}
