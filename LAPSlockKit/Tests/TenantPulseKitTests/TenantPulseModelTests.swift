import XCTest
import AuthKit
@testable import TenantPulseKit

final class TenantPulseModelTests: XCTestCase {

    private let now = Date()

    // MARK: decoding

    private struct Page<T: Decodable>: Decodable { let value: [T] }

    func test_healthOverviewAndIssueDecodeFromGraphShapes() throws {
        let overviews = #"{"value":[{"id":"Exchange","service":"Exchange Online","status":"serviceDegradation"},{"id":"Intune","service":"Microsoft Intune","status":"serviceOperational"}]}"#
        let decoded = try GraphClient.decoder.decode(Page<ServiceHealthOverview>.self, from: Data(overviews.utf8)).value
        XCTAssertEqual(decoded.count, 2)
        XCTAssertFalse(decoded[0].isOperational)
        XCTAssertEqual(decoded[0].statusLabel, "Service degradation")
        XCTAssertTrue(decoded[1].isOperational)

        let issues = #"{"value":[{"id":"EX1","title":"Mail delays","service":"Exchange Online","feature":"E-Mail","classification":"incident","status":"serviceDegradation","startDateTime":"2026-10-25T10:00:00Z","lastModifiedDateTime":"2026-10-25T12:00:00.1234567Z","isResolved":false,"impactDescription":"Some users.","origin":"microsoft","posts":[]}]}"#
        let issue = try GraphClient.decoder.decode(Page<ServiceIssue>.self, from: Data(issues.utf8)).value[0]
        XCTAssertTrue(issue.isIncident)
        XCTAssertTrue(issue.isActive)
        XCTAssertNotNil(issue.lastModifiedDateTime)
    }

    func test_messageDecodesWithCapitalisedEnumsAndExtraFields() throws {
        let json = #"{"value":[{"id":"MC1","title":"Retirement","category":"PlanForChange","severity":"High","isMajorChange":true,"actionRequiredByDateTime":"2026-12-01T00:00:00Z","startDateTime":"2026-10-01T00:00:00Z","endDateTime":null,"lastModifiedDateTime":"2026-10-20T00:00:00Z","services":["Microsoft Entra"],"tags":["Admin impact"],"expiryDateTime":null,"hasAttachments":false,"viewPoint":null,"body":{"contentType":"html","content":"<p>x</p>"}}]}"#
        let message = try GraphClient.decoder.decode(Page<ServiceMessage>.self, from: Data(json.utf8)).value[0]
        XCTAssertTrue(message.isPlanForChange)
        XCTAssertTrue(message.isActionRequired)
        XCTAssertTrue(message.isWorthShowing)
        XCTAssertEqual(message.categoryLabel, "Plan for change")
        XCTAssertEqual(message.services, ["Microsoft Entra"])
    }

    func test_stayInformedWithoutDeadlineIsNotWorthShowing() {
        let quiet = ServiceMessage(id: "a", title: "Icon", category: "stayInformed", isMajorChange: false, actionRequiredByDateTime: nil, lastModifiedDateTime: now)
        let major = ServiceMessage(id: "b", title: "Big", category: "stayInformed", isMajorChange: true, actionRequiredByDateTime: nil, lastModifiedDateTime: now)
        let fix = ServiceMessage(id: "c", title: "Fix", category: "preventOrFixIssue", isMajorChange: false, actionRequiredByDateTime: nil, lastModifiedDateTime: now)
        XCTAssertFalse(quiet.isWorthShowing)
        XCTAssertTrue(major.isWorthShowing)
        XCTAssertTrue(fix.isWorthShowing)
        XCTAssertTrue(fix.isActionRequired)
    }

    func test_messagesSortDeadlinesFirstThenMajorThenNewest() {
        let soon = ServiceMessage(id: "soon", title: nil, category: "planForChange", isMajorChange: false, actionRequiredByDateTime: now.addingTimeInterval(5 * 86_400), lastModifiedDateTime: now.addingTimeInterval(-10 * 86_400))
        let later = ServiceMessage(id: "later", title: nil, category: "planForChange", isMajorChange: true, actionRequiredByDateTime: now.addingTimeInterval(40 * 86_400), lastModifiedDateTime: now)
        let major = ServiceMessage(id: "major", title: nil, category: "planForChange", isMajorChange: true, actionRequiredByDateTime: nil, lastModifiedDateTime: now.addingTimeInterval(-3 * 86_400))
        let newest = ServiceMessage(id: "newest", title: nil, category: "planForChange", isMajorChange: false, actionRequiredByDateTime: nil, lastModifiedDateTime: now)
        let older = ServiceMessage(id: "older", title: nil, category: "planForChange", isMajorChange: false, actionRequiredByDateTime: nil, lastModifiedDateTime: now.addingTimeInterval(-9 * 86_400))
        let sorted = MessageOrdering.sort([older, newest, major, later, soon])
        XCTAssertEqual(sorted.map(\.id), ["soon", "later", "major", "newest", "older"])
    }

    // MARK: expiring

    func test_bucketsAndDaysLeft() {
        let expired = ExpiringItem(id: "a", kind: .appSecret, owner: "x", detail: nil, expiresAt: now.addingTimeInterval(-2 * 86_400))
        let soon = ExpiringItem(id: "b", kind: .appSecret, owner: "x", detail: nil, expiresAt: now.addingTimeInterval(10 * 86_400))
        let quarter = ExpiringItem(id: "c", kind: .appSecret, owner: "x", detail: nil, expiresAt: now.addingTimeInterval(60 * 86_400))
        let far = ExpiringItem(id: "d", kind: .appSecret, owner: "x", detail: nil, expiresAt: now.addingTimeInterval(200 * 86_400))
        XCTAssertEqual(expired.bucket(now: now), .expired)
        XCTAssertEqual(soon.bucket(now: now), .within30Days)
        XCTAssertEqual(quarter.bucket(now: now), .within90Days)
        XCTAssertEqual(far.bucket(now: now), .later)
        XCTAssertEqual(soon.daysLeft(now: now), 10)
        XCTAssertEqual(expired.daysLeft(now: now), -2)
        XCTAssertTrue(ExpiringItem.Bucket.expired < .within30Days)
    }

    func test_relevantWindowKeepsNinetyDaysAheadAndThirtyBehind() {
        let items = [
            ExpiringItem(id: "old", kind: .appSecret, owner: "x", detail: nil, expiresAt: now.addingTimeInterval(-40 * 86_400)),
            ExpiringItem(id: "recent", kind: .appSecret, owner: "x", detail: nil, expiresAt: now.addingTimeInterval(-5 * 86_400)),
            ExpiringItem(id: "soon", kind: .appSecret, owner: "x", detail: nil, expiresAt: now.addingTimeInterval(20 * 86_400)),
            ExpiringItem(id: "far", kind: .appSecret, owner: "x", detail: nil, expiresAt: now.addingTimeInterval(120 * 86_400)),
        ]
        XCTAssertEqual(ExpiryWindow.relevant(items, now: now).map(\.id), ["recent", "soon"])
    }

    // MARK: Secure Score

    func test_secureScoreSummaryPicksLatestAndNearestWeekAgo() {
        func snap(_ daysAgo: Double, _ score: Double, identity: Double) -> SecureScoreSnapshot {
            SecureScoreSnapshot(id: "\(daysAgo)", createdDateTime: now.addingTimeInterval(-daysAgo * 86_400), currentScore: score, maxScore: 1000,
                                controlScores: [.init(controlCategory: "Identity", controlName: "a", score: identity), .init(controlCategory: "Device", controlName: "b", score: 10)])
        }
        let summary = SecureScoreSummary.make(from: [snap(3, 500, identity: 100), snap(0, 520, identity: 110), snap(8, 480, identity: 90), snap(6, 490, identity: 95)])
        XCTAssertEqual(summary?.latest.currentScore, 520)
        XCTAssertEqual(summary?.weekAgo?.currentScore, 490)
        XCTAssertEqual(summary?.change, 30)
        XCTAssertEqual(summary?.latest.identityScore, 110)
        XCTAssertEqual(summary?.identityChange, 15)
        XCTAssertEqual(summary?.history.count, 4)
    }

    func test_thirtyDayWindowNeedsAComparisonAtLeastFifteenDaysBack() {
        func snap(_ daysAgo: Double, _ score: Double) -> SecureScoreSnapshot {
            SecureScoreSnapshot(id: "\(daysAgo)", createdDateTime: now.addingTimeInterval(-daysAgo * 86_400), currentScore: score, maxScore: 1000, controlScores: nil)
        }
        let month = SecureScoreSummary.make(from: [snap(0, 600), snap(7, 590), snap(29, 550)])
        XCTAssertEqual(month?.change(overDays: 30), 50)
        XCTAssertEqual(month?.change(overDays: 7), 10)
        let shortHistory = SecureScoreSummary.make(from: [snap(0, 600), snap(7, 590)])
        XCTAssertEqual(shortHistory?.change(overDays: 7), 10)
        XCTAssertNil(shortHistory?.change(overDays: 30), "a week-old snapshot must not pose as a month")
        XCTAssertNil(shortHistory?.comparison(daysBack: 0))
    }

    func test_secureScoreWithOneSnapshotHasNoChange() {
        let only = SecureScoreSnapshot(id: "a", createdDateTime: now, currentScore: 500, maxScore: 1000, controlScores: nil)
        let summary = SecureScoreSummary.make(from: [only])
        XCTAssertNil(summary?.weekAgo)
        XCTAssertNil(summary?.change)
        XCTAssertNil(summary?.latest.identityScore)
        XCTAssertNil(SecureScoreSummary.make(from: []))
    }

    func test_secureScoreDecodesFromGraph() throws {
        let json = #"{"value":[{"id":"s1","createdDateTime":"2026-10-25T00:00:00Z","currentScore":612.0,"maxScore":1176.0,"azureTenantId":"t","controlScores":[{"controlCategory":"Identity","controlName":"AdminMFAV2","score":50.0,"description":"x"},{"controlCategory":"Data","controlName":"X","score":5.0}]}]}"#
        let snapshot = try GraphClient.decoder.decode(Page<SecureScoreSnapshot>.self, from: Data(json.utf8)).value[0]
        XCTAssertEqual(snapshot.currentScore, 612)
        XCTAssertEqual(snapshot.identityScore, 50)
    }

    func test_vocabularyFallsThroughToTheRawValue() {
        XCTAssertEqual(TenantPulseVocabulary.healthStatusLabel("somethingNew"), "somethingNew")
        XCTAssertEqual(TenantPulseVocabulary.messageCategoryLabel(nil), "Message")
        XCTAssertEqual(ExpiringItem.Kind.applePushCertificate.label, "Apple MDM push certificate")
    }
}
