import XCTest
import AuthKit
@testable import SignInTriageKit

final class SignInTriageModelTests: XCTestCase {

    private struct Page<T: Decodable>: Decodable { let value: [T] }

    func test_signInDecodesFromGraphShape() throws {
        let json = #"{"value":[{"id":"s1","createdDateTime":"2026-10-25T12:00:00.1234567Z","userDisplayName":"Jane","userPrincipalName":"jane@contoso.com","userId":"u1","appId":"a","appDisplayName":"Teams","ipAddress":"1.2.3.4","clientAppUsed":"Browser","correlationId":"c1","conditionalAccessStatus":"failure","isInteractive":true,"riskDetail":"hidden","riskLevelAggregated":"hidden","riskLevelDuringSignIn":"hidden","riskState":"none","riskEventTypes_v2":[],"resourceDisplayName":"Microsoft Graph","status":{"errorCode":53000,"failureReason":"Device is not compliant.","additionalDetails":null},"deviceDetail":{"deviceId":"d1","displayName":"LT1","operatingSystem":"Windows 11","browser":"Edge","isCompliant":false,"isManaged":true,"trustType":"Azure AD joined"},"location":{"city":"Lawrence","state":"Kansas","countryOrRegion":"US","geoCoordinates":{"latitude":1.0,"longitude":2.0}},"appliedConditionalAccessPolicies":[{"id":"p1","displayName":"Compliant","enforcedGrantControls":["CompliantDevice"],"enforcedSessionControls":[],"result":"failure"},{"id":"p2","displayName":"Guests","enforcedGrantControls":[],"enforcedSessionControls":[],"result":"notApplied"}]}]}"#
        let event = try GraphClient.decoder.decode(Page<SignInEvent>.self, from: Data(json.utf8)).value[0]
        XCTAssertEqual(event.errorCode, 53000)
        XCTAssertTrue(event.isFailure)
        XCTAssertEqual(event.location?.label, "Lawrence, Kansas, US")
        XCTAssertEqual(event.decisivePolicies.map(\.id), ["p1"])
        XCTAssertEqual(event.blockingPolicies.first?.displayName, "Compliant")
        XCTAssertTrue(event.riskIsHidden)
        XCTAssertFalse(event.hasRisk)
        XCTAssertFalse(event.isLegacyClient)
        XCTAssertEqual(event.deviceDetail?.isCompliant, false)
    }

    func test_failuresSortFirstAmongDecisivePolicies() {
        let event = SignInEvent(id: "x", createdDateTime: nil, userDisplayName: nil, userPrincipalName: nil, appDisplayName: nil, clientAppUsed: "IMAP", ipAddress: nil, location: nil, status: .init(errorCode: 53003, failureReason: nil, additionalDetails: nil), conditionalAccessStatus: "failure", appliedConditionalAccessPolicies: [
            .init(id: "ok", displayName: "MFA", result: "success"),
            .init(id: "off", displayName: "Off", result: "notEnabled"),
            .init(id: "blocked", displayName: "Legacy", result: "failure"),
            .init(id: "ro", displayName: "Report", result: "reportOnlyFailure"),
        ], deviceDetail: nil, riskLevelAggregated: "medium", riskLevelDuringSignIn: "none", riskState: "atRisk")
        XCTAssertEqual(event.decisivePolicies.map(\.id), ["blocked", "ok"])
        XCTAssertTrue(event.isLegacyClient)
        XCTAssertTrue(event.hasRisk)
        XCTAssertFalse(event.riskIsHidden)
    }

    func test_vocabulary() {
        XCTAssertEqual(SignInVocabulary.conditionalAccessLabel("notApplied"), "No policy applied")
        XCTAssertEqual(SignInVocabulary.policyResultLabel("reportOnlyFailure"), "Report-only: would block")
        XCTAssertEqual(SignInVocabulary.riskLabel("hidden"), "Needs Entra ID P2")
        XCTAssertEqual(SignInVocabulary.riskStateLabel("confirmedCompromised"), "Confirmed compromised")
        XCTAssertEqual(SignInVocabulary.riskLabel("weird"), "weird")
    }

    // MARK: glossary

    func test_bundledGlossaryLoadsAndCoversTheCommonCodes() {
        let glossary = ErrorGlossary.bundled
        XCTAssertGreaterThanOrEqual(glossary.entries.count, 30)
        for code in [50074, 50076, 53000, 53003, 500121, 530032, 50126, 50053, 50057, 65001, 70044] {
            XCTAssertNotNil(glossary.entry(for: code), "missing \(code)")
        }
        XCTAssertNil(glossary.entry(for: 999_999_999))
        XCTAssertEqual(glossary.entries.map(\.code), glossary.entries.map(\.code).sorted())
    }

    func test_glossaryEntriesHaveNoEmDashesAndEndWithAFullStop() {
        for entry in ErrorGlossary.bundled.entries {
            for text in [entry.title, entry.meaning, entry.action] {
                XCTAssertFalse(text.contains("\u{2014}"), "em dash in \(entry.code)")
            }
            XCTAssertTrue(entry.meaning.hasSuffix("."), "meaning for \(entry.code) should end with a full stop")
            XCTAssertTrue(entry.action.hasSuffix("."), "action for \(entry.code) should end with a full stop")
        }
    }

    // MARK: query

    func test_filterEscapesQuotesAndAddsTheTimeWindow() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let plain = SignInQuery(userPrincipalName: "o'brien@contoso.com")
        XCTAssertEqual(plain.filter(now: now), "userPrincipalName eq 'o''brien@contoso.com'")
        let windowed = SignInQuery(userPrincipalName: "jane@contoso.com", last24Hours: true)
        let filter = windowed.filter(now: now)
        XCTAssertTrue(filter.hasPrefix("userPrincipalName eq 'jane@contoso.com' and createdDateTime ge 2027-01-"), filter)
        XCTAssertTrue(filter.hasSuffix("Z"), filter)
    }

    func test_failuresOnlyFetchesMoreAndFiltersAfterwards() {
        let query = SignInQuery(userPrincipalName: "x", failuresOnly: true, limit: 20)
        XCTAssertEqual(query.fetchCount, 100)
        XCTAssertEqual(SignInQuery(userPrincipalName: "x").fetchCount, 20)
        func event(_ id: String, _ code: Int) -> SignInEvent {
            SignInEvent(id: id, createdDateTime: nil, userDisplayName: nil, userPrincipalName: nil, appDisplayName: nil, clientAppUsed: nil, ipAddress: nil, location: nil, status: .init(errorCode: code, failureReason: nil, additionalDetails: nil), conditionalAccessStatus: nil, appliedConditionalAccessPolicies: nil, deviceDetail: nil)
        }
        let events = [event("a", 0), event("b", 50126), event("c", 0), event("d", 53003)]
        XCTAssertEqual(query.apply(events).map(\.id), ["b", "d"])
        XCTAssertEqual(SignInQuery(userPrincipalName: "x", limit: 3).apply(events).map(\.id), ["a", "b", "c"])
    }
}
