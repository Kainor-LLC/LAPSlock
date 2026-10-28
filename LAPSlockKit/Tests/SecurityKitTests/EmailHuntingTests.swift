import XCTest
import AuthKit
@testable import SecurityKit

final class EmailHuntingTests: XCTestCase {

    func testValuesThatCouldLeaveTheStringAreRefused() {
        let attempts = [
            "a@b.com\" | take 1 | union SecurityAlert //",
            "contoso.com\"",
            "x\\\"y",
            "invoice\n| where 1==1",
            "",
            "   "
        ]
        for value in attempts {
            for hunt in EmailHunt.allCases where hunt.parameter != nil {
                XCTAssertThrowsError(try hunt.query(value: value, window: .day), hunt.rawValue + ": " + value)
            }
        }
    }

    func testAddressesAndDomainsAllowNothingElse() {
        for hunt in [EmailHunt.fromSender, .toRecipient, .linkClicks] {
            for value in ["a@b.com; drop", "a b.com", "contoso.com/path", "*.contoso.com"] {
                XCTAssertThrowsError(try hunt.query(value: value, window: .day), hunt.rawValue + ": " + value)
            }
        }
    }

    func testSenderUsesTheAddressOrTheDomainColumn() throws {
        let address = try EmailHunt.fromSender.query(value: "Invoices@Contoso-Billing.com", window: .week)
        XCTAssertTrue(address.contains("| where SenderFromAddress =~ \"invoices@contoso-billing.com\""))
        XCTAssertTrue(address.contains("ago(7d)"))
        let domain = try EmailHunt.fromSender.query(value: "contoso-billing.com", window: .day)
        XCTAssertTrue(domain.contains("| where SenderFromDomain =~ \"contoso-billing.com\""))
    }

    func testRecipientMustBeAnAddress() {
        XCTAssertThrowsError(try EmailHunt.toRecipient.query(value: "contoso.com", window: .day))
        XCTAssertNoThrow(try EmailHunt.toRecipient.query(value: "jane.o'neil@contoso.com", window: .day))
    }

    func testSubjectAllowsOrdinaryWords() throws {
        let kql = try EmailHunt.bySubject.query(value: "Payment overdue: invoice #4471 (final)", window: .month)
        XCTAssertTrue(kql.contains("| where Subject contains \"Payment overdue: invoice #4471 (final)\""))
        XCTAssertThrowsError(try EmailHunt.bySubject.query(value: "ab", window: .day), "too short")
    }

    func testQueriesWithoutAValueIgnoreOne() throws {
        let kql = try EmailHunt.deliveredThreats.query(value: nil, window: .day)
        XCTAssertTrue(kql.hasPrefix("EmailEvents"))
        XCTAssertTrue(kql.contains("has_any (\"Phish\", \"Malware\")"))
        XCTAssertTrue(try EmailHunt.removedAfterDelivery.query(value: nil, window: .day).hasPrefix("let removed = EmailPostDeliveryEvents"))
    }

    func testRemovalsTakeTheNewest200BeforeTheJoin() throws {
        let kql = try EmailHunt.removedAfterDelivery.query(value: nil, window: .week)
        let lines = kql.components(separatedBy: "\n")
        let top = try XCTUnwrap(lines.firstIndex(of: "| top 200 by Timestamp desc;"))
        let join = try XCTUnwrap(lines.firstIndex { $0.hasPrefix("| join") })
        XCTAssertLessThan(top, join, "the 200 are chosen before any join")
        XCTAssertTrue(lines[join].contains("where NetworkMessageId in ((removed | project NetworkMessageId))"), lines[join])
        XCTAssertEqual(kql.components(separatedBy: "ago(7d)").count - 1, 2, "both tables are bounded by the window")
    }

    func testEveryQueryIsBoundedAndReadOnly() throws {
        for hunt in EmailHunt.allCases {
            let value = hunt.parameter?.example
            let kql = try hunt.query(value: value, window: .day)
            XCTAssertTrue(kql.contains("| take 200"), hunt.rawValue)
            XCTAssertTrue(kql.contains("ago(1d)"), hunt.rawValue)
            for word in [".set", ".drop", ".append", ".delete", "externaldata", "evaluate"] {
                XCTAssertFalse(kql.lowercased().contains(word), hunt.rawValue + " " + word)
            }
            XCTAssertTrue(hunt.tables.allSatisfy { kql.contains($0) }, hunt.rawValue)
        }
    }

    func testParsingTheGraphShape() throws {
        let json = #"{"schema":[{"name":"Timestamp","type":"DateTime"},{"name":"ThreatTypes","type":"String"},{"name":"IsClickedThrough","type":"Boolean"},{"name":"Count","type":"Int64"}],"results":[{"Timestamp":"2026-10-27T01:00:00Z","ThreatTypes":"[\"Phish\",\"Malware\"]","IsClickedThrough":true,"Count":3},{"Timestamp":"2026-10-27T02:00:00Z","ThreatTypes":"","IsClickedThrough":false,"Count":null}]}"#
        let result = try HuntResult.parse(Data(json.utf8))
        XCTAssertEqual(result.columns, ["Timestamp", "ThreatTypes", "IsClickedThrough", "Count"])
        XCTAssertEqual(result.rows.count, 2)
        XCTAssertEqual(result.rows[0]["ThreatTypes"], "Phish, Malware")
        XCTAssertEqual(result.rows[0]["IsClickedThrough"], "Yes")
        XCTAssertEqual(result.rows[0]["Count"], "3")
        XCTAssertNil(result.rows[1]["ThreatTypes"])
        XCTAssertNil(result.rows[1]["Count"])
        XCTAssertThrowsError(try HuntResult.parse(Data("nope".utf8)))
    }

    func testTicketTextNamesTheQueryAndSaysWhatIsAuthoritative() {
        let result = HuntResult(columns: ["Subject"], rows: [HuntRow(id: 0, values: ["Subject": "Hi"])])
        let text = result.text(for: .bySubject, value: "Hi there", window: .day, at: Date(timeIntervalSince1970: 0))
        XCTAssertTrue(text.hasPrefix("Messages by Subject: Hi there, last 24 hours"))
        XCTAssertTrue(text.contains("Subject=Hi"))
        XCTAssertTrue(text.hasSuffix("Advanced hunting in Microsoft Defender is authoritative."))
    }

    func testTheWindowIsATimespan() {
        XCTAssertEqual(HuntWindow.week.timespan, "P7D")
    }

    func testDemoRefusesWhatTheServiceWouldRefuse() async {
        let demo = DemoEmailHuntingProvider(latency: .zero)
        do {
            _ = try await demo.run(.fromSender, value: "x\"", window: .day, allowInteractive: false)
            XCTFail("demo must refuse the same values")
        } catch {}
        let ok = try? await demo.run(.linkClicks, value: "contoso-login.com", window: .day, allowInteractive: false)
        XCTAssertEqual(ok?.rows.count, 2)
    }

    func testTheQuietDemoCustomerFindsNothing() async throws {
        let quiet = DemoEmailHuntingProvider(latency: .zero, quiet: true)
        let result = try await quiet.run(.fromSender, value: "contoso-billing.com", window: .week, allowInteractive: false)
        XCTAssertTrue(result.rows.isEmpty)
        XCTAssertFalse(result.columns.isEmpty)
    }
}
