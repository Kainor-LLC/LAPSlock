import XCTest
@testable import DiagnosticsKit

// These tests exist to enforce the module's whole reason for being: a diagnostic report
// must be safe to paste into a support email without a second thought.
//
// The strongest test here is `test_reportContainsNoFreeText`, which asserts the report
// never contains strings that were never given to it. That sounds trivial, but it's the
// property that breaks the moment someone adds a free-text field — which is exactly when
// you want a red test.

final class DiagnosticEventTests: XCTestCase {

    func test_recordsTypedFields() {
        let e = DiagnosticEvent(
            operation: .credentialReveal,
            outcome: .notAuthorized,
            httpStatus: 403,
            graphRequestId: "d4576653-30f5-44ae-8790-06fff930667f",
            endpointTemplate: DiagnosticEndpoint.deviceLocalCredentials,
            devicePlatform: "windows",
            durationMs: 412
        )
        XCTAssertEqual(e.operation, .credentialReveal)
        XCTAssertEqual(e.outcome, .notAuthorized)
        XCTAssertEqual(e.httpStatus, 403)
        XCTAssertEqual(e.durationMs, 412)
    }

    // MARK: - request id sanitization

    func test_acceptsGuidShapedRequestId() {
        XCTAssertEqual(
            DiagnosticEvent.sanitizedRequestId("d4576653-30f5-44ae-8790-06fff930667f"),
            "d4576653-30f5-44ae-8790-06fff930667f"
        )
    }

    func test_rejectsNonGuidRequestId() {
        // If anything other than a request id ever reaches this field, it is dropped
        // rather than trusted. A password pasted here would not survive.
        XCTAssertNil(DiagnosticEvent.sanitizedRequestId("P@ssw0rd-Not-A-Guid"))
        XCTAssertNil(DiagnosticEvent.sanitizedRequestId("DESKTOP-FRONT01"))
        XCTAssertNil(DiagnosticEvent.sanitizedRequestId("admin@contoso.com"))
        XCTAssertNil(DiagnosticEvent.sanitizedRequestId(""))
        XCTAssertNil(DiagnosticEvent.sanitizedRequestId(nil))
    }

    func test_trimsWhitespaceOnRequestId() {
        XCTAssertEqual(
            DiagnosticEvent.sanitizedRequestId("  d4576653-30f5-44ae-8790-06fff930667f  "),
            "d4576653-30f5-44ae-8790-06fff930667f"
        )
    }

    func test_endpointTemplatesContainPlaceholdersNotIds() {
        // Templates must be literal placeholders. If a real id were ever interpolated
        // into one of these constants, this test would fail.
        XCTAssertTrue(DiagnosticEndpoint.deviceLocalCredentials.contains("{entraDeviceId}"))
        XCTAssertTrue(DiagnosticEndpoint.macLocalAdminDetail.contains("{id}"))
        XCTAssertFalse(DiagnosticEndpoint.managedDevicesList.contains("-"),
                       "A GUID would introduce hyphens into the template.")
    }
}

final class DiagnosticsReportTests: XCTestCase {

    private let environment = DiagnosticEnvironment(
        appVersion: "1.0.0",
        buildNumber: "42",
        osVersion: "iOS 18.2",
        deviceModel: "iPhone16,1",
        tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73"
    )

    private func recorderWithEvents() async -> DiagnosticsRecorder {
        let r = DiagnosticsRecorder(capacity: 50)
        await r.record(.signIn, .success, durationMs: 900)
        await r.record(.deviceListFirstPage, .success,
                       httpStatus: 200,
                       endpointTemplate: DiagnosticEndpoint.managedDevicesList,
                       durationMs: 640)
        await r.record(.credentialReveal, .notAuthorized,
                       httpStatus: 403,
                       graphRequestId: "d4576653-30f5-44ae-8790-06fff930667f",
                       endpointTemplate: DiagnosticEndpoint.deviceLocalCredentials,
                       devicePlatform: "windows",
                       durationMs: 380)
        return r
    }

    func test_reportIncludesUsefulTriageFacts() async {
        let r = await recorderWithEvents()
        let report = await r.buildReport(environment: environment, includeTenantId: true)

        XCTAssertTrue(report.contains("1.0.0"))
        XCTAssertTrue(report.contains("iPhone16,1"))
        XCTAssertTrue(report.contains("credentialReveal"))
        XCTAssertTrue(report.contains("notAuthorized"))
        XCTAssertTrue(report.contains("http=403"))
        XCTAssertTrue(report.contains("d4576653-30f5-44ae-8790-06fff930667f"),
                      "The Graph request id is the most useful field for a support case.")
    }

    func test_tenantIdIsOptOut() async {
        let r = await recorderWithEvents()
        let withTenant = await r.buildReport(environment: environment, includeTenantId: true)
        let without = await r.buildReport(environment: environment, includeTenantId: false)

        XCTAssertTrue(withTenant.contains("4470dc21"))
        XCTAssertFalse(without.contains("4470dc21"),
                       "Tenant id identifies the customer org; sharing it must be a choice.")
        XCTAssertTrue(without.contains("not included"))
    }

    /// THE important test. The report must contain only what was given to it as typed
    /// data — never a device name, a UPN, a serial, or a password, because there is no
    /// field on DiagnosticEvent capable of carrying one.
    func test_reportContainsNoFreeText() async {
        let r = DiagnosticsRecorder(capacity: 50)
        await r.record(.credentialReveal, .decodeFailure,
                       httpStatus: 200,
                       endpointTemplate: DiagnosticEndpoint.deviceLocalCredentials,
                       devicePlatform: "windows")
        let report = await r.buildReport(environment: environment, includeTenantId: false)

        let mustNotAppear = [
            "P@ssw0rd", "DEMO-Not-A-Real-Password",
            "DESKTOP-FRONT01", "MBA-", "@demo.example", "@contoso.com",
            "Administrator", "LapsAdmin",
            "passwordBase64", "Bearer", "eyJ"
        ]
        for needle in mustNotAppear {
            XCTAssertFalse(report.contains(needle),
                           "Diagnostic report must never contain \"\(needle)\".")
        }
    }

    func test_reportStatesItsOwnSafety() async {
        // The user reading this before they send it should be able to see the claim.
        let r = await recorderWithEvents()
        let report = await r.buildReport(environment: environment, includeTenantId: false)
        XCTAssertTrue(report.lowercased().contains("no passwords"))
    }

    func test_ringBufferCapsGrowth() async {
        let r = DiagnosticsRecorder(capacity: 10)
        for _ in 0..<40 {
            await r.record(.tokenSilent, .success)
        }
        let events = await r.recentEvents()
        XCTAssertEqual(events.count, 10, "Ring buffer must not grow without bound.")
    }

    func test_clearEmptiesBuffer() async {
        let r = await recorderWithEvents()
        await r.clear()
        let events = await r.recentEvents()
        XCTAssertTrue(events.isEmpty)
    }

    func test_emptyReportIsStillValid() async {
        let r = DiagnosticsRecorder()
        let report = await r.buildReport(environment: environment, includeTenantId: false)
        XCTAssertTrue(report.contains("none recorded this session"))
    }
}
