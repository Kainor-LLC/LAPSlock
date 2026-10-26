import XCTest
import AuthKit
@testable import SecurityKit

final class SecurityModelsTests: XCTestCase {

    private func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        try GraphClient.decoder.decode(T.self, from: Data(json.utf8))
    }

    // MARK: evidence

    func test_userEvidenceDecodesTheAccount() throws {
        let json = ##"{"@odata.type":"#microsoft.graph.security.userEvidence","roles":["compromised"],"verdict":"suspicious","remediationStatus":"none","userAccount":{"accountName":"j.alvarez","domainName":"demo","userPrincipalName":"j.alvarez@demo.example","displayName":"Jordan Alvarez","azureAdUserId":"1111"}}"##
        let evidence = try decode(AlertEvidence.self, json)
        guard case .user(let account) = evidence.kind else { return XCTFail("expected user") }
        XCTAssertEqual(account.userPrincipalName, "j.alvarez@demo.example")
        XCTAssertEqual(evidence.roles, ["compromised"])
        XCTAssertEqual(evidence.verdict, .suspicious)
        XCTAssertEqual(evidence.label, "j.alvarez@demo.example")
        XCTAssertEqual(evidence.detail, "Jordan Alvarez")
        XCTAssertEqual(evidence.userPrincipalName, "j.alvarez@demo.example")
        XCTAssertNil(evidence.deviceHostName)
    }

    func test_deviceEvidenceDecodesAndYieldsAHostName() throws {
        let json = ##"{"@odata.type":"#microsoft.graph.security.deviceEvidence","roles":["contextual"],"verdict":"unknown","deviceDnsName":"LT-FINANCE-07.demo.example","mdeDeviceId":"abc","azureAdDeviceId":"9f3a","osPlatform":"Windows11","osBuild":26100,"healthStatus":"active","riskScore":"medium","onboardingStatus":"onboarded"}"##
        let evidence = try decode(AlertEvidence.self, json)
        XCTAssertEqual(evidence.deviceHostName, "LT-FINANCE-07")
        XCTAssertEqual(evidence.label, "LT-FINANCE-07.demo.example")
        XCTAssertEqual(evidence.detail, "Windows11, risk medium, active")
        XCTAssertEqual(evidence.kindTitle, "Devices")
    }

    func test_mailboxIpUrlFileProcessAndAppsDecode() throws {
        let items = [
            ##"{"@odata.type":"#microsoft.graph.security.mailboxEvidence","displayName":"Priya","primaryAddress":"p@demo.example","userAccount":{"userPrincipalName":"p@demo.example"}}"##,
            ##"{"@odata.type":"#microsoft.graph.security.ipEvidence","ipAddress":"203.0.113.57","countryLetterCode":"NL"}"##,
            ##"{"@odata.type":"#microsoft.graph.security.urlEvidence","url":"https://bad.example/login"}"##,
            ##"{"@odata.type":"#microsoft.graph.security.fileEvidence","fileDetails":{"fileName":"a.docm","filePath":"C:\\Users\\x","sha256":"ff","fileSize":10}}"##,
            ##"{"@odata.type":"#microsoft.graph.security.processEvidence","processId":7712,"processCommandLine":"powershell -enc AAA","imageFile":{"fileName":"powershell.exe"},"userAccount":{"userPrincipalName":"m@demo.example"}}"##,
            ##"{"@odata.type":"#microsoft.graph.security.cloudApplicationEvidence","displayName":"Exchange Online","appId":20893}"##,
            ##"{"@odata.type":"#microsoft.graph.security.oauthApplicationEvidence","displayName":"MailSync","appId":"7c2d","publisher":"Contoso"}"##
        ]
        let decoded = try decode([AlertEvidence].self, "[" + items.joined(separator: ",") + "]")
        XCTAssertEqual(decoded.map(\.kindTitle), ["Mailboxes", "IP Addresses", "URLs", "Files", "Processes", "Cloud Apps", "OAuth Apps"])
        XCTAssertEqual(decoded[0].label, "p@demo.example")
        XCTAssertEqual(decoded[0].userPrincipalName, "p@demo.example")
        XCTAssertEqual(decoded[1].detail, "NL")
        XCTAssertEqual(decoded[2].label, "https://bad.example/login")
        XCTAssertEqual(decoded[3].label, "a.docm")
        XCTAssertEqual(decoded[3].detail, "C:\\Users\\x")
        XCTAssertEqual(decoded[4].label, "powershell.exe")
        XCTAssertEqual(decoded[4].userPrincipalName, "m@demo.example")
        XCTAssertEqual(decoded[5].detail, "20893")
        XCTAssertEqual(decoded[6].detail, "Contoso, 7c2d")
    }

    func test_anUnmodelledEvidenceTypeBecomesAnOtherRowNotAFailure() throws {
        let json = ##"{"@odata.type":"#microsoft.graph.security.kubernetesPodEvidence","roles":["attacked"],"verdict":"malicious","name":"web-1"}"##
        let evidence = try decode(AlertEvidence.self, json)
        guard case .other(let typeName) = evidence.kind else { return XCTFail("expected other") }
        XCTAssertEqual(typeName, "kubernetesPodEvidence")
        XCTAssertEqual(evidence.label, "Kubernetes pod")
        XCTAssertEqual(evidence.kindTitle, "Other")
        XCTAssertEqual(evidence.verdict, .malicious)
    }

    func test_evidenceWithoutATypeStillDecodes() throws {
        let evidence = try decode(AlertEvidence.self, ##"{"roles":[],"verdict":"madeUpTomorrow"}"##)
        guard case .other(let typeName) = evidence.kind else { return XCTFail("expected other") }
        XCTAssertEqual(typeName, "evidence")
        XCTAssertEqual(evidence.verdict, .other("madeUpTomorrow"))
        XCTAssertEqual(evidence.verdict.label, "Unknown")
    }

    func test_evidenceRoundTripsThroughItsEncoder() throws {
        let original = AlertEvidence(id: "x", kind: .ip(address: "198.51.100.4", country: "US"), roles: ["attacker"], verdict: .malicious)
        let data = try JSONEncoder().encode(original)
        let back = try decode(AlertEvidence.self, String(decoding: data, as: UTF8.self))
        XCTAssertEqual(back.kind, original.kind)
        XCTAssertEqual(back.roles, original.roles)
        XCTAssertEqual(back.verdict, original.verdict)
    }

    // MARK: enums

    func test_unknownSeverityAndStatusesFallBackInsteadOfFailing() throws {
        let json = ##"{"id":"1","displayName":"x","severity":"critical","status":"awaitingAction","alerts":[{"id":"a","severity":"nope","status":"escalated"}]}"##
        let incident = try decode(SecurityIncident.self, json)
        XCTAssertEqual(incident.severity, .unknown)
        XCTAssertEqual(incident.status, .awaitingAction)
        XCTAssertTrue(incident.isOpen)
        XCTAssertEqual(incident.alerts.first?.severity, .unknown)
        XCTAssertEqual(incident.alerts.first?.status, .unknown("escalated"))
        XCTAssertEqual(incident.alerts.first?.status.label, "Unknown")
    }

    func test_anIncidentWithNoAlertsOrNameDecodes() throws {
        let incident = try decode(SecurityIncident.self, ##"{"id":"77","severity":"low","status":"redirected"}"##)
        XCTAssertEqual(incident.title, "Incident 77")
        XCTAssertFalse(incident.isOpen)
        XCTAssertTrue(incident.alerts.isEmpty)
        XCTAssertEqual(incident.evidenceSummary, "")
    }

    func test_statusesEncodeBackToGraphsSpelling() throws {
        let data = try JSONEncoder().encode([SecurityIncident.Status.inProgress, .unknown("later")])
        XCTAssertEqual(String(decoding: data, as: UTF8.self), ##"["inProgress","later"]"##)
    }

    // MARK: presentation

    func test_evidenceSummaryCountsInDisplayOrderWithPlurals() {
        let incident = SecurityIncident(id: "1", displayName: "x", severity: .high, status: .active, alerts: [
            SecurityAlert(id: "a", title: "a", severity: .high, status: .new, evidence: [
                AlertEvidence(id: "1", kind: .url("u")),
                AlertEvidence(id: "2", kind: .user(.init(userPrincipalName: "a@x"))),
                AlertEvidence(id: "3", kind: .ip(address: "1.1.1.1", country: nil)),
                AlertEvidence(id: "4", kind: .ip(address: "2.2.2.2", country: nil))
            ]),
            SecurityAlert(id: "b", title: "b", severity: .low, status: .new, evidence: [
                AlertEvidence(id: "5", kind: .user(.init(userPrincipalName: "b@x")))
            ])
        ])
        XCTAssertEqual(incident.evidenceSummary, "2 users, 2 IP addresses, 1 URL")
        let mailboxes = SecurityIncident(id: "2", displayName: "y", severity: .low, status: .active, alerts: [
            SecurityAlert(id: "c", title: "c", severity: .low, status: .new, evidence: [
                AlertEvidence(id: "6", kind: .mailbox(.init(primaryAddress: "a@x"))),
                AlertEvidence(id: "7", kind: .mailbox(.init(primaryAddress: "b@x"))),
                AlertEvidence(id: "8", kind: .process(.init(processId: 1))),
                AlertEvidence(id: "9", kind: .process(.init(processId: 2)))
            ])
        ])
        XCTAssertEqual(mailboxes.evidenceSummary, "2 mailboxes, 2 processes")
    }

    func test_recommendedActionsSplitIntoLines() {
        let alert = SecurityAlert(id: "a", title: "a", severity: .low, status: .new,
                                  recommendedActions: "Reset the password.\n\n  Revoke sessions.  \nCheck the log.")
        XCTAssertEqual(alert.recommendedActionLines, ["Reset the password.", "Revoke sessions.", "Check the log."])
        XCTAssertEqual(SecurityAlert(id: "b", title: nil, severity: .low, status: .new).recommendedActionLines, [])
        XCTAssertEqual(SecurityAlert(id: "b", title: nil, severity: .low, status: .new).displayTitle, "Alert b")
    }

    func test_categoriesFallBackToTheDeprecatedSingleCategory() {
        XCTAssertEqual(SecurityAlert(id: "a", title: nil, severity: .low, status: .new, category: "Malware").allCategories, ["Malware"])
        XCTAssertEqual(SecurityAlert(id: "a", title: nil, severity: .low, status: .new, category: "Malware", categories: ["Execution"]).allCategories, ["Execution"])
    }

    func test_humanizeTurnsTypeNamesIntoWords() {
        XCTAssertEqual(AlertEvidence.humanize("kubernetesPodEvidence"), "Kubernetes pod")
        XCTAssertEqual(AlertEvidence.humanize("analyzedMessageEvidence"), "Analyzed message")
        XCTAssertEqual(AlertEvidence.humanize("blobEvidence"), "Blob")
    }

    // MARK: filter

    func test_filterDefaultsToOpenOnlyAndRespectsTheSeverityFloor() {
        let incidents = [
            SecurityIncident(id: "1", displayName: "high open", severity: .high, status: .active),
            SecurityIncident(id: "2", displayName: "medium open", severity: .medium, status: .inProgress),
            SecurityIncident(id: "3", displayName: "low open", severity: .low, status: .awaitingAction),
            SecurityIncident(id: "4", displayName: "high closed", severity: .high, status: .resolved),
            SecurityIncident(id: "5", displayName: "unknown open", severity: .unknown, status: .unknown("new"))
        ]
        XCTAssertEqual(SecurityFilter.standard.apply(incidents).map(\.id), ["1", "2", "3", "5"])
        XCTAssertEqual(SecurityFilter(openOnly: true, severity: .mediumAndUp).apply(incidents).map(\.id), ["1", "2"])
        XCTAssertEqual(SecurityFilter(openOnly: false, severity: .highOnly).apply(incidents).map(\.id), ["1", "4"])
        XCTAssertEqual(SecurityFilter(openOnly: false, severity: .all).apply(incidents).count, 5)
    }

    func test_severityOrders() {
        XCTAssertTrue(SecuritySeverity.informational < .low)
        XCTAssertTrue(SecuritySeverity.medium < .high)
        XCTAssertTrue(SecuritySeverity.unknown < .informational)
    }

    func test_scopeIsTheIncidentScopeAlone() {
        XCTAssertEqual(SecurityScopes.module, ["SecurityIncident.Read.All"])
    }

    func test_graphErrorsMapOneToOne() {
        XCTAssertEqual(SecurityError(.consentRequired), .consentRequired)
        XCTAssertEqual(SecurityError(.notAuthorized), .notAuthorized)
        XCTAssertEqual(SecurityError(.notFound), .transport(status: 404))
        XCTAssertEqual(SecurityError(.throttled(retryAfter: 3)), .throttled(retryAfter: 3))
        XCTAssertEqual(SecurityError(.decodeFailure), .decodeFailure)
    }
}
