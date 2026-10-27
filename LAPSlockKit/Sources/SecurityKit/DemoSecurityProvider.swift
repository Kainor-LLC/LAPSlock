import Foundation

// Demo Security. Powers previews, development without a Defender tenant, and App Store
// review. The incidents are chosen to exercise every row and section the screens have:
// every severity, open and closed, assigned and not, an awaiting-action status that only
// the Prefer header reveals, every modelled evidence type plus one the module does not
// model, recommended actions with several lines, MITRE techniques, and an alert with no
// evidence at all. The people and devices named are the ones the Sign-in Triage and
// device-list demo sets also have, so the cross-links land on a row rather than on
// "nobody matches".

public actor DemoSecurityProvider: SecurityProviding {

    private let latency: Duration
    private let now: Date
    /// The second sample customer in demo mode: a calm tenant with nothing open, so switching
    /// customers shows different data and anything left over from the first stands out.
    private let quiet: Bool
    /// The large demo tenant's 200 incidents in place of the five hand-built ones.
    private let large: [SecurityIncident]?

    public init(latency: Duration = .milliseconds(400), now: Date = Date(), quiet: Bool = false, large: Bool = false) {
        self.latency = latency
        self.now = now
        self.quiet = quiet
        self.large = large ? Self.largeIncidents(now: now) : nil
    }

    private var all: [SecurityIncident] { large ?? Self.incidents(now: now) }

    public func incidents() async throws -> [SecurityIncident] {
        try await Task.sleep(for: latency)
        if quiet { return [] }
        return all.sorted(by: SecurityService.newestFirst)
    }

    public func incident(id: String) async throws -> SecurityIncident {
        try await Task.sleep(for: latency)
        guard !quiet, let found = all.first(where: { $0.id == id }) else {
            throw SecurityError.transport(status: 404)
        }
        return found
    }

    public func reset() {}

    // MARK: - fixtures

    public static let phishingId = "40211"
    public static let endpointId = "40198"
    public static let oauthId = "40150"
    public static let resolvedId = "39987"
    public static let awaitingId = "40230"

    public static let phishedUser = "jane.okafor@demo.example"
    public static let endpointDevice = "LT-FIELD-207.demo.example"

    public static func incidents(now: Date) -> [SecurityIncident] {
        [
            SecurityIncident(
                id: phishingId,
                displayName: "Credential phishing campaign reached 3 mailboxes",
                severity: .high,
                status: .active,
                assignedTo: nil,
                classification: "unknown",
                determination: "unknown",
                createdDateTime: now.addingTimeInterval(-3 * 3600),
                lastUpdateDateTime: now.addingTimeInterval(-40 * 60),
                priorityScore: 82,
                incidentWebUrl: "https://security.microsoft.com/incidents/40211",
                summary: "A message impersonating the payroll provider carried a link to a credential harvesting page. One recipient clicked within four minutes of delivery.",
                alerts: [
                    SecurityAlert(
                        id: "da637-phish-1",
                        title: "A potentially malicious URL click was detected",
                        description: "A user clicked a URL that Safe Links later classified as a credential phishing page.",
                        severity: .high,
                        status: .new,
                        serviceSource: "microsoftDefenderForOffice365",
                        detectionSource: "microsoftDefenderForOffice365",
                        categories: ["InitialAccess", "CredentialAccess"],
                        recommendedActions: "Reset the user's password and revoke sessions.\nCheck the sign-in log for the user since the click.\nSearch for other recipients of the same sender.\nSubmit the URL to Microsoft if the verdict looks wrong.",
                        mitreTechniques: ["T1566.002", "T1078"],
                        createdDateTime: now.addingTimeInterval(-3 * 3600),
                        firstActivityDateTime: now.addingTimeInterval(-3 * 3600 - 4 * 60),
                        lastActivityDateTime: now.addingTimeInterval(-3 * 3600),
                        alertWebUrl: "https://security.microsoft.com/alerts/da637-phish-1",
                        evidence: [
                            AlertEvidence(id: "e1", kind: .user(.init(accountName: "jane.okafor", domainName: "demo", userPrincipalName: phishedUser, displayName: "Jane Okafor")), roles: ["compromised"], verdict: .suspicious, remediationStatus: "none"),
                            AlertEvidence(id: "e2", kind: .mailbox(.init(displayName: "Jane Okafor", primaryAddress: phishedUser)), roles: ["destination"], verdict: .suspicious),
                            AlertEvidence(id: "e3", kind: .url("https://payroll-update-secure.example.net/login"), roles: ["attacker"], verdict: .malicious, remediationStatus: "blocked"),
                            AlertEvidence(id: "e4", kind: .ip(address: "203.0.113.57", country: "NL"), roles: ["attacker"], verdict: .suspicious)
                        ]),
                    SecurityAlert(
                        id: "da637-phish-2",
                        title: "Email messages containing malicious URL removed after delivery",
                        severity: .medium,
                        status: .inProgress,
                        serviceSource: "microsoftDefenderForOffice365",
                        detectionSource: "automatedInvestigation",
                        categories: ["InitialAccess"],
                        recommendedActions: "No action needed for the removed messages. Review the users who received them for follow-on activity.",
                        createdDateTime: now.addingTimeInterval(-2 * 3600),
                        firstActivityDateTime: now.addingTimeInterval(-3 * 3600 - 8 * 60),
                        lastActivityDateTime: now.addingTimeInterval(-2 * 3600),
                        evidence: [
                            AlertEvidence(id: "e5", kind: .mailbox(.init(displayName: "Priya Natarajan", primaryAddress: "p.natarajan@demo.example")), roles: ["destination"], verdict: .noThreatsFound, remediationStatus: "remediated"),
                            AlertEvidence(id: "e6", kind: .mailbox(.init(displayName: "Sam Okafor", primaryAddress: "s.okafor@demo.example")), roles: ["destination"], verdict: .noThreatsFound, remediationStatus: "remediated"),
                            AlertEvidence(id: "e7", kind: .other(typeName: "analyzedMessageEvidence"), roles: ["source"], verdict: .malicious, remediationStatus: "remediated")
                        ])
                ]),
            SecurityIncident(
                id: endpointId,
                displayName: "Suspicious PowerShell on LT-FIELD-207",
                severity: .medium,
                status: .inProgress,
                assignedTo: "sec-admin@demo.example",
                classification: "truePositive",
                determination: "malware",
                createdDateTime: now.addingTimeInterval(-26 * 3600),
                lastUpdateDateTime: now.addingTimeInterval(-5 * 3600),
                priorityScore: 61,
                incidentWebUrl: "https://security.microsoft.com/incidents/40198",
                summary: "An encoded PowerShell command launched from a document downloaded in the browser. The process was terminated by Defender and the file quarantined.",
                alerts: [
                    SecurityAlert(
                        id: "da637-ep-1",
                        title: "Suspicious PowerShell command line",
                        description: "A PowerShell process ran with an encoded command, a pattern used by droppers to hide their intent.",
                        severity: .medium,
                        status: .inProgress,
                        serviceSource: "microsoftDefenderForEndpoint",
                        detectionSource: "microsoftDefenderForEndpoint",
                        categories: ["Execution"],
                        recommendedActions: "Isolate the device if the user cannot account for the download.\nCollect the investigation package from the portal.\nCheck whether the same file hash appears on other devices.",
                        mitreTechniques: ["T1059.001", "T1204.002"],
                        createdDateTime: now.addingTimeInterval(-26 * 3600),
                        firstActivityDateTime: now.addingTimeInterval(-26 * 3600 - 90),
                        lastActivityDateTime: now.addingTimeInterval(-26 * 3600),
                        alertWebUrl: "https://security.microsoft.com/alerts/da637-ep-1",
                        evidence: [
                            AlertEvidence(id: "e8", kind: .device(.init(deviceDnsName: endpointDevice, mdeDeviceId: "4c1e3b7f0a2d", azureAdDeviceId: "9f3a7c2e-4b1d-4e8a-9c6f-2d5b8a1e7f30", osPlatform: "Windows 11", osBuild: 26100, healthStatus: "active", riskScore: "medium", onboardingStatus: "onboarded")), roles: ["contextual"], verdict: .suspicious),
                            AlertEvidence(id: "e9", kind: .process(.init(processId: 7712, processCommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAo...", imageFile: .init(fileName: "powershell.exe", filePath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"), userAccount: .init(accountName: "mei.tanaka", domainName: "DEMO", userPrincipalName: "mei.tanaka@demo.example", displayName: "Mei Tanaka"), detectionStatus: "detected")), roles: ["suspicious"], verdict: .malicious, remediationStatus: "remediated"),
                            AlertEvidence(id: "e10", kind: .file(.init(fileName: "Invoice_Q3_final.docm", filePath: "C:\\Users\\mei.tanaka\\Downloads", sha256: "3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e", filePublisher: nil, fileSize: 48_212)), roles: ["source"], verdict: .malicious, remediationStatus: "remediated"),
                            AlertEvidence(id: "e11", kind: .user(.init(accountName: "mei.tanaka", domainName: "DEMO", userPrincipalName: "mei.tanaka@demo.example", displayName: "Mei Tanaka")), roles: ["contextual"], verdict: .unknown)
                        ])
                ]),
            SecurityIncident(
                id: oauthId,
                displayName: "Risky OAuth app granted mail access",
                severity: .low,
                status: .active,
                assignedTo: nil,
                createdDateTime: now.addingTimeInterval(-3 * 86_400),
                lastUpdateDateTime: now.addingTimeInterval(-3 * 86_400),
                priorityScore: 35,
                incidentWebUrl: "https://security.microsoft.com/incidents/40150",
                summary: "A user consented to a third-party application requesting Mail.Read and offline access. The publisher is unverified.",
                alerts: [
                    SecurityAlert(
                        id: "da637-oauth-1",
                        title: "Unverified app consented to with mail permissions",
                        severity: .low,
                        status: .new,
                        serviceSource: "microsoftAppGovernance",
                        detectionSource: "appGovernancePolicy",
                        categories: ["Persistence"],
                        recommendedActions: "Review the app in Entra under Enterprise applications.\nRevoke the consent if the publisher is not expected.",
                        mitreTechniques: ["T1528"],
                        createdDateTime: now.addingTimeInterval(-3 * 86_400),
                        evidence: [
                            AlertEvidence(id: "e12", kind: .oauthApplication(name: "MailSync Helper", appId: "7c2d6e4f-1a3b-4c5d-9e8f-0a1b2c3d4e5f", publisher: nil), roles: ["suspicious"], verdict: .suspicious),
                            AlertEvidence(id: "e13", kind: .cloudApplication(name: "Microsoft Exchange Online", appId: "20893"), roles: ["contextual"], verdict: .unknown),
                            AlertEvidence(id: "e14", kind: .user(.init(accountName: "raj.patel", domainName: "demo", userPrincipalName: "raj.patel@demo.example", displayName: "Raj Patel")), roles: ["source"], verdict: .unknown)
                        ])
                ]),
            SecurityIncident(
                id: awaitingId,
                displayName: "Defender Experts: unusual sign-in pattern under review",
                severity: .informational,
                status: .awaitingAction,
                assignedTo: "Defender Experts",
                createdDateTime: now.addingTimeInterval(-9 * 3600),
                lastUpdateDateTime: now.addingTimeInterval(-9 * 3600),
                priorityScore: 20,
                incidentWebUrl: "https://security.microsoft.com/incidents/40230",
                alerts: [
                    SecurityAlert(
                        id: "da637-ir-1",
                        title: "Atypical travel",
                        severity: .informational,
                        status: .new,
                        serviceSource: "azureAdIdentityProtection",
                        detectionSource: "azureAdIdentityProtection",
                        categories: ["InitialAccess"],
                        createdDateTime: now.addingTimeInterval(-9 * 3600),
                        evidence: [])
                ]),
            SecurityIncident(
                id: resolvedId,
                displayName: "Malware detected and blocked on 2 devices",
                severity: .medium,
                status: .resolved,
                assignedTo: "sec-admin@demo.example",
                classification: "truePositive",
                determination: "malware",
                createdDateTime: now.addingTimeInterval(-6 * 86_400),
                lastUpdateDateTime: now.addingTimeInterval(-5 * 86_400),
                priorityScore: 15,
                incidentWebUrl: "https://security.microsoft.com/incidents/39987",
                summary: "Defender Antivirus blocked a known trojan on two devices at download time. No execution occurred.",
                alerts: [
                    SecurityAlert(
                        id: "da637-av-1",
                        title: "Trojan:Win32/Emotet was blocked",
                        severity: .medium,
                        status: .resolved,
                        serviceSource: "microsoftDefenderForEndpoint",
                        detectionSource: "antivirus",
                        categories: ["Malware"],
                        createdDateTime: now.addingTimeInterval(-6 * 86_400),
                        evidence: [
                            AlertEvidence(id: "e15", kind: .device(.init(deviceDnsName: "LT-SALES-114.demo.example", osPlatform: "Windows 11", healthStatus: "active", riskScore: "none")), roles: ["contextual"], verdict: .noThreatsFound, remediationStatus: "prevented"),
                            AlertEvidence(id: "e16", kind: .device(.init(deviceDnsName: "WS-LAB-009.demo.example", osPlatform: "Windows 11", healthStatus: "active", riskScore: "none")), roles: ["contextual"], verdict: .noThreatsFound, remediationStatus: "prevented"),
                            AlertEvidence(id: "e17", kind: .file(.init(fileName: "setup_update.exe", sha256: "9d1f2c3b4a5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8")), roles: ["source"], verdict: .malicious, remediationStatus: "prevented")
                        ])
                ])
        ]
    }
}
