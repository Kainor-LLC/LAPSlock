import Foundation

// The large demo tenant's incidents, for measuring the Security list at the size of a large
// customer (optimization plan step C). Deterministic from the index, so a measurement can be
// repeated; nothing here resembles a real organization.

extension DemoSecurityProvider {

    /// 200 incidents across the 30-day window: a third open, the rest resolved or redirected;
    /// every severity; one to four alerts each, carrying 3 to 30 pieces of evidence.
    public static func largeIncidents(now: Date, count: Int = 200) -> [SecurityIncident] {
        let titles = ["Credential phishing campaign reached mailboxes", "Suspicious PowerShell on a device",
                      "Unfamiliar sign-in properties", "Malware detected and blocked", "Mass download by a user",
                      "Suspicious inbox forwarding rule", "Impossible travel activity", "Ransomware behaviour blocked"]
        let severities: [SecuritySeverity] = [.high, .medium, .low, .informational, .medium, .low]
        return (0..<max(0, count)).map { i in
            let status: SecurityIncident.Status = i % 3 == 0
                ? (i % 2 == 0 ? .active : .inProgress)
                : (i % 7 == 0 ? .redirected : .resolved)
            let created = now.addingTimeInterval(-Double((i * 3_571) % (29 * 24 * 60)) * 60)
            let alerts = (0..<(1 + i % 4)).map { a -> SecurityAlert in
                let evidence = (0..<(3 + (i * 7 + a * 5) % 28)).map { e -> AlertEvidence in
                    let id = "le-" + String(i) + "-" + String(a) + "-" + String(e)
                    let person = (i * 31 + e) % 5_000
                    let upn = "user" + String(format: "%04d", person) + "@demo.example"
                    switch e % 4 {
                    case 0:
                        return AlertEvidence(id: id, kind: .user(.init(accountName: "user" + String(person), domainName: "demo", userPrincipalName: upn, displayName: "Person " + String(person))), roles: ["impacted"], verdict: .suspicious)
                    case 1:
                        let device = "WS-ENG-" + String(format: "%05d", (i * 17 + e) % 20_000) + ".demo.example"
                        return AlertEvidence(id: id, kind: .device(.init(deviceDnsName: device, osPlatform: "Windows 11", healthStatus: "active", riskScore: "medium")), roles: ["contextual"], verdict: .suspicious)
                    case 2:
                        return AlertEvidence(id: id, kind: .mailbox(.init(displayName: "Person " + String(person), primaryAddress: upn)), roles: ["destination"], verdict: .noThreatsFound, remediationStatus: "remediated")
                    default:
                        return AlertEvidence(id: id, kind: .ip(address: "203.0.113." + String(e % 250), country: "NL"), roles: ["attacker"], verdict: .suspicious)
                    }
                }
                return SecurityAlert(
                    id: "la-" + String(i) + "-" + String(a),
                    title: titles[(i + a) % titles.count],
                    severity: severities[(i + a) % severities.count],
                    status: status.isOpen ? .new : .resolved,
                    serviceSource: "microsoftDefenderForEndpoint",
                    detectionSource: "automatedInvestigation",
                    categories: ["InitialAccess"],
                    recommendedActions: "Review the evidence and the people and devices it names.",
                    createdDateTime: created,
                    firstActivityDateTime: created,
                    lastActivityDateTime: created,
                    evidence: evidence)
            }
            return SecurityIncident(
                id: String(50_000 + i),
                displayName: titles[i % titles.count] + " (" + String(i) + ")",
                severity: severities[i % severities.count],
                status: status,
                assignedTo: nil,
                classification: "unknown",
                determination: "unknown",
                createdDateTime: created,
                lastUpdateDateTime: created.addingTimeInterval(1_800),
                priorityScore: 20 + i % 80,
                incidentWebUrl: "https://security.microsoft.com/incidents/" + String(50_000 + i),
                summary: "A generated incident for measuring the list at the size of a large tenant.",
                alerts: alerts)
        }
    }
}
