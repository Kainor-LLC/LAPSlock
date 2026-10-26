import Foundation

// Graph's enum spellings turned into the names an administrator uses. Anything not in
// the table is split on its capitals so a value Microsoft adds tomorrow still reads.

public enum SecurityVocabulary {

    static let sources: [String: String] = [
        "microsoftDefenderForEndpoint": "Defender for Endpoint",
        "microsoftDefenderForIdentity": "Defender for Identity",
        "microsoftDefenderForCloudApps": "Defender for Cloud Apps",
        "microsoftDefenderForOffice365": "Defender for Office 365",
        "microsoftDefenderForCloud": "Defender for Cloud",
        "microsoft365Defender": "Microsoft Defender XDR",
        "azureAdIdentityProtection": "Entra ID Protection",
        "microsoftAppGovernance": "App governance",
        "appGovernancePolicy": "App governance policy",
        "appGovernanceDetection": "App governance detection",
        "dataLossPrevention": "Data loss prevention",
        "microsoftDataLossPrevention": "Data loss prevention",
        "microsoftSentinel": "Microsoft Sentinel",
        "microsoftThreatIntelligence": "Threat intelligence",
        "microsoftSecurityForAI": "Security for AI",
        "microsoftInsiderRiskManagement": "Insider risk management",
        "antivirus": "Defender Antivirus",
        "smartScreen": "SmartScreen",
        "customTi": "Custom threat intelligence",
        "customDetection": "Custom detection",
        "automatedInvestigation": "Automated investigation",
        "microsoftThreatExperts": "Defender Experts",
        "cloudAppSecurity": "Defender for Cloud Apps",
        "manual": "Manual",
        "unknown": "Unknown"
    ]

    /// "microsoftDefenderForOffice365" reads as "Defender for Office 365".
    public static func sourceLabel(_ raw: String?) -> String? {
        guard let raw, !raw.isEmpty else { return nil }
        if let known = sources[raw] { return known }
        return words(raw)
    }

    /// "InitialAccess" reads as "Initial access"; "CredentialAccess" as "Credential access".
    public static func categoryLabel(_ raw: String) -> String {
        words(raw)
    }

    /// Classification and determination: "truePositive" reads as "True positive".
    public static func verdictLabel(_ raw: String?) -> String? {
        guard let raw, !raw.isEmpty, raw != "unknown" else { return nil }
        return words(raw)
    }

    static func words(_ raw: String) -> String {
        var out = ""
        var previousWasLower = false
        for ch in raw {
            if ch.isUppercase, previousWasLower {
                out.append(" ")
                out.append(ch.lowercased())
            } else if ch.isNumber, previousWasLower {
                out.append(" ")
                out.append(ch)
            } else {
                out.append(ch)
            }
            previousWasLower = ch.isLowercase || ch.isNumber
        }
        guard let first = out.first else { return raw }
        return first.uppercased() + out.dropFirst()
    }
}
