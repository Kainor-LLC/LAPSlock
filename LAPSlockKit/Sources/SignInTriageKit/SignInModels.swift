import Foundation

// A sign-in as the Entra sign-in log reports it, read-only. Spec section 3.4.
//
// The log returns interactive sign-ins on v1.0, so "interactive only" is not a filter
// here but the shape of the data. Non-interactive sign-ins are a beta query and are not
// in phase 1.
//
// Risk is included because the columns are on the same record; without Entra ID P2 the
// values come back as `hidden`, and the screen says so rather than showing a blank.

public struct SignInEvent: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let createdDateTime: Date?
    public let userDisplayName: String?
    public let userPrincipalName: String?
    public let userId: String?
    public let appDisplayName: String?
    public let resourceDisplayName: String?
    public let clientAppUsed: String?
    public let ipAddress: String?
    public let location: Location?
    public let status: Status?
    public let conditionalAccessStatus: String?
    public let appliedConditionalAccessPolicies: [AppliedPolicy]?
    public let deviceDetail: DeviceDetail?
    public let riskLevelAggregated: String?
    public let riskLevelDuringSignIn: String?
    public let riskState: String?
    public let riskDetail: String?
    public let isInteractive: Bool?
    public let correlationId: String?

    public struct Location: Codable, Sendable, Equatable {
        public let city: String?
        public let state: String?
        public let countryOrRegion: String?
        public init(city: String?, state: String?, countryOrRegion: String?) {
            self.city = city
            self.state = state
            self.countryOrRegion = countryOrRegion
        }
        public var label: String? {
            let parts = [city, state, countryOrRegion].compactMap { $0 }.filter { !$0.isEmpty }
            return parts.isEmpty ? nil : parts.joined(separator: ", ")
        }
    }

    public struct Status: Codable, Sendable, Equatable {
        public let errorCode: Int?
        public let failureReason: String?
        public let additionalDetails: String?
        public init(errorCode: Int?, failureReason: String?, additionalDetails: String?) {
            self.errorCode = errorCode
            self.failureReason = failureReason
            self.additionalDetails = additionalDetails
        }
    }

    public struct AppliedPolicy: Codable, Sendable, Equatable, Identifiable {
        public let id: String
        public let displayName: String?
        /// `success`, `failure`, `notApplied`, `notEnabled`, `unknown`, and the report-only forms.
        public let result: String?
        public let enforcedGrantControls: [String]?
        public let enforcedSessionControls: [String]?
        public init(id: String, displayName: String?, result: String?, enforcedGrantControls: [String]? = nil, enforcedSessionControls: [String]? = nil) {
            self.id = id
            self.displayName = displayName
            self.result = result
            self.enforcedGrantControls = enforcedGrantControls
            self.enforcedSessionControls = enforcedSessionControls
        }
        public var failed: Bool { result?.lowercased() == "failure" }
        public var applied: Bool {
            guard let result = result?.lowercased() else { return false }
            return result == "success" || result == "failure"
        }
    }

    public struct DeviceDetail: Codable, Sendable, Equatable {
        public let deviceId: String?
        public let displayName: String?
        public let operatingSystem: String?
        public let browser: String?
        public let isCompliant: Bool?
        public let isManaged: Bool?
        public let trustType: String?
        public init(deviceId: String?, displayName: String?, operatingSystem: String?, browser: String?, isCompliant: Bool?, isManaged: Bool?, trustType: String?) {
            self.deviceId = deviceId
            self.displayName = displayName
            self.operatingSystem = operatingSystem
            self.browser = browser
            self.isCompliant = isCompliant
            self.isManaged = isManaged
            self.trustType = trustType
        }
    }

    public init(
        id: String, createdDateTime: Date?, userDisplayName: String?, userPrincipalName: String?, userId: String? = nil,
        appDisplayName: String?, resourceDisplayName: String? = nil, clientAppUsed: String?, ipAddress: String?,
        location: Location?, status: Status?, conditionalAccessStatus: String?,
        appliedConditionalAccessPolicies: [AppliedPolicy]?, deviceDetail: DeviceDetail?,
        riskLevelAggregated: String? = nil, riskLevelDuringSignIn: String? = nil, riskState: String? = nil,
        riskDetail: String? = nil, isInteractive: Bool? = true, correlationId: String? = nil
    ) {
        self.id = id
        self.createdDateTime = createdDateTime
        self.userDisplayName = userDisplayName
        self.userPrincipalName = userPrincipalName
        self.userId = userId
        self.appDisplayName = appDisplayName
        self.resourceDisplayName = resourceDisplayName
        self.clientAppUsed = clientAppUsed
        self.ipAddress = ipAddress
        self.location = location
        self.status = status
        self.conditionalAccessStatus = conditionalAccessStatus
        self.appliedConditionalAccessPolicies = appliedConditionalAccessPolicies
        self.deviceDetail = deviceDetail
        self.riskLevelAggregated = riskLevelAggregated
        self.riskLevelDuringSignIn = riskLevelDuringSignIn
        self.riskState = riskState
        self.riskDetail = riskDetail
        self.isInteractive = isInteractive
        self.correlationId = correlationId
    }

    public var errorCode: Int { status?.errorCode ?? 0 }
    public var isFailure: Bool { errorCode != 0 }

    /// The policies that were evaluated and either passed or blocked, failures first.
    public var decisivePolicies: [AppliedPolicy] {
        (appliedConditionalAccessPolicies ?? []).filter(\.applied).sorted { a, b in a.failed && !b.failed }
    }
    public var blockingPolicies: [AppliedPolicy] { decisivePolicies.filter(\.failed) }

    /// Legacy authentication clients stand out because blocking them is the single most
    /// common Conditional Access policy, and the reason it fired is in this field.
    public var isLegacyClient: Bool {
        guard let client = clientAppUsed?.lowercased() else { return false }
        return SignInVocabulary.legacyClients.contains(client)
    }

    /// Entra returns `hidden` for every risk field on a tenant without P2.
    public var riskIsHidden: Bool {
        riskLevelAggregated?.lowercased() == "hidden" || riskLevelDuringSignIn?.lowercased() == "hidden"
    }

    public var hasRisk: Bool {
        guard !riskIsHidden else { return false }
        let levels = [riskLevelAggregated, riskLevelDuringSignIn].compactMap { $0?.lowercased() }
        return levels.contains { $0 != "none" }
    }
}

/// A person, from the user search.
public struct DirectoryUser: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let displayName: String?
    public let userPrincipalName: String?
    public let mail: String?

    public init(id: String, displayName: String?, userPrincipalName: String?, mail: String? = nil) {
        self.id = id
        self.displayName = displayName
        self.userPrincipalName = userPrincipalName
        self.mail = mail
    }
}

public enum SignInVocabulary {
    public static let legacyClients: Set<String> = ["exchange activesync", "imap", "mapi", "smtp", "pop", "other clients", "authenticated smtp", "exchange web services", "autodiscover", "offline address book", "reporting web services", "exchange online powershell"]

    public static func conditionalAccessLabel(_ status: String?) -> String {
        switch status?.lowercased() {
        case "success":    return "Passed"
        case "failure":    return "Blocked"
        case "notapplied": return "No policy applied"
        default:           return status ?? "Unknown"
        }
    }

    public static func policyResultLabel(_ result: String?) -> String {
        switch result?.lowercased() {
        case "success":                return "Passed"
        case "failure":                return "Blocked"
        case "notapplied":             return "Not applied"
        case "notenabled":             return "Policy off"
        case "reportonlysuccess":      return "Report-only: would pass"
        case "reportonlyfailure":      return "Report-only: would block"
        case "reportonlynotapplied":   return "Report-only: not applied"
        case "reportonlyinterrupted":  return "Report-only: interrupted"
        default:                       return result ?? "Unknown"
        }
    }

    public static func riskLabel(_ level: String?) -> String {
        switch level?.lowercased() {
        case "none":   return "None"
        case "low":    return "Low"
        case "medium": return "Medium"
        case "high":   return "High"
        case "hidden": return "Needs Entra ID P2"
        default:       return level ?? "Unknown"
        }
    }

    public static func riskStateLabel(_ state: String?) -> String {
        switch state?.lowercased() {
        case "none":                 return "None"
        case "atrisk":               return "At risk"
        case "confirmedsafe":        return "Confirmed safe"
        case "confirmedcompromised": return "Confirmed compromised"
        case "remediated":           return "Remediated"
        case "dismissed":            return "Dismissed"
        default:                     return state ?? "Unknown"
        }
    }
}
