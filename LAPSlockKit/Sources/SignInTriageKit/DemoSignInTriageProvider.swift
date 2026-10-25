import Foundation

// Demo sign-in triage. Four people, enough sign-ins to show every row the screen has:
// successes, every common failure code in the glossary, a block with the policy named, a
// legacy client, a non-compliant device, hidden risk and real risk.

public actor DemoSignInTriageProvider: SignInTriageProviding {

    private let latency: Duration
    private let now: Date

    public init(latency: Duration = .milliseconds(400), now: Date = Date()) {
        self.latency = latency
        self.now = now
    }

    public func searchUsers(prefix: String) async throws -> [DirectoryUser] {
        try await Task.sleep(for: latency)
        let needle = prefix.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard needle.count >= 2 else { return [] }
        return Self.users.filter {
            ($0.displayName ?? "").lowercased().hasPrefix(needle)
                || ($0.userPrincipalName ?? "").lowercased().hasPrefix(needle)
                || ($0.displayName ?? "").lowercased().split(separator: " ").contains { $0.hasPrefix(needle) }
        }
    }

    public func signIns(_ query: SignInQuery) async throws -> [SignInEvent] {
        try await Task.sleep(for: latency)
        let all = Self.signIns(now: now).filter { $0.userPrincipalName?.lowercased() == query.userPrincipalName.lowercased() }
        let windowed = query.last24Hours ? all.filter { ($0.createdDateTime ?? .distantPast) >= now.addingTimeInterval(-86_400) } : all
        return query.apply(windowed.sorted { ($0.createdDateTime ?? .distantPast) > ($1.createdDateTime ?? .distantPast) })
    }

    public static let users: [DirectoryUser] = [
        DirectoryUser(id: "u-jane", displayName: "Jane Okafor", userPrincipalName: "jane.okafor@demo.example", mail: "jane.okafor@demo.example"),
        DirectoryUser(id: "u-raj", displayName: "Raj Patel", userPrincipalName: "raj.patel@demo.example", mail: "raj.patel@demo.example"),
        DirectoryUser(id: "u-svc", displayName: "svc-scanner", userPrincipalName: "svc-scanner@demo.example", mail: nil),
        DirectoryUser(id: "u-mei", displayName: "Mei Tanaka", userPrincipalName: "mei.tanaka@demo.example", mail: "mei.tanaka@demo.example"),
    ]

    static func hours(_ h: Double, from now: Date) -> Date { now.addingTimeInterval(-h * 3600) }

    public static func signIns(now: Date) -> [SignInEvent] {
        let mfaPolicy = SignInEvent.AppliedPolicy(id: "d0000000-0000-4000-8000-000000000001", displayName: "Require MFA for all users", result: "success", enforcedGrantControls: ["Mfa"])
        let compliantPolicy = SignInEvent.AppliedPolicy(id: "d0000000-0000-4000-8000-000000000003", displayName: "Require compliant device for Office 365", result: "failure", enforcedGrantControls: ["CompliantDevice"])
        let legacyPolicy = SignInEvent.AppliedPolicy(id: "d0000000-0000-4000-8000-000000000002", displayName: "Block legacy authentication", result: "failure", enforcedGrantControls: ["Block"])
        let locationPolicy = SignInEvent.AppliedPolicy(id: "d0000000-0000-4000-8000-000000000005", displayName: "Block access from outside trusted locations", result: "reportOnlyFailure", enforcedGrantControls: ["Block"])
        let notApplied = SignInEvent.AppliedPolicy(id: "d0000000-0000-4000-8000-000000000007", displayName: "Guests: accept terms of use", result: "notApplied")

        let janeLaptop = SignInEvent.DeviceDetail(deviceId: "dev-jane-1", displayName: "LT-FIELD-207", operatingSystem: "Windows 11", browser: "Edge 130.0.0", isCompliant: false, isManaged: true, trustType: "Azure AD joined")
        let janePhone = SignInEvent.DeviceDetail(deviceId: "dev-jane-2", displayName: "Jane's iPhone", operatingSystem: "iOS 27.1", browser: "Mobile Safari", isCompliant: true, isManaged: true, trustType: "Azure AD registered")
        let rajMac = SignInEvent.DeviceDetail(deviceId: "dev-raj-1", displayName: "MBP-ENG-11", operatingSystem: "macOS 26.1", browser: "Chrome 142.0.0", isCompliant: true, isManaged: true, trustType: "Azure AD registered")
        let unknownDevice = SignInEvent.DeviceDetail(deviceId: nil, displayName: nil, operatingSystem: "Windows 10", browser: "Chrome 141.0.0", isCompliant: nil, isManaged: nil, trustType: nil)

        let office = SignInEvent.Location(city: "Overland Park", state: "Kansas", countryOrRegion: "US")
        let home = SignInEvent.Location(city: "Lawrence", state: "Kansas", countryOrRegion: "US")
        let abroad = SignInEvent.Location(city: "Lagos", state: "Lagos", countryOrRegion: "NG")
        let odd = SignInEvent.Location(city: nil, state: nil, countryOrRegion: "RU")

        return [
            // Jane: the helpdesk ticket. Blocked by the compliant-device policy from her laptop.
            SignInEvent(id: "s-j1", createdDateTime: hours(0.4, from: now), userDisplayName: "Jane Okafor", userPrincipalName: "jane.okafor@demo.example", appDisplayName: "Microsoft Teams", resourceDisplayName: "Microsoft Graph", clientAppUsed: "Mobile Apps and Desktop clients", ipAddress: "198.51.100.23", location: office, status: .init(errorCode: 53000, failureReason: "Device is not in required device state: compliant.", additionalDetails: nil), conditionalAccessStatus: "failure", appliedConditionalAccessPolicies: [mfaPolicy, compliantPolicy, notApplied], deviceDetail: janeLaptop, riskLevelAggregated: "hidden", riskLevelDuringSignIn: "hidden", riskState: "none", riskDetail: "hidden"),
            SignInEvent(id: "s-j2", createdDateTime: hours(0.5, from: now), userDisplayName: "Jane Okafor", userPrincipalName: "jane.okafor@demo.example", appDisplayName: "Microsoft Teams", clientAppUsed: "Mobile Apps and Desktop clients", ipAddress: "198.51.100.23", location: office, status: .init(errorCode: 50074, failureReason: "Strong Authentication is required.", additionalDetails: nil), conditionalAccessStatus: "failure", appliedConditionalAccessPolicies: [mfaPolicy], deviceDetail: janeLaptop, riskLevelAggregated: "hidden", riskLevelDuringSignIn: "hidden", riskState: "none", riskDetail: "hidden"),
            SignInEvent(id: "s-j3", createdDateTime: hours(3, from: now), userDisplayName: "Jane Okafor", userPrincipalName: "jane.okafor@demo.example", appDisplayName: "Outlook Mobile", clientAppUsed: "Mobile Apps and Desktop clients", ipAddress: "203.0.113.8", location: home, status: .init(errorCode: 0, failureReason: nil, additionalDetails: nil), conditionalAccessStatus: "success", appliedConditionalAccessPolicies: [mfaPolicy, locationPolicy], deviceDetail: janePhone, riskLevelAggregated: "hidden", riskLevelDuringSignIn: "hidden", riskState: "none", riskDetail: "hidden"),
            SignInEvent(id: "s-j4", createdDateTime: hours(26, from: now), userDisplayName: "Jane Okafor", userPrincipalName: "jane.okafor@demo.example", appDisplayName: "Office 365 SharePoint Online", clientAppUsed: "Browser", ipAddress: "198.51.100.23", location: office, status: .init(errorCode: 0, failureReason: nil, additionalDetails: nil), conditionalAccessStatus: "success", appliedConditionalAccessPolicies: [mfaPolicy], deviceDetail: janeLaptop, riskLevelAggregated: "hidden", riskLevelDuringSignIn: "hidden", riskState: "none", riskDetail: "hidden"),
            SignInEvent(id: "s-j5", createdDateTime: hours(30, from: now), userDisplayName: "Jane Okafor", userPrincipalName: "jane.okafor@demo.example", appDisplayName: "Microsoft Teams", clientAppUsed: "Mobile Apps and Desktop clients", ipAddress: "198.51.100.23", location: office, status: .init(errorCode: 500121, failureReason: "Authentication failed during strong authentication request.", additionalDetails: "MFA denied; user declined the authentication"), conditionalAccessStatus: "failure", appliedConditionalAccessPolicies: [mfaPolicy], deviceDetail: janeLaptop, riskLevelAggregated: "hidden", riskLevelDuringSignIn: "hidden", riskState: "none", riskDetail: "hidden"),

            // Raj: fine, with one password slip.
            SignInEvent(id: "s-r1", createdDateTime: hours(1, from: now), userDisplayName: "Raj Patel", userPrincipalName: "raj.patel@demo.example", appDisplayName: "Azure Portal", clientAppUsed: "Browser", ipAddress: "198.51.100.40", location: office, status: .init(errorCode: 0, failureReason: nil, additionalDetails: nil), conditionalAccessStatus: "success", appliedConditionalAccessPolicies: [mfaPolicy], deviceDetail: rajMac, riskLevelAggregated: "none", riskLevelDuringSignIn: "none", riskState: "none", riskDetail: "none"),
            SignInEvent(id: "s-r2", createdDateTime: hours(1.1, from: now), userDisplayName: "Raj Patel", userPrincipalName: "raj.patel@demo.example", appDisplayName: "Azure Portal", clientAppUsed: "Browser", ipAddress: "198.51.100.40", location: office, status: .init(errorCode: 50126, failureReason: "Error validating credentials due to invalid username or password.", additionalDetails: nil), conditionalAccessStatus: "notApplied", appliedConditionalAccessPolicies: [], deviceDetail: rajMac, riskLevelAggregated: "none", riskLevelDuringSignIn: "none", riskState: "none", riskDetail: "none"),

            // Service account: legacy auth blocked, and a password spray from far away.
            SignInEvent(id: "s-s1", createdDateTime: hours(2, from: now), userDisplayName: "svc-scanner", userPrincipalName: "svc-scanner@demo.example", appDisplayName: "Office 365 Exchange Online", clientAppUsed: "IMAP", ipAddress: "198.51.100.77", location: office, status: .init(errorCode: 53003, failureReason: "Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.", additionalDetails: nil), conditionalAccessStatus: "failure", appliedConditionalAccessPolicies: [legacyPolicy], deviceDetail: unknownDevice, riskLevelAggregated: "none", riskLevelDuringSignIn: "none", riskState: "none", riskDetail: "none"),
            SignInEvent(id: "s-s2", createdDateTime: hours(5, from: now), userDisplayName: "svc-scanner", userPrincipalName: "svc-scanner@demo.example", appDisplayName: "Office 365 Exchange Online", clientAppUsed: "Other clients", ipAddress: "192.0.2.199", location: odd, status: .init(errorCode: 50126, failureReason: "Error validating credentials due to invalid username or password.", additionalDetails: nil), conditionalAccessStatus: "notApplied", appliedConditionalAccessPolicies: [], deviceDetail: unknownDevice, riskLevelAggregated: "medium", riskLevelDuringSignIn: "medium", riskState: "atRisk", riskDetail: "none"),
            SignInEvent(id: "s-s3", createdDateTime: hours(5.1, from: now), userDisplayName: "svc-scanner", userPrincipalName: "svc-scanner@demo.example", appDisplayName: "Office 365 Exchange Online", clientAppUsed: "Other clients", ipAddress: "192.0.2.199", location: odd, status: .init(errorCode: 50053, failureReason: "The account is locked, you've tried to sign in too many times with an incorrect user ID or password.", additionalDetails: nil), conditionalAccessStatus: "notApplied", appliedConditionalAccessPolicies: [], deviceDetail: unknownDevice, riskLevelAggregated: "medium", riskLevelDuringSignIn: "high", riskState: "atRisk", riskDetail: "none"),

            // Mei: travelling, report-only would have blocked her.
            SignInEvent(id: "s-m1", createdDateTime: hours(8, from: now), userDisplayName: "Mei Tanaka", userPrincipalName: "mei.tanaka@demo.example", appDisplayName: "Outlook Mobile", clientAppUsed: "Mobile Apps and Desktop clients", ipAddress: "203.0.113.150", location: abroad, status: .init(errorCode: 0, failureReason: nil, additionalDetails: nil), conditionalAccessStatus: "success", appliedConditionalAccessPolicies: [mfaPolicy, locationPolicy], deviceDetail: janePhone, riskLevelAggregated: "low", riskLevelDuringSignIn: "low", riskState: "none", riskDetail: "none"),
            SignInEvent(id: "s-m2", createdDateTime: hours(9, from: now), userDisplayName: "Mei Tanaka", userPrincipalName: "mei.tanaka@demo.example", appDisplayName: "Outlook Mobile", clientAppUsed: "Mobile Apps and Desktop clients", ipAddress: "203.0.113.150", location: abroad, status: .init(errorCode: 50076, failureReason: "Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication.", additionalDetails: nil), conditionalAccessStatus: "failure", appliedConditionalAccessPolicies: [mfaPolicy], deviceDetail: janePhone, riskLevelAggregated: "low", riskLevelDuringSignIn: "low", riskState: "none", riskDetail: "none"),
        ]
    }
}
