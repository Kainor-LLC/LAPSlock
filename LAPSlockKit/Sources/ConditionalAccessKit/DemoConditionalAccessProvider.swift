import Foundation

// Demo Conditional Access. Powers previews, development without a tenant, and App Store
// review. The policies are chosen to exercise every row and section the screens have:
// every state, a change inside the badge window and well outside it, keywords beside real
// ids, roles, an authentication strength, terms of use, a device filter, session controls,
// and a policy with no grant controls at all.

public actor DemoConditionalAccessProvider: ConditionalAccessProviding {

    private let latency: Duration
    private let now: Date
    /// The second sample customer in demo mode: a calm tenant with nothing open, so switching
    /// customers shows different data and anything left over from the first stands out.
    private let quiet: Bool
    /// The large demo tenant's 150 policies in place of the hand-built ones.
    private let large: Bool

    public init(latency: Duration = .milliseconds(400), now: Date = Date(), quiet: Bool = false, large: Bool = false) {
        self.latency = latency
        self.now = now
        self.quiet = quiet
        self.large = large
    }

    public func policies() async throws -> [ConditionalAccessPolicy] {
        try await Task.sleep(for: latency)
        if quiet { return [] }
        let policies = large ? Self.largePolicies(now: now) : Self.policies(now: now)
        return policies.sorted(by: ConditionalAccessService.newestChangeFirst)
    }

    public func names(for references: Set<DirectoryReference>) async throws -> [DirectoryReference: String] {
        try await Task.sleep(for: latency)
        var result: [DirectoryReference: String] = [:]
        for reference in references {
            if let name = Self.names[reference.id] ?? (large ? Self.largeName(for: reference) : nil) { result[reference] = name }
        }
        return result
    }

    public func changes(forPolicyId policyId: String) async throws -> [PolicyChange] {
        try await Task.sleep(for: latency)
        return quiet ? [] : Self.changes(now: now)[policyId] ?? []
    }

    public func reset() {}

    // MARK: - fixtures

    public static let breakGlassGroup = "a1b2c3d4-0001-4000-8000-000000000001"
    public static let helpdeskGroup = "a1b2c3d4-0002-4000-8000-000000000002"
    public static let contractorsGroup = "a1b2c3d4-0003-4000-8000-000000000003"
    public static let serviceAccountUser = "a1b2c3d4-0004-4000-8000-000000000004"
    public static let globalAdministratorRole = "62e90394-69f5-4237-9190-012177145e10"
    public static let securityAdministratorRole = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    public static let headOfficeLocation = "a1b2c3d4-0005-4000-8000-000000000005"
    public static let azureManagementApp = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
    public static let unresolvedApp = "a1b2c3d4-0006-4000-8000-000000000006"

    public static let names: [String: String] = [
        breakGlassGroup: "Break-glass accounts",
        helpdeskGroup: "Helpdesk",
        contractorsGroup: "Contractors",
        serviceAccountUser: "svc-backup",
        globalAdministratorRole: "Global Administrator",
        securityAdministratorRole: "Security Administrator",
        headOfficeLocation: "Head office",
        azureManagementApp: "Windows Azure Service Management API"
        // unresolvedApp is deliberately absent: the screen must cope with an id it cannot name.
    ]

    public static let requireMFAId = "d0000000-0000-4000-8000-000000000001"
    public static let blockLegacyId = "d0000000-0000-4000-8000-000000000002"
    public static let compliantDeviceId = "d0000000-0000-4000-8000-000000000003"
    public static let adminStrengthId = "d0000000-0000-4000-8000-000000000004"
    public static let locationsId = "d0000000-0000-4000-8000-000000000005"
    public static let signInFrequencyId = "d0000000-0000-4000-8000-000000000006"
    public static let guestsTermsId = "d0000000-0000-4000-8000-000000000007"
    public static let riskId = "d0000000-0000-4000-8000-000000000008"

    static func daysAgo(_ days: Double, from now: Date) -> Date {
        now.addingTimeInterval(-days * 86_400)
    }

    public static func policies(now: Date) -> [ConditionalAccessPolicy] {
        [
            ConditionalAccessPolicy(
                id: requireMFAId,
                displayName: "Require MFA for all users",
                state: .enabled,
                createdDateTime: daysAgo(400, from: now),
                modifiedDateTime: daysAgo(40, from: now),
                conditions: .init(
                    users: .init(includeUsers: ["All"], excludeGroups: [breakGlassGroup]),
                    applications: .init(includeApplications: ["All"]),
                    clientAppTypes: ["all"]),
                grantControls: .init(operator: "OR", builtInControls: ["mfa"])),
            ConditionalAccessPolicy(
                id: blockLegacyId,
                displayName: "Block legacy authentication",
                state: .enabled,
                createdDateTime: daysAgo(380, from: now),
                modifiedDateTime: daysAgo(200, from: now),
                conditions: .init(
                    users: .init(includeUsers: ["All"], excludeUsers: [serviceAccountUser], excludeGroups: [breakGlassGroup]),
                    applications: .init(includeApplications: ["All"]),
                    clientAppTypes: ["exchangeActiveSync", "other"]),
                grantControls: .init(operator: "OR", builtInControls: ["block"])),
            ConditionalAccessPolicy(
                id: compliantDeviceId,
                displayName: "Require compliant device for Office 365",
                state: .enabled,
                createdDateTime: daysAgo(300, from: now),
                modifiedDateTime: daysAgo(3, from: now),
                conditions: .init(
                    users: .init(includeGroups: [helpdeskGroup, contractorsGroup]),
                    applications: .init(includeApplications: ["Office365"]),
                    platforms: .init(includePlatforms: ["windows", "macOS"]),
                    clientAppTypes: ["browser", "mobileAppsAndDesktopClients"],
                    devices: .init(deviceFilter: .init(mode: "exclude", rule: "device.isCompliant -eq True"))),
                grantControls: .init(operator: "OR", builtInControls: ["compliantDevice", "domainJoinedDevice"])),
            ConditionalAccessPolicy(
                id: adminStrengthId,
                displayName: "Admins: phishing-resistant MFA",
                state: .enabled,
                createdDateTime: daysAgo(120, from: now),
                modifiedDateTime: daysAgo(1, from: now),
                conditions: .init(
                    users: .init(includeRoles: [globalAdministratorRole, securityAdministratorRole]),
                    applications: .init(includeApplications: ["All"]),
                    clientAppTypes: ["all"]),
                grantControls: .init(
                    operator: "AND",
                    builtInControls: ["mfa"],
                    authenticationStrength: .init(id: "00000000-0000-0000-0000-000000000004", displayName: "Phishing-resistant MFA"))),
            ConditionalAccessPolicy(
                id: locationsId,
                displayName: "Block access from outside trusted locations",
                state: .reportOnly,
                createdDateTime: daysAgo(60, from: now),
                modifiedDateTime: daysAgo(10, from: now),
                conditions: .init(
                    users: .init(includeUsers: ["All"], excludeGroups: [breakGlassGroup]),
                    applications: .init(includeApplications: [azureManagementApp, unresolvedApp]),
                    locations: .init(includeLocations: ["All"], excludeLocations: ["AllTrusted", headOfficeLocation]),
                    clientAppTypes: ["all"]),
                grantControls: .init(operator: "OR", builtInControls: ["block"])),
            ConditionalAccessPolicy(
                id: signInFrequencyId,
                displayName: "Sign-in frequency on unmanaged devices",
                state: .disabled,
                createdDateTime: daysAgo(200, from: now),
                modifiedDateTime: daysAgo(90, from: now),
                conditions: .init(
                    users: .init(includeUsers: ["All"]),
                    applications: .init(includeApplications: ["All"]),
                    clientAppTypes: ["browser"],
                    devices: .init(deviceFilter: .init(mode: "include", rule: "device.trustType -ne \"ServerAD\""))),
                sessionControls: .init(
                    signInFrequency: .init(value: 1, type: "hours", isEnabled: true, frequencyInterval: "timeBased"),
                    persistentBrowser: .init(mode: "never", isEnabled: true))),
            ConditionalAccessPolicy(
                id: guestsTermsId,
                displayName: "Guests: accept terms of use",
                state: .enabled,
                createdDateTime: daysAgo(30, from: now),
                modifiedDateTime: daysAgo(5, from: now),
                conditions: .init(
                    users: .init(includeUsers: ["GuestsOrExternalUsers"]),
                    applications: .init(includeApplications: ["All"]),
                    clientAppTypes: ["all"]),
                grantControls: .init(operator: "AND", builtInControls: ["mfa"], termsOfUse: ["tou-0001"])),
            ConditionalAccessPolicy(
                id: riskId,
                displayName: "Risky sign-ins require MFA and password change",
                state: .enabled,
                createdDateTime: daysAgo(15, from: now),
                modifiedDateTime: nil,
                conditions: .init(
                    users: .init(includeUsers: ["All"], excludeGroups: [breakGlassGroup]),
                    applications: .init(includeApplications: ["All"]),
                    clientAppTypes: ["all"],
                    signInRiskLevels: ["high", "medium"],
                    userRiskLevels: ["high"]),
                grantControls: .init(operator: "AND", builtInControls: ["mfa", "passwordChange"]))
        ]
    }

    public static func changes(now: Date) -> [String: [PolicyChange]] {
        [
            compliantDeviceId: [
                PolicyChange(
                    id: "e0000000-0000-4000-8000-000000000001",
                    activity: "Update conditional access policy",
                    at: daysAgo(3, from: now),
                    actor: "sec-admin@demo.example",
                    result: "success",
                    changedProperties: ["ConditionalAccessPolicy"]),
                PolicyChange(
                    id: "e0000000-0000-4000-8000-000000000002",
                    activity: "Update conditional access policy",
                    at: daysAgo(45, from: now),
                    actor: "sec-admin@demo.example",
                    result: "success",
                    changedProperties: ["ConditionalAccessPolicy"])
            ],
            adminStrengthId: [
                PolicyChange(
                    id: "e0000000-0000-4000-8000-000000000003",
                    activity: "Update conditional access policy",
                    at: daysAgo(1, from: now),
                    actor: "Microsoft Entra Conditional Access",
                    result: "success",
                    changedProperties: ["ConditionalAccessPolicy"])
            ]
        ]
    }
}
