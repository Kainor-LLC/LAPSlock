import Foundation

// Demo sign-in triage. Four people with enough sign-ins to show every row the screen has:
// successes, every common failure code in the glossary, a block with the policy named, a
// legacy client, a non-compliant device, hidden risk and real risk. Around them a directory
// of forty with two guests; the quiet customer has six of its own; the large demo has 5,000
// people and 50 guests, whose addresses are the ones the large Security demo names.

public actor DemoSignInTriageProvider: SignInTriageProviding {

    private let latency: Duration
    private let now: Date
    /// The second sample customer in demo mode: a calm tenant with nothing open, so switching
    /// customers shows different data and anything left over from the first stands out.
    private let quiet: Bool
    private let directory: [DirectoryUser]
    private let pageSize: Int

    public init(latency: Duration = .milliseconds(400), now: Date = Date(), quiet: Bool = false, large: Bool = false) {
        self.latency = latency
        self.now = now
        self.quiet = quiet
        self.directory = quiet ? Self.quietDirectory : large ? Self.largeDirectory() : Self.directory
        // Graph's own page for the large demo; small pages otherwise, so the fill shows.
        self.pageSize = large ? 999 : 25
    }

    public func searchUsers(prefix: String) async throws -> [DirectoryUser] {
        try await Task.sleep(for: latency)
        let needle = prefix.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard needle.count >= 2 else { return [] }
        let found = directory.filter {
            ($0.displayName ?? "").lowercased().hasPrefix(needle)
                || ($0.userPrincipalName ?? "").lowercased().hasPrefix(needle)
                || ($0.displayName ?? "").lowercased().split(separator: " ").contains { $0.hasPrefix(needle) }
        }
        return Array(found.prefix(10))
    }

    public func directoryPage(after next: URL?) async throws -> DirectoryPage {
        try await Task.sleep(for: latency)
        let start = next.flatMap { URLComponents(url: $0, resolvingAgainstBaseURL: false)?.queryItems?.first { $0.name == "$skiptoken" }?.value }
            .flatMap(Int.init) ?? 0
        let end = min(start + pageSize, directory.count)
        let users = start < end ? Array(directory[start..<end]) : []
        let more = end < directory.count ? URL(string: "https://graph.microsoft.com/v1.0/users?$skiptoken=" + String(end)) : nil
        return DirectoryPage(users: users, next: more)
    }

    public func signIns(_ query: SignInQuery) async throws -> [SignInEvent] {
        try await Task.sleep(for: latency)
        if quiet { return [] }
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

    private static let firstNames = ["Ada", "Ben", "Carmen", "Dev", "Elena", "Farid", "Grace", "Hugo", "Ines", "Jonas",
                                     "Kemi", "Liam", "Maya", "Nikhil", "Olga", "Pablo", "Quinn", "Rosa", "Sami", "Tomas",
                                     "Uma", "Victor", "Wren", "Xavier", "Yara", "Zoe", "Aiden", "Bea", "Chen", "Dara",
                                     "Emil", "Fatima", "Gus", "Hana", "Ivan", "Jade", "Kai", "Lena", "Marco", "Nora",
                                     "Omar", "Priya", "Rafael", "Sofia", "Theo", "Ursula", "Vera", "Will", "Yusuf", "Zara",
                                     "Amir", "Bianca", "Cole", "Dina", "Erik", "Freya", "Gabe", "Hiro", "Isla", "Joel"]
    private static let lastNames = ["Abbott", "Banerjee", "Castro", "Dimitrov", "Eriksen", "Fischer", "Garcia", "Haddad",
                                    "Ito", "Jensen", "Kowalski", "Lindqvist", "Moreau", "Nakamura", "Osei", "Petrov",
                                    "Quintero", "Rossi", "Silva", "Tanaka", "Ueda", "Varga", "Weber", "Xu", "Yilmaz",
                                    "Zhang", "Andersen", "Brennan", "Chowdhury", "Dubois", "Engel", "Ferreira", "Gill",
                                    "Horvat", "Iqbal", "Jovanovic", "Kim", "Larsen", "Mensah", "Novak", "Oduya", "Park",
                                    "Reyes", "Schmidt", "Torres", "Ulrich", "Vos", "Walsh", "Young", "Zimmer", "Afolabi",
                                    "Bauer", "Costa", "Dahl", "Evans", "Fontaine", "Grant", "Holm", "Ivanova", "Kaur",
                                    "Lopez", "Meyer", "Nguyen", "Olsen", "Pereira", "Ramos", "Santos", "Thomsen", "Vidal",
                                    "Wright", "Yamada", "Zeller", "Arslan", "Becker", "Cruz", "Diaz", "Ekstrom", "Flores",
                                    "Gomez", "Hughes", "Ilic", "Jung", "Klein", "Lam", "Molina", "Nilsen", "Ortiz", "Popescu"]

    private static func person(_ i: Int, offset: Int = 0) -> (name: String, handle: String) {
        let first = firstNames[(i + offset) % firstNames.count]
        let last = lastNames[((i + offset) / firstNames.count + i) % lastNames.count]
        return (first + " " + last, (first + "." + last).lowercased())
    }

    private static func guest(_ index: Int, _ name: String, _ handle: String, at domain: String, in tenant: String) -> DirectoryUser {
        DirectoryUser(id: "g-" + String(index), displayName: name + " (" + domain + ")",
                      userPrincipalName: handle + "_" + domain + "#EXT#@" + tenant,
                      mail: handle + "@" + domain)
    }

    /// The four with sign-ins, thirty-four colleagues and two guests.
    public static let directory: [DirectoryUser] = users
        + (0..<34).map { i in
            let p = person(i * 7, offset: 3)
            return DirectoryUser(id: "u-d" + String(i), displayName: p.name, userPrincipalName: p.handle + "@demo.example", mail: p.handle + "@demo.example")
        }
        + [guest(0, "Ana Ruiz", "ana.ruiz", at: "northwind.example", in: "demo.example"),
           guest(1, "Tom Becker", "tom.becker", at: "litware.example", in: "demo.example")]

    /// The second customer's people: none of the first's.
    public static let quietDirectory: [DirectoryUser] = (0..<6).map { i in
        let p = person(i * 11, offset: 17)
        return DirectoryUser(id: "u-f" + String(i), displayName: p.name, userPrincipalName: p.handle + "@fabrikam.example", mail: p.handle + "@fabrikam.example")
    }

    /// 5,000 people and 50 guests. Addresses `user0000` to `user4999`, the people the large
    /// Security demo's evidence names.
    public static func largeDirectory(people: Int = 5_000, guests: Int = 50) -> [DirectoryUser] {
        (0..<people).map { i in
            let address = "user" + String(format: "%04d", i) + "@demo.example"
            return DirectoryUser(id: "lu-" + String(i), displayName: person(i).name, userPrincipalName: address, mail: address)
        } + (0..<guests).map { i in
            let p = person(i * 13, offset: 29)
            return guest(100 + i, p.name, p.handle, at: "partner" + String(i % 5) + ".example", in: "demo.example")
        }
    }

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
