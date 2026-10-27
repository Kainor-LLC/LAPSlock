import Foundation

// The large demo tenant's Conditional Access policies (optimization plan step C): 150
// policies naming hundreds of users, groups and applications, deterministic from the index.

extension DemoConditionalAccessProvider {

    /// A directory id in the large tenant's own range, GUID-shaped like the real ones.
    static func largeId(_ kind: Int, _ n: Int) -> String {
        "c0de" + String(format: "%04d", kind) + "-0000-4000-8000-" + String(format: "%012d", n)
    }

    public static func largePolicies(now: Date, count: Int = 150) -> [ConditionalAccessPolicy] {
        let subjects = ["Require MFA for", "Block legacy authentication for", "Require compliant device for",
                        "Sign-in frequency for", "Block high-risk sign-ins for", "Require phishing-resistant MFA for"]
        let audiences = ["finance", "contractors", "admins", "sales", "field staff", "guests", "pilot users", "executives"]
        let states: [ConditionalAccessPolicy.State] = [.enabled, .enabled, .reportOnly, .disabled]
        return (0..<max(0, count)).map { i in
            let groups = (0..<(1 + i % 6)).map { largeId(2, i * 7 + $0) }
            let excluded = (0..<(i % 3)).map { largeId(1, i * 5 + $0) }
            let apps = i % 4 == 0 ? ["All"] : (0..<(1 + i % 5)).map { largeId(4, i * 3 + $0) }
            return ConditionalAccessPolicy(
                id: largeId(9, i),
                displayName: subjects[i % subjects.count] + " " + audiences[i % audiences.count] + " " + String(i),
                state: states[i % states.count],
                createdDateTime: now.addingTimeInterval(-Double(400 - i) * 86_400),
                modifiedDateTime: now.addingTimeInterval(-Double(i % 90) * 86_400),
                conditions: .init(
                    users: .init(excludeUsers: excluded, includeGroups: groups, excludeGroups: [breakGlassGroup]),
                    applications: .init(includeApplications: apps),
                    clientAppTypes: ["all"]),
                grantControls: .init(operator: "OR", builtInControls: i % 6 == 1 ? ["block"] : ["mfa"]))
        }
    }

    /// Names for the large tenant's ids: a readable label from the kind and number.
    static func largeName(for reference: DirectoryReference) -> String? {
        guard reference.id.hasPrefix("c0de") else { return nil }
        let number = Int(reference.id.suffix(12)) ?? 0
        switch reference.kind {
        case .user:        return "Person " + String(number)
        case .group:       return "Group " + String(number)
        case .application: return "App " + String(number)
        case .role:        return "Role " + String(number)
        case .location:    return "Location " + String(number)
        }
    }
}
