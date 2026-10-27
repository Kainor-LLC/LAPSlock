import Foundation

// The large demo tenant's groups (optimization plan step C): a person in 300 groups, so the
// cost of reading each group's facts shows at the size it reaches in a large tenant.

extension DemoGroupWritesProvider {

    public static func largeGroups(count: Int = 300) -> [DirectoryGroup] {
        let kinds = ["HD", "APP", "LIC", "TEAM", "CA", "DEPT"]
        return (0..<max(0, count)).map { i in
            let kind = kinds[i % kinds.count]
            return DirectoryGroup(
                id: "large-g-" + String(i),
                displayName: kind + "-" + String(format: "%03d", i) + " Members",
                description: "Generated for measuring",
                groupTypes: kind == "TEAM" ? ["Unified"] : [],
                isAssignableToRole: i % 50 == 0,
                mailEnabled: kind == "TEAM")
        }
    }
}
