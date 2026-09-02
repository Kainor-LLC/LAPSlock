import Foundation

// Building the POST body for `roleAssignmentScheduleRequests`, and reading the response.
//
// Pure. It builds and parses JSON and knows nothing about the network, so the request shape
// and every response branch are covered by tests without a tenant — which matters because
// the branch that must never be got wrong (pending approval reported as success) is
// otherwise only reachable in a tenant configured to require approval.

public enum ActivationRequest {

    /// Graph's cap for self-activation is 8 hours; tenants commonly configure less. Five is
    /// a working afternoon, long enough to finish a job and short enough that a forgotten
    /// activation expires on its own.
    public static let defaultDuration = "PT5H"

    /// Body for `POST /v1.0/roleManagement/directory/roleAssignmentScheduleRequests`.
    ///
    /// - Parameter justification: the reason, which lands in the customer's own audit log.
    ///   Required by many tenant policies and useful in all of them.
    public static func selfActivateBody(
        principalId: String,
        roleDefinitionId: String,
        directoryScopeId: String,
        justification: String,
        duration: String = defaultDuration,
        ticketNumber: String? = nil,
        ticketSystem: String? = nil
    ) -> [String: Any] {
        var body: [String: Any] = [
            "action": "selfActivate",
            "principalId": principalId,
            "roleDefinitionId": roleDefinitionId,
            "directoryScopeId": directoryScopeId,
            "justification": justification,
            "scheduleInfo": [
                "startDateTime": ISO8601DateFormatter.graph.string(from: Date()),
                "expiration": [
                    "type": "afterDuration",
                    "duration": duration,
                ],
            ],
        ]
        // Only sent when the user supplied one. An empty ticketInfo is noise in an audit log.
        if let ticketNumber, !ticketNumber.isEmpty {
            body["ticketInfo"] = [
                "ticketNumber": ticketNumber,
                "ticketSystem": ticketSystem ?? "",
            ]
        }
        return body
    }

    /// Reads the outcome from a `roleAssignmentScheduleRequests` response.
    ///
    /// **The status field is the whole point.** Graph returns 201 whether the role was
    /// granted or merely requested; only `status` distinguishes them. Anything not clearly
    /// provisioned is reported as pending, because over-reporting success is the failure that
    /// sends someone back to a broken machine believing they have access.
    public static func outcome(from json: [String: Any]) -> ActivationOutcome {
        let status = (json["status"] as? String)?.lowercased() ?? ""
        let requestId = json["id"] as? String

        let granted: Set<String> = ["provisioned", "granted"]
        guard granted.contains(status) else {
            return .pendingApproval(requestId: requestId)
        }

        let expiry = (json["scheduleInfo"] as? [String: Any])
            .flatMap { $0["expiration"] as? [String: Any] }
            .flatMap { $0["endDateTime"] as? String }
            .flatMap { ISO8601DateFormatter.graphDate($0) }

        return .activated(until: expiry)
    }

    /// Parses `roleEligibilitySchedules`, tolerating the shapes Graph actually returns.
    ///
    /// Entries missing a role definition id are skipped rather than failing the whole list:
    /// one malformed schedule should not hide every other role the user could activate.
    public static func eligibleRoles(from json: [String: Any]) -> [EligibleRole] {
        guard let items = json["value"] as? [[String: Any]] else { return [] }

        return items.compactMap { item in
            guard let roleDefinitionId = item["roleDefinitionId"] as? String, !roleDefinitionId.isEmpty
            else { return nil }

            // `roleDefinition` is present only when the caller asked Graph to expand it.
            let displayName = (item["roleDefinition"] as? [String: Any])?["displayName"] as? String

            let endsAt = (item["scheduleInfo"] as? [String: Any])
                .flatMap { $0["expiration"] as? [String: Any] }
                .flatMap { $0["endDateTime"] as? String }
                .flatMap { ISO8601DateFormatter.graphDate($0) }

            return EligibleRole(
                id: item["id"] as? String ?? roleDefinitionId,
                roleDefinitionId: roleDefinitionId,
                displayName: displayName,
                directoryScopeId: item["directoryScopeId"] as? String ?? "/",
                eligibilityEndsAt: endsAt
            )
        }
        // Roles that can actually read a credential first: this list exists to unblock a
        // reveal, so the role that unblocks it should not be third in the list.
        .sorted { lhs, rhs in
            if lhs.canReadLocalCredentials != rhs.canReadLocalCredentials {
                return lhs.canReadLocalCredentials
            }
            return lhs.label.localizedCaseInsensitiveCompare(rhs.label) == .orderedAscending
        }
    }
}

extension ISO8601DateFormatter {
    /// Graph emits fractional seconds on some endpoints and not others, so parsing needs to
    /// accept both. A single formatter configured one way silently returns nil for the other.
    static let graph: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    static let graphNoFraction: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    static func graphDate(_ value: String) -> Date? {
        graph.date(from: value) ?? graphNoFraction.date(from: value)
    }
}
