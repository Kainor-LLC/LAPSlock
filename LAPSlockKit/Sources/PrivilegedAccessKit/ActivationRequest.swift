import Foundation

// Building activation requests and reading their outcomes, for both PIM surfaces.
//
// Pure: it builds and parses JSON and knows nothing about the network, so every response
// branch is covered by tests without a tenant. That matters most for the branch that must
// never be got wrong — a pending approval reported as success — which is otherwise only
// reachable in a tenant configured to require approval.

public enum ActivationRequest {

    /// Durations offered, shortest first.
    ///
    /// **The default is deliberately the shortest, and that is a correctness matter rather
    /// than a security preference.** Every PIM policy caps how long access may be activated
    /// for, the cap is per-tenant and often per-group, and asking for longer than the policy
    /// allows is rejected with a bare 400 that names no reason. A hardcoded five hours
    /// therefore failed outright in a tenant whose policy allowed less — the request was not
    /// merely generous, it was invalid.
    ///
    /// One hour clears almost any policy and is enough to finish a job at a bench. Anyone
    /// who needs longer can choose it and will be told if their policy refuses.
    public static let durations: [(label: String, iso: String)] = [
        ("1 hour", "PT1H"),
        ("2 hours", "PT2H"),
        ("4 hours", "PT4H"),
        ("8 hours", "PT8H"),
    ]

    public static let defaultDuration = "PT1H"

    /// A request ready to send: which endpoint, and what body.
    ///
    /// Returned together because they are not independent. The two PIM surfaces take
    /// different bodies at different paths, and pairing them here means a caller cannot post
    /// a group body to the roles endpoint.
    public struct Prepared: Sendable, Equatable {
        public let path: String
        /// The flat top-level fields. Typed as strings because every one of them is a
        /// string: no `[String: Any]` here, so `Prepared` is genuinely `Sendable` rather
        /// than nominally so.
        public let fields: [String: String]
        public let startDateTime: String
        public let duration: String
        public let ticket: Ticket?

        /// The body as Graph wants it. Built on demand, so the nested shape never has to be
        /// stored in a form that defeats `Sendable`.
        public var json: [String: Any] {
            var body: [String: Any] = fields
            body["scheduleInfo"] = [
                "startDateTime": startDateTime,
                "expiration": ["type": "afterDuration", "duration": duration],
            ]
            // TOP LEVEL, beside scheduleInfo rather than inside it. It was nested at first,
            // which makes the whole request invalid — Graph rejects an unknown property on
            // scheduleInfo with a 400 that says nothing about which property.
            if let ticket {
                body["ticketInfo"] = [
                    "ticketNumber": ticket.number,
                    "ticketSystem": ticket.system,
                ]
            }
            return body
        }
    }

    /// A helpdesk reference, recorded in the customer's audit log alongside the activation.
    public struct Ticket: Sendable, Equatable {
        public let number: String
        public let system: String
        public init(number: String, system: String) {
            self.number = number
            self.system = system
        }
    }

    /// Builds a self-activation request for either kind of eligible access.
    ///
    /// - Parameter justification: the reason, which lands in the customer's own audit log.
    ///   Required by many tenant policies and worth sending in all of them: an activation
    ///   should be as traceable as the credential read it unblocks.
    public static func selfActivate(
        _ access: EligibleAccess,
        principalId: String,
        justification: String,
        duration: String = defaultDuration,
        ticketNumber: String? = nil,
        ticketSystem: String? = nil
    ) -> Prepared {

        var body: [String: String] = [
            // `selfActivate` acts only on the caller's own existing eligibility. No other
            // action belongs in this app: anything else would be administering somebody
            // else's access.
            "action": "selfActivate",
            "principalId": principalId,
            "justification": justification,
        ]

        let path: String
        switch access.kind {
        case .directoryRole(let roleDefinitionId, let directoryScopeId):
            path = PrivilegedAccessGraph.roleActivationPath
            body["roleDefinitionId"] = roleDefinitionId
            body["directoryScopeId"] = directoryScopeId
        case .group(let groupId, let accessId):
            path = PrivilegedAccessGraph.groupActivationPath
            body["groupId"] = groupId
            body["accessId"] = accessId.rawValue
        }

        // Only when supplied. An empty ticketInfo is noise in an audit log.
        let ticket = (ticketNumber?.isEmpty == false)
            ? Ticket(number: ticketNumber!, system: ticketSystem ?? "")
            : nil

        return Prepared(
            path: path,
            fields: body,
            startDateTime: ISO8601DateFormatter.graphNoFraction.string(from: Date()),
            duration: duration,
            ticket: ticket
        )
    }

    /// Reads the outcome of an activation request.
    ///
    /// **The status field is the whole point.** Graph answers 201 whether access was granted
    /// or merely requested, and only `status` distinguishes them. Anything not clearly
    /// provisioned reports as pending, because over-reporting success is what sends somebody
    /// back to a broken machine believing they have access.
    public static func outcome(from json: [String: Any]) -> ActivationOutcome {
        // Lowercased but deliberately NOT trimmed. Case varies across Graph endpoints so
        // folding it is necessary; whitespace does not, and trimming would make a padded
        // "Granted " parse as success. That is the unsafe direction — this function's job is
        // to under-promise, and a status that is not exactly a grant is not clearly a grant.
        let status = (json["status"] as? String)?.lowercased() ?? ""
        let requestId = json["id"] as? String

        guard ["provisioned", "granted"].contains(status) else {
            return .pendingApproval(requestId: requestId)
        }

        let expiry = (json["scheduleInfo"] as? [String: Any])
            .flatMap { $0["expiration"] as? [String: Any] }
            .flatMap { $0["endDateTime"] as? String }
            .flatMap { ISO8601DateFormatter.graphDate($0) }

        return .activated(until: expiry)
    }

    // MARK: - parsing eligibility

    /// Parses `roleEligibilitySchedules`.
    public static func eligibleRoles(from json: [String: Any]) -> [EligibleAccess] {
        items(in: json).compactMap { item in
            guard let roleDefinitionId = nonEmpty(item["roleDefinitionId"]) else { return nil }
            return EligibleAccess(
                id: item["id"] as? String ?? roleDefinitionId,
                kind: .directoryRole(
                    roleDefinitionId: roleDefinitionId,
                    // Tenant-wide unless Graph says otherwise.
                    directoryScopeId: nonEmpty(item["directoryScopeId"]) ?? "/"
                ),
                displayName: (item["roleDefinition"] as? [String: Any])?["displayName"] as? String,
                eligibilityEndsAt: endDate(item)
            )
        }
    }

    /// Parses `privilegedAccess/group/eligibilitySchedules`.
    public static func eligibleGroups(from json: [String: Any]) -> [EligibleAccess] {
        items(in: json).compactMap { item in
            guard let groupId = nonEmpty(item["groupId"]) else { return nil }
            // An unrecognised accessId is skipped rather than guessed at: activating
            // ownership when the user is eligible for membership would be a different and
              // larger grant than they asked for.
            guard let raw = nonEmpty(item["accessId"]),
                  let accessId = GroupAccessId(rawValue: raw.lowercased())
            else { return nil }

            return EligibleAccess(
                id: item["id"] as? String ?? "\(groupId)-\(accessId.rawValue)",
                kind: .group(groupId: groupId, accessId: accessId),
                displayName: (item["group"] as? [String: Any])?["displayName"] as? String,
                eligibilityEndsAt: endDate(item)
            )
        }
    }

    /// Both lists, ordered for the activation sheet.
    ///
    /// Three rules, in order:
    ///   1. Roles known to read credentials come first. The list exists to unblock a reveal,
    ///      so the entry that unblocks it should not be third.
    ///   2. Then the LEAST-PRIVILEGED option. Group ownership can change who else is in the
    ///      group, so where somebody is eligible for both membership and ownership,
    ///      membership is offered first — it is what reading one password needs. Ordering
    ///      the larger grant first invites activating it out of habit.
    ///   3. Then alphabetically, so the list is stable between runs.
    public static func combined(roles: [EligibleAccess], groups: [EligibleAccess]) -> [EligibleAccess] {
        (roles + groups).sorted { lhs, rhs in
            if lhs.canReadLocalCredentials != rhs.canReadLocalCredentials {
                return lhs.canReadLocalCredentials
            }
            if lhs.grantsManagementOfOthers != rhs.grantsManagementOfOthers {
                return !lhs.grantsManagementOfOthers
            }
            return lhs.label.localizedCaseInsensitiveCompare(rhs.label) == .orderedAscending
        }
    }

    // MARK: - shared parsing

    /// One malformed entry must not hide every other piece of access the user has, so
    /// entries are skipped individually rather than failing the whole list.
    private static func items(in json: [String: Any]) -> [[String: Any]] {
        json["value"] as? [[String: Any]] ?? []
    }

    private static func nonEmpty(_ value: Any?) -> String? {
        guard let s = value as? String, !s.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return s
    }

    private static func endDate(_ item: [String: Any]) -> Date? {
        (item["scheduleInfo"] as? [String: Any])
            .flatMap { $0["expiration"] as? [String: Any] }
            .flatMap { $0["endDateTime"] as? String }
            .flatMap { ISO8601DateFormatter.graphDate($0) }
    }
}

extension ISO8601DateFormatter {
    /// Graph emits fractional seconds on some endpoints and not others. A single formatter
    /// configured one way silently returns nil for the other, which would show access as
    /// active with no expiry.
    static let graphFractional: ISO8601DateFormatter = {
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
        graphFractional.date(from: value) ?? graphNoFraction.date(from: value)
    }
}
