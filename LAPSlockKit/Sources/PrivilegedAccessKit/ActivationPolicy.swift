import Foundation

// What the tenant's PIM policy actually allows, read rather than guessed.
//
// WHY THIS EXISTS. The activation duration was a hardcoded guess, then a fixed picker. Both
// are wrong for the same reason: every PIM policy caps activation length, the cap is set
// per-tenant and often per-group, and asking for longer than allowed is refused with a bare
// 400 that names no reason. Offering "8 hours" to a tenant that permits three is offering a
// button that cannot work.
//
// The same policy answers three other questions the UI was guessing at: whether a
// justification is required, whether a ticket number is required, and whether activation
// demands a Conditional Access authentication context. That last one is what produced
// `RoleAssignmentRequestAcrsValidationFailed` on device — reading it up front turns a
// mid-activation failure into a sign-in that happens before the request.

/// The end-user activation rules from a PIM policy.
public struct ActivationPolicy: Sendable, Equatable {

    /// Longest activation the policy permits, as an ISO 8601 duration.
    public let maximumDuration: String?
    public let justificationRequired: Bool
    public let ticketRequired: Bool
    public let multiFactorRequired: Bool
    /// The `acrs` value activation demands, when the policy requires an authentication
    /// context. Knowing it in advance means the token can carry it on the first attempt.
    public let authenticationContextClaim: String?

    public init(
        maximumDuration: String? = nil,
        justificationRequired: Bool = false,
        ticketRequired: Bool = false,
        multiFactorRequired: Bool = false,
        authenticationContextClaim: String? = nil
    ) {
        self.maximumDuration = maximumDuration
        self.justificationRequired = justificationRequired
        self.ticketRequired = ticketRequired
        self.multiFactorRequired = multiFactorRequired
        self.authenticationContextClaim = authenticationContextClaim
    }

    /// Nothing known. Every field permissive except the ones the UI already asks for anyway,
    /// so a tenant whose policy could not be read behaves exactly as it did before this
    /// type existed — the policy read is an improvement, never a new way to fail.
    public static let unknown = ActivationPolicy()

    /// Durations to offer, capped at what the policy allows.
    ///
    /// Returns the standard options up to and including the maximum, and if the maximum is
    /// not one of them — three hours, say — the maximum itself is added so the user can use
    /// their whole allowance. Never offers something the policy will refuse.
    public var offeredDurations: [(label: String, iso: String)] {
        guard let maximumDuration, let maxHours = Self.hours(maximumDuration) else {
            return ActivationRequest.durations
        }
        var options = ActivationRequest.durations.filter {
            (Self.hours($0.iso) ?? .max) <= maxHours
        }
        if !options.contains(where: { $0.iso == maximumDuration }) {
            options.append((label: Self.label(hours: maxHours), iso: maximumDuration))
        }
        // A policy shorter than an hour leaves nothing standard to offer, so offer its
        // maximum rather than an empty picker.
        return options.isEmpty
            ? [(label: Self.label(hours: maxHours), iso: maximumDuration)]
            : options.sorted { (Self.hours($0.iso) ?? 0) < (Self.hours($1.iso) ?? 0) }
    }

    /// Whole hours in an ISO 8601 duration, for the shapes PIM actually emits: `PT3H`,
    /// `PT30M`, `P1D`. Nil for anything else rather than a wrong number.
    public static func hours(_ iso: String) -> Int? {
        if let range = iso.range(of: "^PT([0-9]{1,3})H$", options: .regularExpression) {
            return Int(iso[range].dropFirst(2).dropLast())
        }
        if let range = iso.range(of: "^PT([0-9]{1,4})M$", options: .regularExpression) {
            // Rounds DOWN: a 90-minute policy offers one hour, never two.
            return (Int(iso[range].dropFirst(2).dropLast()) ?? 0) / 60
        }
        if let range = iso.range(of: "^P([0-9]{1,3})D$", options: .regularExpression) {
            return (Int(iso[range].dropFirst().dropLast()) ?? 0) * 24
        }
        return nil
    }

    public static func label(hours: Int) -> String {
        hours == 1 ? "1 hour" : "\(hours) hours"
    }

    // MARK: - parsing

    /// Reads the end-user activation rules out of a policy's expanded `rules` collection.
    ///
    /// Rule ids are immutable and identical in every tenant, which is why they are matched
    /// rather than the localised display names beside them. Unknown rules are ignored, so a
    /// rule Microsoft adds later cannot break the read.
    public static func from(rules: [[String: Any]]) -> ActivationPolicy {
        var maximumDuration: String?
        var justification = false
        var ticket = false
        var multiFactor = false
        var claim: String?

        for rule in rules {
            switch rule["id"] as? String {
            case "Expiration_EndUser_Assignment":
                maximumDuration = rule["maximumDuration"] as? String
            case "Enablement_EndUser_Assignment":
                let enabled = (rule["enabledRules"] as? [String] ?? []).map { $0.lowercased() }
                justification = enabled.contains("justification")
                ticket = enabled.contains("ticketing")
                multiFactor = enabled.contains("multifactorauthentication")
            case "AuthenticationContext_EndUser_Assignment":
                // Only when actually enabled: a disabled rule still carries a claim value,
                // and requesting a context the policy does not want would prompt for
                // nothing.
                if rule["isEnabled"] as? Bool == true {
                    claim = rule["claimValue"] as? String
                }
            default:
                continue
            }
        }

        return ActivationPolicy(
            maximumDuration: maximumDuration,
            justificationRequired: justification,
            ticketRequired: ticket,
            multiFactorRequired: multiFactor,
            authenticationContextClaim: claim)
    }

    /// Reads the first policy out of a `roleManagementPolicies` response.
    public static func from(policiesResponse json: [String: Any]) -> ActivationPolicy {
        guard let policies = json["value"] as? [[String: Any]],
              let rules = policies.compactMap({ $0["rules"] as? [[String: Any]] }).first
        else { return .unknown }
        return from(rules: rules)
    }
}
