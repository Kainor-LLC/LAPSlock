import Foundation
import AuthKit
import ActionGateKit
import PrivilegedAccessKit

// User actions. Spec section 3.5: revoke sessions, block and unblock sign-in, the
// authentication wipe, and on Entra ID P2 tenants confirm compromised and dismiss risk.
// Every one is a WriteAction run by the gate. The Temporary Access Pass is not here: its
// response is a credential, and this target must never hold one, so it is issued on the
// credential path (CredentialKit) and only its role check and log line come through the
// gate.
//
// No password reset, decided in the spec: the recovery flow is the authentication wipe,
// then a TAP, then the person registers again.

public struct UserActionTarget: Sendable, Equatable {
    public let userId: String
    public let userPrincipalName: String
    public let displayName: String?
    public init(userId: String, userPrincipalName: String, displayName: String? = nil) {
        self.userId = userId
        self.userPrincipalName = userPrincipalName
        self.displayName = displayName
    }
    public var label: String { displayName ?? userPrincipalName }
}

/// Verified on the v1.0 reference pages 2026-10-26.
public enum UserActionScopes {
    public static let revokeSessions = "User.RevokeSessions.All"
    /// With User.Read.All, the least privileged combination for `accountEnabled`.
    public static let enableDisable = "User.EnableDisableAccount.All"
    public static let userRead = "User.Read.All"
    /// Listing and deleting another person's authentication methods.
    public static let authenticationMethods = "UserAuthenticationMethod.ReadWrite.All"
    /// Confirm compromised and dismiss; needs Entra ID P2 in the tenant.
    public static let riskyUsers = "IdentityRiskyUser.ReadWrite.All"
    /// The TAP, issued on the credential path, asked for with the rest.
    public static let temporaryAccessPass = "UserAuthMethod-TAP.ReadWrite.All"

    /// Requested together when the Settings switch is turned on.
    public static let module = [revokeSessions, enableDisable, userRead, authenticationMethods, riskyUsers, temporaryAccessPass]
}

/// Role template ids, identical in every tenant.
public enum UserActionRoles {
    public static let globalAdministrator = "62e90394-69f5-4237-9190-012177145e10"
    public static let userAdministrator = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    public static let authenticationAdministrator = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    public static let privilegedAuthenticationAdministrator = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
    public static let securityAdministrator = "194ae4cb-b126-40b2-bd5b-6091b380977d"
}

public enum UserActionKind: String, CaseIterable, Sendable, Identifiable {
    case revokeSessions
    case blockSignIn
    case unblockSignIn
    case authenticationWipe
    case issueTemporaryAccessPass
    case confirmCompromised
    case dismissRisk

    public var id: String { rawValue }
    public var actionId: String { "user." + rawValue }

    public var title: String {
        switch self {
        case .revokeSessions:           return "Revoke sessions"
        case .blockSignIn:              return "Block sign-in"
        case .unblockSignIn:            return "Allow sign-in"
        case .authenticationWipe:       return "Remove all sign-in methods"
        case .issueTemporaryAccessPass: return "Issue a Temporary Access Pass"
        case .confirmCompromised:       return "Confirm compromised"
        case .dismissRisk:              return "Dismiss risk"
        }
    }

    public var symbol: String {
        switch self {
        case .revokeSessions:           return "rectangle.portrait.and.arrow.forward"
        case .blockSignIn:              return "person.crop.circle.badge.xmark"
        case .unblockSignIn:            return "person.crop.circle.badge.checkmark"
        case .authenticationWipe:       return "key.slash"
        case .issueTemporaryAccessPass: return "ticket"
        case .confirmCompromised:       return "exclamationmark.shield"
        case .dismissRisk:              return "checkmark.shield"
        }
    }

    /// Spec section 3.5. The TAP's own gate is Face ID and the reveal timer, on the
    /// credential path; here it is confirm so a strict policy still raises it.
    public var tier: ActionTier {
        switch self {
        case .authenticationWipe: return .destructive
        default:                  return .confirm
        }
    }

    public var confirmation: String {
        switch self {
        case .revokeSessions:     return "Sign this person out everywhere? Every refresh token is revoked; apps ask them to sign in again within about an hour."
        case .blockSignIn:        return "Block this person from signing in? Existing sessions keep working until they expire; revoke sessions as well to end them now."
        case .unblockSignIn:      return "Allow this person to sign in again?"
        case .authenticationWipe: return "Remove every sign-in method this person has registered: Authenticator, phone, FIDO2 keys, Windows Hello, email, OATH tokens. Their password stays. At their next sign-in that needs MFA they register again; issue a Temporary Access Pass next so they can."
        case .issueTemporaryAccessPass: return "Issue a one-time Temporary Access Pass, valid for one hour? It replaces any pass they already have. Face ID before it is shown."
        case .confirmCompromised: return "Mark this person as compromised? Entra ID Protection sets their risk to high, and your risk-based Conditional Access policies apply."
        case .dismissRisk:        return "Dismiss this person's risk? Entra ID Protection sets it to none."
        }
    }

    public var successCopy: String {
        switch self {
        case .revokeSessions:     return "Sessions revoked. Apps ask them to sign in again within about an hour."
        case .blockSignIn:        return "Sign-in blocked."
        case .unblockSignIn:      return "Sign-in allowed again."
        case .authenticationWipe: return "Sign-in methods removed. Issue a Temporary Access Pass so they can register again."
        case .issueTemporaryAccessPass: return "Temporary Access Pass issued."
        case .confirmCompromised: return "Marked compromised. Risk is high."
        case .dismissRisk:        return "Risk dismissed."
        }
    }

    public var requiredRoles: [String] {
        switch self {
        case .revokeSessions, .blockSignIn, .unblockSignIn:
            return [UserActionRoles.globalAdministrator, UserActionRoles.userAdministrator, UserActionRoles.privilegedAuthenticationAdministrator]
        case .authenticationWipe, .issueTemporaryAccessPass:
            return [UserActionRoles.globalAdministrator, UserActionRoles.authenticationAdministrator, UserActionRoles.privilegedAuthenticationAdministrator]
        case .confirmCompromised, .dismissRisk:
            return [UserActionRoles.globalAdministrator, UserActionRoles.securityAdministrator]
        }
    }

    /// The write, as data. The authentication wipe is a sequence of these, built from the
    /// methods the person has; see `AuthenticationMethodRef`.
    public func action(for target: UserActionTarget) -> WriteAction? {
        let request: GraphRequest
        switch self {
        case .revokeSessions:
            request = GraphRequest(method: .post, path: "/users/" + target.userId + "/revokeSignInSessions",
                                   template: "/users/{id}/revokeSignInSessions", scopes: [UserActionScopes.revokeSessions])
        case .blockSignIn, .unblockSignIn:
            let body = try? JSONSerialization.data(withJSONObject: ["accountEnabled": self == .unblockSignIn])
            request = GraphRequest(method: .patch, path: "/users/" + target.userId, template: "/users/{id}",
                                   body: body, scopes: [UserActionScopes.enableDisable, UserActionScopes.userRead])
        case .confirmCompromised, .dismissRisk:
            let body = try? JSONSerialization.data(withJSONObject: ["userIds": [target.userId]])
            let verb = self == .confirmCompromised ? "confirmCompromised" : "dismiss"
            request = GraphRequest(method: .post, path: "/identityProtection/riskyUsers/" + verb,
                                   body: body, scopes: [UserActionScopes.riskyUsers])
        case .authenticationWipe, .issueTemporaryAccessPass:
            return marker(for: target)
        }
        return WriteAction(id: actionId, title: title, tier: tier,
                           target: ActionTarget(label: target.userPrincipalName, id: target.userId),
                           request: request, requiredRoleTemplateIds: requiredRoles, successCopy: successCopy)
    }

    /// For the two composite or off-gate actions: the identity the role check and the log
    /// line use, with a request that is never sent.
    public func marker(for target: UserActionTarget) -> WriteAction {
        WriteAction(id: actionId, title: title, tier: tier,
                    target: ActionTarget(label: target.userPrincipalName, id: target.userId),
                    request: GraphRequest(method: .post, path: "/users/{id}/" + rawValue, scopes: []),
                    requiredRoleTemplateIds: requiredRoles, successCopy: successCopy)
    }
}

/// One registered sign-in method, as much as the wipe needs: what it is and where to send
/// its DELETE. The password is listed by Graph and is never removed here.
public struct AuthenticationMethodRef: Sendable, Equatable, Identifiable {
    public let id: String
    public let odataType: String

    public init(id: String, odataType: String) {
        self.id = id
        self.odataType = odataType
    }

    var typeName: String {
        odataType.hasPrefix("#microsoft.graph.") ? String(odataType.dropFirst("#microsoft.graph.".count)) : odataType
    }

    /// The collection the DELETE goes to, or nil for anything that cannot be removed
    /// this way (the password, and any type Microsoft adds tomorrow).
    public var collection: String? {
        switch typeName {
        case "microsoftAuthenticatorAuthenticationMethod": return "microsoftAuthenticatorMethods"
        case "phoneAuthenticationMethod":                  return "phoneMethods"
        case "fido2AuthenticationMethod":                  return "fido2Methods"
        case "windowsHelloForBusinessAuthenticationMethod": return "windowsHelloForBusinessMethods"
        case "emailAuthenticationMethod":                  return "emailMethods"
        case "softwareOathAuthenticationMethod":           return "softwareOathMethods"
        case "temporaryAccessPassAuthenticationMethod":    return "temporaryAccessPassMethods"
        case "platformCredentialAuthenticationMethod":     return "platformCredentialMethods"
        case "externalAuthenticationMethod":               return "externalAuthenticationMethods"
        default:                                           return nil
        }
    }

    public var label: String {
        switch typeName {
        case "microsoftAuthenticatorAuthenticationMethod": return "Microsoft Authenticator"
        case "phoneAuthenticationMethod":                  return "Phone"
        case "fido2AuthenticationMethod":                  return "FIDO2 security key"
        case "windowsHelloForBusinessAuthenticationMethod": return "Windows Hello for Business"
        case "emailAuthenticationMethod":                  return "Email"
        case "softwareOathAuthenticationMethod":           return "OATH token"
        case "temporaryAccessPassAuthenticationMethod":    return "Temporary Access Pass"
        case "platformCredentialAuthenticationMethod":     return "Platform credential"
        case "externalAuthenticationMethod":               return "External MFA"
        case "passwordAuthenticationMethod":               return "Password"
        default:                                           return typeName
        }
    }

    public func deleteAction(for target: UserActionTarget) -> WriteAction? {
        guard let collection else { return nil }
        return WriteAction(
            id: "user.removeMethod",
            title: "Remove " + label,
            tier: .destructive,
            target: ActionTarget(label: target.userPrincipalName, id: target.userId),
            request: GraphRequest(method: .delete,
                                  path: "/users/" + target.userId + "/authentication/" + collection + "/" + id,
                                  template: "/users/{id}/authentication/" + collection + "/{methodId}",
                                  scopes: [UserActionScopes.authenticationMethods]),
            requiredRoleTemplateIds: UserActionKind.authenticationWipe.requiredRoles,
            successCopy: label + " removed.")
    }
}

/// Microsoft's documented claims for "this credential change needs fresh MFA", sent when a
/// method write answers 403. From the authentication methods overview, verified 2026-10-26.
public enum UserActionClaims {
    public static let freshMFA = #"{"access_token":{"amr":{"essential":true,"values":["ngcmfa"]}}}"#
}

/// The result of the wipe, method by method, so the screen can say what is left.
public struct AuthenticationWipeResult: Sendable, Equatable {
    public var removed: [String]
    public var kept: [String]
    public var failed: [String]
    public var outcome: ActionOutcome?

    public init(removed: [String] = [], kept: [String] = [], failed: [String] = [], outcome: ActionOutcome? = nil) {
        self.removed = removed
        self.kept = kept
        self.failed = failed
        self.outcome = outcome
    }
}

/// A device the person is the primary user of, for the leaver checklist.
public struct UserDevice: Sendable, Equatable, Identifiable, Decodable {
    public let id: String
    public let deviceName: String?
    public let operatingSystem: String?
    public let managedDeviceOwnerType: String?
    public let azureADDeviceId: String?

    public init(id: String, deviceName: String?, operatingSystem: String?, managedDeviceOwnerType: String?, azureADDeviceId: String?) {
        self.id = id
        self.deviceName = deviceName
        self.operatingSystem = operatingSystem
        self.managedDeviceOwnerType = managedDeviceOwnerType
        self.azureADDeviceId = azureADDeviceId
    }

    public var label: String { deviceName ?? id }

    /// The all-zeros id Intune uses for "none" counts as no Entra identity.
    public var hasEntraIdentity: Bool {
        guard let value = azureADDeviceId, !value.isEmpty else { return false }
        return value != "00000000-0000-0000-0000-000000000000"
    }
}

/// A person's state at a glance, for the top of their page in People. Every field is
/// optional: each comes from its own call, and one that fails or is not licensed (risk
/// needs P2) leaves its line out rather than the whole snapshot.
public struct PersonSnapshot: Sendable, Equatable {
    public var accountEnabled: Bool?
    /// Graph's riskLevel: none, low, medium, high, hidden. Nil when it could not be read.
    public var riskLevel: String?
    /// Registered methods other than the password.
    public var methodCount: Int?
    public var deviceCount: Int?

    public init(accountEnabled: Bool? = nil, riskLevel: String? = nil, methodCount: Int? = nil, deviceCount: Int? = nil) {
        self.accountEnabled = accountEnabled
        self.riskLevel = riskLevel
        self.methodCount = methodCount
        self.deviceCount = deviceCount
    }

    public var signInLine: String? {
        accountEnabled.map { $0 ? "Can sign in" : "Sign-in blocked" }
    }

    public var riskLine: String? {
        guard let level = riskLevel?.lowercased() else { return nil }
        switch level {
        case "none":   return "No user risk"
        case "hidden": return "Risk hidden from your role"
        default:       return "User risk " + level
        }
    }

    public var isRisky: Bool { ["low", "medium", "high"].contains(riskLevel?.lowercased() ?? "") }

    public var methodsLine: String? {
        methodCount.map { $0 == 0 ? "No sign-in methods besides the password" : ($0 == 1 ? "1 sign-in method" : String($0) + " sign-in methods") + " besides the password" }
    }

    public var devicesLine: String? {
        deviceCount.map { $0 == 0 ? "No devices" : ($0 == 1 ? "1 device" : String($0) + " devices") }
    }

    /// The password counts as no method: it is never removed by the authentication wipe.
    public static func countMethods(_ methods: [AuthenticationMethodRef]) -> Int {
        methods.filter { !$0.odataType.lowercased().hasSuffix("passwordauthenticationmethod") }.count
    }
}

/// The leaver checklist's steps, in order. Spec 8a and D8. Each runs the action it names
/// through its usual tier; the two that Graph cannot do as designed are links.
public enum LeaverStep: String, CaseIterable, Sendable, Identifiable {
    case blockSignIn
    case revokeSessions
    case removeMethods
    case devices
    case mailbox
    case privilegedAccess

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .blockSignIn:      return "Block sign-in"
        case .revokeSessions:   return "Revoke sessions"
        case .removeMethods:    return "Remove all sign-in methods"
        case .devices:          return "Retire or wipe their devices"
        case .mailbox:          return "Hand over the mailbox"
        case .privilegedAccess: return "Remove privileged access"
        }
    }

    public var detail: String {
        switch self {
        case .blockSignIn:      return "First, so nothing new starts while the rest runs."
        case .revokeSessions:   return "Ends what is already signed in."
        case .removeMethods:    return "Authenticator, phone, keys. The password stays, and sign-in is blocked anyway."
        case .devices:          return "Corporate devices can be wiped; personal ones retired."
        case .mailbox:          return "Converting to a shared mailbox or forwarding is done in the Exchange admin center; it is not in Microsoft Graph."
        case .privilegedAccess: return "PIM eligibility and group ownership are removed in the Entra admin center."
        }
    }

    /// The user action a step runs, when it is one.
    public var action: UserActionKind? {
        switch self {
        case .blockSignIn:    return .blockSignIn
        case .revokeSessions: return .revokeSessions
        case .removeMethods:  return .authenticationWipe
        default:              return nil
        }
    }

    public var portal: URL? {
        switch self {
        case .mailbox:          return URL(string: "https://admin.exchange.microsoft.com/#/mailboxes")
        case .privilegedAccess: return URL(string: "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart")
        default:                return nil
        }
    }
}

public enum LeaverStepStatus: Sendable, Equatable {
    case pending
    case done(String)
    case skipped
    case failed(String)

    public var word: String {
        switch self {
        case .pending:          return "not done"
        case .done:             return "done"
        case .skipped:          return "skipped"
        case .failed:           return "failed"
        }
    }
}

/// The text a leaver checklist leaves behind for the ticket: what was done, what was not,
/// and when. Never a credential; nothing in a step's status could hold one.
public enum LeaverSummary {
    public static func text(person: UserActionTarget, statuses: [(LeaverStep, LeaverStepStatus)], devices: [(String, String)], at: Date) -> String {
        let stamp: String = {
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX")
            f.timeZone = TimeZone(identifier: "UTC")
            f.dateFormat = "yyyy-MM-dd HH:mm'Z'"
            return f.string(from: at)
        }()
        var lines = ["Leaver checklist for " + person.label + " (" + person.userPrincipalName + ")", "Recorded " + stamp + " from TenantKeep On-Call", ""]
        for (step, status) in statuses {
            var line = "- " + step.title + ": " + status.word
            switch status {
            case .done(let detail) where !detail.isEmpty: line += " (" + detail + ")"
            case .failed(let detail): line += " (" + detail + ")"
            default: break
            }
            lines.append(line)
            if step == .devices {
                for (name, outcome) in devices { lines.append("    " + name + ": " + outcome) }
            }
        }
        lines.append("")
        lines.append("The tenant audit log is authoritative.")
        return lines.joined(separator: "\n")
    }
}

public protocol UserActionsProviding: Sendable {
    func run(_ kind: UserActionKind, on target: UserActionTarget) async -> ActionOutcome
    func resume(_ kind: UserActionKind, on target: UserActionTarget, satisfying challenge: ClaimsChallenge) async -> ActionOutcome
    func methods(of target: UserActionTarget) async throws -> [AuthenticationMethodRef]
    func authenticationWipe(_ target: UserActionTarget, satisfying challenge: ClaimsChallenge?) async -> AuthenticationWipeResult
    /// The role check for the TAP, which is issued elsewhere.
    func checkRoles(_ kind: UserActionKind, on target: UserActionTarget) async -> ActionOutcome?
    func logOffGate(_ kind: UserActionKind, on target: UserActionTarget, outcome: ActionOutcome) async
    func lastLogEntry(userId: String) async -> ShiftLogEntry?
    /// Devices the person is the primary user of.
    func devices(of target: UserActionTarget) async throws -> [UserDevice]
    /// Their state at a glance. Never throws: a part that fails is left out.
    func snapshot(of target: UserActionTarget) async -> PersonSnapshot
}

public actor UserActionsService: UserActionsProviding {

    private let graph: GraphClient
    private let runner: ActionRunner
    private let log: any ShiftLogging
    private let tenantId: @Sendable () async -> String

    public init(graph: GraphClient, runner: ActionRunner, log: any ShiftLogging, tenantId: @escaping @Sendable () async -> String) {
        self.graph = graph
        self.runner = runner
        self.log = log
        self.tenantId = tenantId
    }

    public func run(_ kind: UserActionKind, on target: UserActionTarget) async -> ActionOutcome {
        guard let action = kind.action(for: target), kind != .authenticationWipe, kind != .issueTemporaryAccessPass else {
            return .failed(.refused(reason: "That action has its own path."))
        }
        return await runner.run(action)
    }

    public func resume(_ kind: UserActionKind, on target: UserActionTarget, satisfying challenge: ClaimsChallenge) async -> ActionOutcome {
        guard let action = kind.action(for: target) else { return .failed(.refused(reason: "Nothing to resume.")) }
        return await runner.resume(action, satisfying: challenge)
    }

    struct MethodRecord: Decodable, Sendable {
        let id: String
        let odataType: String?
        enum CodingKeys: String, CodingKey {
            case id
            case odataType = "@odata.type"
        }
    }

    public func methods(of target: UserActionTarget) async throws -> [AuthenticationMethodRef] {
        let request = GraphRequest(path: "/users/" + target.userId + "/authentication/methods",
                                   template: "/users/{id}/authentication/methods",
                                   scopes: [UserActionScopes.authenticationMethods])
        let page = try await graph.collection(MethodRecord.self, from: request, maxPages: 2)
        return page.items.map { AuthenticationMethodRef(id: $0.id, odataType: $0.odataType ?? "") }
    }

    /// Lists the methods, then removes each one that can be removed, one DELETE each
    /// through the gate. A 403 on the first removal is Microsoft asking for fresh MFA:
    /// handed back as a challenge for the person's tap, never retried here.
    ///
    /// The role is checked once, before anything is listed, for the whole change, not again
    /// before every DELETE (OPTIMIZATION-PLAN.md, step G, DEV-8 b). Each DELETE is still
    /// sent once and logged, and the first refusal stops the rest.
    public func authenticationWipe(_ target: UserActionTarget, satisfying challenge: ClaimsChallenge?) async -> AuthenticationWipeResult {
        var result = AuthenticationWipeResult()
        if let gate = await runner.checkRoles(UserActionKind.authenticationWipe.marker(for: target)) {
            result.outcome = gate
            return result
        }
        let all: [AuthenticationMethodRef]
        do {
            all = try await methods(of: target)
        } catch {
            result.outcome = .failed(.transport(status: 0))
            return result
        }
        for method in all {
            guard let action = method.deleteAction(for: target) else {
                result.kept.append(method.label)
                continue
            }
            let outcome: ActionOutcome
            if let challenge { outcome = await runner.resume(action, satisfying: challenge) } else { outcome = await runner.run(action, checkingRoles: false) }
            switch outcome {
            case .requested:
                result.removed.append(method.label)
            case .notAuthorized where result.removed.isEmpty && challenge == nil:
                result.outcome = ClaimsChallenge(json: UserActionClaims.freshMFA).map { .challenged($0) } ?? outcome
                return result
            case .challenged, .needsActivation, .notAuthorized:
                result.outcome = outcome
                return result
            case .failed:
                result.failed.append(method.label)
            }
        }
        result.outcome = .requested(requestId: nil)
        return result
    }

    public func checkRoles(_ kind: UserActionKind, on target: UserActionTarget) async -> ActionOutcome? {
        await runner.checkRoles(kind.marker(for: target))
    }

    public func logOffGate(_ kind: UserActionKind, on target: UserActionTarget, outcome: ActionOutcome) async {
        await runner.log(kind.marker(for: target), outcome: outcome, requestId: nil)
    }

    public func lastLogEntry(userId: String) async -> ShiftLogEntry? {
        let tenant = await tenantId()
        return await log.entries(tenantId: tenant).first { $0.targetId == userId }
    }

    /// GET /users/{id}/managedDevices, on the device-read scope consented at sign-in.
    /// Intune answers 404 for a person it does not know, such as one with no Intune
    /// license, common for a leaver whose license went first: that is no devices.
    public func devices(of target: UserActionTarget) async throws -> [UserDevice] {
        let request = GraphRequest(path: "/users/" + target.userId + "/managedDevices",
                                   template: "/users/{id}/managedDevices",
                                   query: [URLQueryItem(name: "$select", value: "id,deviceName,operatingSystem,managedDeviceOwnerType,azureADDeviceId")],
                                   scopes: ["DeviceManagementManagedDevices.Read.All"])
        do {
            return try await graph.collection(UserDevice.self, from: request, maxPages: 2).items
        } catch GraphError.notFound {
            return []
        }
    }

    private struct AccountRecord: Decodable { let accountEnabled: Bool? }
    private struct RiskRecord: Decodable { let riskLevel: String? }

    /// Four reads in parallel, each on a scope the module already holds.
    public func snapshot(of target: UserActionTarget) async -> PersonSnapshot {
        async let enabled = accountEnabled(target)
        async let risk = riskLevel(target)
        async let methodList = try? methods(of: target)
        async let deviceList = try? devices(of: target)
        return PersonSnapshot(
            accountEnabled: await enabled,
            riskLevel: await risk,
            methodCount: await methodList.map(PersonSnapshot.countMethods),
            deviceCount: await deviceList?.count)
    }

    private func accountEnabled(_ target: UserActionTarget) async -> Bool? {
        let request = GraphRequest(path: "/users/" + target.userId,
                                   template: "/users/{id}",
                                   query: [URLQueryItem(name: "$select", value: "accountEnabled")],
                                   scopes: [UserActionScopes.userRead])
        return (try? await graph.decode(AccountRecord.self, from: request))?.accountEnabled
    }

    /// A person Identity Protection has never flagged has no riskyUser record: a 404 is
    /// "none". Any other failure, such as no P2, leaves the line out.
    private func riskLevel(_ target: UserActionTarget) async -> String? {
        let request = GraphRequest(path: "/identityProtection/riskyUsers/" + target.userId,
                                   template: "/identityProtection/riskyUsers/{id}",
                                   query: [URLQueryItem(name: "$select", value: "riskLevel")],
                                   scopes: [UserActionScopes.riskyUsers])
        do {
            return try await graph.decode(RiskRecord.self, from: request).riskLevel
        } catch GraphError.notFound {
            return "none"
        } catch {
            return nil
        }
    }
}

/// Demo: every action succeeds after a pause and lands in an in-memory log; the person has
/// four methods and a password, so the wipe shows both columns.
public actor DemoUserActionsProvider: UserActionsProviding {

    private let latency: Duration
    private let log = InMemoryShiftLog()
    public static let tenant = "demo"

    public init(latency: Duration = .seconds(1)) {
        self.latency = latency
    }

    private var blocked: Set<String> = []

    public func run(_ kind: UserActionKind, on target: UserActionTarget) async -> ActionOutcome {
        try? await Task.sleep(for: latency)
        await record(kind.title, target)
        if kind == .blockSignIn { blocked.insert(target.userId) }
        if kind == .unblockSignIn { blocked.remove(target.userId) }
        return .requested(requestId: "demo")
    }

    public func snapshot(of target: UserActionTarget) async -> PersonSnapshot {
        try? await Task.sleep(for: .milliseconds(300))
        return PersonSnapshot(accountEnabled: !blocked.contains(target.userId), riskLevel: "medium",
                              methodCount: PersonSnapshot.countMethods(Self.demoMethods), deviceCount: 2)
    }

    public func resume(_ kind: UserActionKind, on target: UserActionTarget, satisfying challenge: ClaimsChallenge) async -> ActionOutcome {
        await run(kind, on: target)
    }

    public static let demoMethods = [
        AuthenticationMethodRef(id: "m1", odataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"),
        AuthenticationMethodRef(id: "m2", odataType: "#microsoft.graph.phoneAuthenticationMethod"),
        AuthenticationMethodRef(id: "m3", odataType: "#microsoft.graph.fido2AuthenticationMethod"),
        AuthenticationMethodRef(id: "m4", odataType: "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"),
        AuthenticationMethodRef(id: "pw", odataType: "#microsoft.graph.passwordAuthenticationMethod")
    ]

    public func methods(of target: UserActionTarget) async throws -> [AuthenticationMethodRef] {
        try? await Task.sleep(for: .milliseconds(300))
        return Self.demoMethods
    }

    public func authenticationWipe(_ target: UserActionTarget, satisfying challenge: ClaimsChallenge?) async -> AuthenticationWipeResult {
        try? await Task.sleep(for: latency)
        var result = AuthenticationWipeResult()
        for method in Self.demoMethods {
            if method.collection == nil { result.kept.append(method.label) } else { result.removed.append(method.label) }
        }
        result.outcome = .requested(requestId: "demo")
        await record(UserActionKind.authenticationWipe.title, target)
        return result
    }

    public func checkRoles(_ kind: UserActionKind, on target: UserActionTarget) async -> ActionOutcome? { nil }

    public func logOffGate(_ kind: UserActionKind, on target: UserActionTarget, outcome: ActionOutcome) async {
        await record(kind.title, target)
    }

    public func lastLogEntry(userId: String) async -> ShiftLogEntry? {
        await log.entries(tenantId: Self.tenant).first { $0.targetId == userId }
    }

    private func record(_ title: String, _ target: UserActionTarget) async {
        await log.append(ShiftLogEntry(at: Date(), tenantId: Self.tenant, actionId: "user", actionTitle: title,
                                       targetLabel: target.userPrincipalName, targetId: target.userId,
                                       outcome: "requested", requestId: "demo"))
    }

    public func devices(of target: UserActionTarget) async throws -> [UserDevice] {
        try? await Task.sleep(for: .milliseconds(300))
        return [
            UserDevice(id: "demo-w-003", deviceName: "LT-FIELD-207", operatingSystem: "Windows", managedDeviceOwnerType: "company", azureADDeviceId: "demo-entra-003"),
            UserDevice(id: "demo-w-008", deviceName: "WS-ENG-041", operatingSystem: "Windows", managedDeviceOwnerType: "personal", azureADDeviceId: "demo-entra-008")
        ]
    }

    public var shiftLog: any ShiftLogging { log }
}
