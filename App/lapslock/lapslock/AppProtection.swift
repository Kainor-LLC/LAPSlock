import Foundation
import IntuneMAMSwift

// Intune App Protection.
//
// The one file that touches Microsoft's Intune App SDK, the only closed-source component in
// the app. The SDK is linked to the app target and nothing else: LAPSlockKit does not depend
// on it, so no module in the package can import it, and CredentialKit least of all.
//
// What that does not give: the SDK runs in the app's process. When an organization's policy
// is in force it hooks the pasteboard, files, the Keychain and the network for the whole
// app, credentials screen included, and there is no source to read. That is the trade an
// organization asks for when it targets the app with a policy, and it is said in the README.
//
// What happens with no policy: no hooks. The SDK still fetches its own feature settings from
// Microsoft at launch and keeps a few items of its own in the Keychain group
// com.microsoft.intune.mam. docs/NETWORK-TRANSPARENCY.md lists the host.
//
// The SDK never signs in. It asks this file for a token (`getAccessToken`), and the token
// comes from the app's own sign-in manager through the TenantKeep App Protection
// registration, which holds that one permission and nothing on Microsoft Graph. With no
// token to give, the SDK is told so and enrols nobody.

/// What the app shows about protection for the signed-in account.
enum AppProtectionState: Equatable, Sendable {
    /// Nothing has been asked of Intune for this account.
    case idle
    /// Asked, no answer yet.
    case checking
    /// A policy from the organization is in force.
    case managed
    /// Intune answered and no policy is targeted at this person, or they have no licence.
    case notTargeted
    /// The TenantKeep App Protection registration has no sign-in to use.
    case needsSignIn
    /// Anything else, with Microsoft's status number for a support report.
    case failed(code: Int)
}

/// Gives the SDK a token for Microsoft's Mobile Application Management service, or nil.
typealias AppProtectionTokenSource = @Sendable (_ objectId: String, _ resource: String) async -> AppProtectionToken?

struct AppProtectionToken: Sendable {
    let accessToken: String
    let username: String
    let objectId: String
    let tenantId: String
}

@MainActor
@Observable
final class AppProtection {
    static let shared = AppProtection()

    private(set) var state: AppProtectionState = .idle

    /// Set once the app has a sign-in manager. Until then every request is answered "none".
    var tokenSource: AppProtectionTokenSource? {
        get { bridge.tokenSource.value }
        set { bridge.tokenSource.value = newValue }
    }

    /// Called when Intune orders this account's data removed. Returns whether it all went.
    var wipe: (@Sendable (_ objectId: String) -> Bool)? {
        get { bridge.wipe.value }
        set { bridge.wipe.value = newValue }
    }

    private let bridge = Bridge()

    private init() {}

    /// Before `willFinishLaunching` returns: the SDK reads its policy delegate there.
    func start() {
        bridge.report = { [weak self] state in
            Task { @MainActor [weak self] in self?.state = state }
        }
        IntuneMAMEnrollmentManager.instance().delegate = bridge
        IntuneMAMPolicyManager.instance().delegate = bridge
    }

    /// The object ID Intune holds a policy for on this device, if any.
    var enrolledObjectId: String? {
        IntuneMAMEnrollmentManager.instance().enrolledAccountId()
    }

    /// Whether a policy is in force for this account right now.
    func isManaged(objectId: String) -> Bool {
        IntuneMAMPolicyManager.instance().isAccountIdManaged(objectId)
    }

    /// After sign-in, and after a restored session. Asks Intune whether a policy is targeted
    /// at this person. Safe to call again: the SDK ignores an account it already knows.
    func signedIn(objectId: String) {
        if isManaged(objectId: objectId) {
            state = .managed
        } else {
            state = .checking
        }
        IntuneMAMEnrollmentManager.instance().registerAndEnrollAccountId(objectId)
    }

    /// Before the account's tokens are deleted: the SDK needs one to tell Intune.
    /// The app removes its own data at sign-out, so the SDK is not asked to.
    func signingOut(objectId: String) async {
        let manager = IntuneMAMEnrollmentManager.instance()
        guard (manager.registeredAccountIds() as? [String] ?? []).contains(where: { $0.caseInsensitiveCompare(objectId) == .orderedSame }) else {
            state = .idle
            return
        }
        // Microsoft documents this call as blocking until its token arrives.
        await Task.detached(priority: .userInitiated) {
            manager.deRegisterAndUnenrollAccountId(objectId, withWipe: false)
        }.value
        state = .idle
    }
}

/// Holds one value another thread may read.
private nonisolated final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value
    init(_ value: Value) { stored = value }
    var value: Value {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); defer { lock.unlock() }; stored = newValue }
    }
}

/// The object the SDK calls. Not on the main actor: Microsoft calls these from whichever
/// thread it is on, `restartApplication` from a background one.
private nonisolated final class Bridge: NSObject, IntuneMAMEnrollmentDelegate, IntuneMAMPolicyDelegate, @unchecked Sendable {
    let tokenSource = Locked<AppProtectionTokenSource?>(nil)
    let wipe = Locked<(@Sendable (String) -> Bool)?>(nil)
    var report: (@Sendable (AppProtectionState) -> Void)?

    // MARK: Tokens

    func getAccessToken(forAccountId oid: String, resource: String, completion: @escaping (IntuneMAMEnrollmentToken) -> Void) {
        let source = tokenSource.value
        nonisolated(unsafe) let completion = completion
        Task.detached {
            let answer = IntuneMAMEnrollmentToken()
            if let token = await source?(oid, resource) {
                answer.accessToken = token.accessToken
                answer.upn = token.username
                answer.oid = token.objectId
                answer.tenantId = token.tenantId
            } else {
                answer.error = NSError(domain: "com.kainor.lapslock.appProtection", code: 1, userInfo: [
                    NSLocalizedDescriptionKey: "No sign-in for the TenantKeep App Protection registration."
                ])
            }
            completion(answer)
        }
    }

    // MARK: Outcomes

    func enrollmentRequest(with status: IntuneMAMEnrollmentStatus) {
        report?(Self.state(for: status))
    }

    func policyRequest(with status: IntuneMAMEnrollmentStatus) {
        // A refresh that changed nothing says nothing new about whether a policy is in force.
        guard status.statusCode != .policiesHaveNotChanged else { return }
        report?(Self.state(for: status))
    }

    func unenrollRequest(with status: IntuneMAMEnrollmentStatus) {
        report?(.idle)
    }

    static func state(for status: IntuneMAMEnrollmentStatus) -> AppProtectionState {
        switch status.statusCode {
        case .newPoliciesReceived, .policiesHaveNotChanged, .alreadyEnrolled:
            return IntuneMAMPolicyManager.instance().isAccountIdManaged(status.accountId) ? .managed : .notTargeted
        case .noPolicyReceived, .licensedNotTargeted, .accountNotLicensed, .tenantMigration:
            return .notTargeted
        case .authRequired:
            return .needsSignIn
        case .unenrollmentSuccess, .wipeReceived:
            return .idle
        default:
            return .failed(code: Int(status.statusCode.rawValue))
        }
    }

    // MARK: Orders From Intune

    /// The organization removed this account's access to the app's data.
    func wipeData(forAccountId accountId: String) -> Bool {
        wipe.value?(accountId) ?? false
    }

    /// The first policy needs a fresh process. False: the SDK says so and closes the app.
    func restartApplication() -> Bool {
        false
    }
}
