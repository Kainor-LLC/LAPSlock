import Foundation
import AuthKit
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
    /// Intune answered and no policy is targeted at this person.
    case notTargeted
    /// Intune answered that this person has no Intune licence, so no policy can apply.
    case notLicensed
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

    /// Called when Intune orders this account's data removed (a selective wipe). Returns
    /// whether everything went.
    var wipe: (@Sendable (_ objectId: String) async -> Bool)? {
        get { bridge.wipe.value }
        set { bridge.wipe.value = newValue }
    }

    /// Everything the app wrote outside the Keychain: its Application Support and Caches
    /// folders, its temporary files, what it shares with the notification extension and the
    /// watch, and its settings. Microsoft's SDK keeps its own state elsewhere, in
    /// Library/.IntuneMAM and its Keychain group, and its settings are left alone.
    nonisolated static func eraseFilesAndSettings() -> Bool {
        let files = FileManager.default
        let group = "group.com.kainor.lapslock"
        var complete = true
        var doomed: [URL] = []
        for folder in [FileManager.SearchPathDirectory.applicationSupportDirectory, .cachesDirectory] {
            guard let url = files.urls(for: folder, in: .userDomainMask).first else { continue }
            doomed += (try? files.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? []
        }
        doomed += (try? files.contentsOfDirectory(at: files.temporaryDirectory, includingPropertiesForKeys: nil)) ?? []
        if let shared = files.containerURL(forSecurityApplicationGroupIdentifier: group) {
            // The system keeps the group's settings under Library; those go by name below.
            doomed += ((try? files.contentsOfDirectory(at: shared, includingPropertiesForKeys: nil)) ?? [])
                .filter { $0.lastPathComponent != "Library" }
        }
        for url in doomed {
            do { try files.removeItem(at: url) } catch { complete = false }
        }
        URLCache.shared.removeAllCachedResponses()
        for defaults in [UserDefaults.standard, UserDefaults(suiteName: group)].compactMap({ $0 }) {
            let domain = defaults === UserDefaults.standard ? (Bundle.main.bundleIdentifier ?? "") : group
            for key in (defaults.persistentDomain(forName: domain) ?? [:]).keys where !Self.isMicrosofts(key) {
                defaults.removeObject(forKey: key)
            }
        }
        return complete
    }

    /// A settings key Microsoft's SDK may have written. The app writes none like it.
    nonisolated static func isMicrosofts(_ key: String) -> Bool {
        let lowered = key.lowercased()
        return lowered.hasPrefix("com.microsoft.") || lowered.contains("intune") || lowered.hasPrefix("mam")
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

    /// Once the person has a sign-in on the App Protection registration. Asks Intune
    /// whether a policy is targeted at them.
    func signedIn(objectId: String) {
        let manager = IntuneMAMEnrollmentManager.instance()
        if Self.holds(manager.enrolledAccountIds(), objectId) {
            // Intune already answered for this person; the SDK refreshes that by itself.
            state = isManaged(objectId: objectId) ? .managed : .notTargeted
            return
        }
        state = .checking
        if Self.holds(manager.registeredAccountIds(), objectId) {
            // Known but never enrolled: the SDK would try again once a day. Start over, so
            // the token it could not get last time is asked for now.
            manager.deRegisterAndUnenrollAccountId(objectId, withWipe: false)
        }
        manager.registerAndEnrollAccountId(objectId)
    }

    /// Signed in, with no sign-in on the App Protection registration. Intune is not asked.
    func notSignedIn() {
        state = .needsSignIn
    }

    /// Before the account's tokens are deleted: the SDK needs one to tell Intune.
    /// The app removes its own data at sign-out, so the SDK is not asked to.
    ///
    /// Microsoft documents the call as blocking until its token arrives. Sign-out must not
    /// wait on Microsoft, so it is given ten seconds and then sign-out carries on.
    func signingOut(objectId: String) async {
        defer { state = .idle }
        guard Self.holds(IntuneMAMEnrollmentManager.instance().registeredAccountIds(), objectId) else { return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let finished = Locked(false)
            let finish: @Sendable () -> Void = {
                if !finished.swap(true) { continuation.resume() }
            }
            Task.detached(priority: .userInitiated) {
                IntuneMAMEnrollmentManager.instance().deRegisterAndUnenrollAccountId(objectId, withWipe: false)
                finish()
            }
            Task.detached {
                try? await Task.sleep(for: .seconds(10))
                finish()
            }
        }
    }

    private static func holds(_ accounts: [Any], _ objectId: String) -> Bool {
        accounts.contains { ($0 as? String)?.caseInsensitiveCompare(objectId) == .orderedSame }
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
    /// Stores `new` and returns what was there, as one step.
    func swap(_ new: Value) -> Value {
        lock.lock(); defer { lock.unlock() }
        let old = stored
        stored = new
        return old
    }
}

/// The object the SDK calls. Not on the main actor: Microsoft calls these from whichever
/// thread it is on, `restartApplication` from a background one.
private nonisolated final class Bridge: NSObject, IntuneMAMEnrollmentDelegate, IntuneMAMPolicyDelegate, @unchecked Sendable {
    let tokenSource = Locked<AppProtectionTokenSource?>(nil)
    let wipe = Locked<(@Sendable (String) async -> Bool)?>(nil)
    var report: (@Sendable (AppProtectionState) -> Void)?

    // MARK: Tokens

    func getAccessToken(forAccountId oid: String, resource: String, completion: @escaping (IntuneMAMEnrollmentToken) -> Void) {
        let source = tokenSource.value
        nonisolated(unsafe) let completion = completion
        Task.detached {
            let answer = IntuneMAMEnrollmentToken()
            let token = await source?(oid, resource)
            Self.trace("token asked for " + resource + ": " + (token == nil ? "none to give" : "given"))
            if let token {
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
        Self.trace("enrolment", status)
        report?(Self.state(for: status))
    }

    func policyRequest(with status: IntuneMAMEnrollmentStatus) {
        Self.trace("policy", status)
        // A refresh that changed nothing says nothing new about whether a policy is in force.
        guard status.statusCode != .policiesHaveNotChanged else { return }
        report?(Self.state(for: status))
    }

    func unenrollRequest(with status: IntuneMAMEnrollmentStatus) {
        Self.trace("unenrolment", status)
        // Only a real unenrolment changes anything. "Was not enrolled" is also reported
        // here, when an account that never enrolled is started over.
        if status.didSucceed { report?(.idle) }
    }

    /// Debug builds only, like the MSAL log: Microsoft's status number and its own words,
    /// which name the account, so never in a build anyone else runs.
    static func trace(_ what: String, _ status: IntuneMAMEnrollmentStatus? = nil) {
        #if DEBUG
        if let status {
            print("[AppProtection] " + what + ": status \(status.statusCode.rawValue), succeeded \(status.didSucceed), " + (status.errorString ?? "no detail"))
        } else {
            print("[AppProtection] " + what)
        }
        #endif
    }

    static func state(for status: IntuneMAMEnrollmentStatus) -> AppProtectionState {
        switch status.statusCode {
        case .newPoliciesReceived, .policiesHaveNotChanged, .alreadyEnrolled:
            return IntuneMAMPolicyManager.instance().isAccountIdManaged(status.accountId) ? .managed : .notTargeted
        case .noPolicyReceived, .licensedNotTargeted:
            return .notTargeted
        case .accountNotLicensed, .tenantMigration:
            // Microsoft uses the second for a tenant that is moving and for a missing licence.
            return .notLicensed
        case .authRequired:
            return .needsSignIn
        case .unenrollmentSuccess, .wipeReceived:
            return .idle
        default:
            return .failed(code: Int(status.statusCode.rawValue))
        }
    }

    // MARK: Orders From Intune

    /// The organization ordered this account's data removed from the app.
    ///
    /// Microsoft calls this from a background thread and wants no answer until the data is
    /// gone, so this thread waits while the app does it. A minute at most: the one step that
    /// can be slow is telling Kainor's alert service the phone has left, and that gives up
    /// by itself. An answer of false makes the SDK delete the app's files itself.
    func wipeData(forAccountId accountId: String) -> Bool {
        Self.trace("wipe ordered")
        guard let wipe = wipe.value else { return false }
        guard !Thread.isMainThread else {
            // Never seen, and waiting here for work the main thread must do would hang the
            // app. The data still goes; the SDK is told to remove the files as well.
            Task.detached { _ = await wipe(accountId) }
            return false
        }
        let finished = DispatchSemaphore(value: 0)
        let complete = Locked(false)
        Task.detached {
            complete.value = await wipe(accountId)
            finished.signal()
        }
        let done = finished.wait(timeout: .now() + 60) == .success && complete.value
        Self.trace(done ? "wipe complete" : "wipe incomplete")
        return done
    }

    /// The first policy needs a fresh process. False: the SDK says so and closes the app.
    func restartApplication() -> Bool {
        false
    }
}
