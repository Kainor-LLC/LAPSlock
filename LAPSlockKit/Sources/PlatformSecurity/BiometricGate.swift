import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

// Build Spec §6, the biometric gate that must pass BEFORE any password is fetched.
//
// DESIGN: the decision logic is separated from LAContext so it can be unit tested with
// no device, no simulator prompt, and no user interaction. `BiometricGateOutcome` and
// `BiometricAvailability` are pure values; only `BiometricGate` touches the framework.
//
// Policy: `.deviceOwnerAuthentication`, not `.deviceOwnerAuthenticationWithBiometrics`.
// The former falls back to the device passcode when Face ID fails or isn't enrolled.
// Rationale: an admin standing in a server room with a mask on, or holding a device whose
// Face ID is temporarily locked out, still needs to get the password. Refusing entirely
// would push them to a less safe workaround (reading it off the portal on a desktop, or
// writing it down). Passcode is still an authenticator the device owner controls.

/// What the device can currently do, for UI copy purposes.
public enum BiometricAvailability: Sendable, Equatable {
    /// Face ID or Touch ID is enrolled and usable.
    case biometricsAvailable(kind: BiometricKind)
    /// No biometrics enrolled, but a device passcode is set, gate still works.
    case passcodeOnly
    /// No biometrics AND no passcode. The device has no owner authentication at all.
    case noneConfigured
    /// Biometrics are locked out after too many failed attempts; passcode can unlock.
    case biometricsLockedOut

    /// True when the gate can run at all. `noneConfigured` is the only blocking case.
    public var canAuthenticate: Bool {
        self != .noneConfigured
    }
}

public enum BiometricKind: String, Sendable, Equatable {
    case faceID = "Face ID"
    case touchID = "Touch ID"
    case unknown = "biometric authentication"
}

/// What a confirmation is for, so the system prompt can say so. Names are optional; a
/// missing or empty one is left out of the sentence.
public enum BiometricPurpose: Sendable, Equatable {
    case revealPassword(device: String?)
    case revealRecoveryKey(device: String?)
    case openApp
    /// A device write, by the title it was confirmed under, such as "Retire".
    case deviceAction(title: String, device: String?)
    /// A write to a person's account, by its title, such as "Remove all sign-in methods".
    case userAction(title: String, person: String?)
    case issueTemporaryAccessPass(person: String?)
    case groupChange(adding: Bool, member: String?, group: String?)
    case approval(approve: Bool, requester: String?)
}

/// Result of an authentication attempt.
public enum BiometricGateOutcome: Sendable, Equatable {
    case authenticated
    /// User tapped cancel, or backgrounded the app mid-prompt. Not an error to report loudly.
    case cancelledByUser
    /// User chose to enter a password/passcode instead and that path was dismissed.
    case fallbackDismissed
    /// Authentication ran and failed (wrong face, wrong passcode).
    case failed
    /// Cannot authenticate at all, the device has no passcode or biometrics.
    case unavailable(reason: String)
}

/// Pure mapping from a LocalAuthentication error code to an outcome.
/// Extracted so the mapping is testable without triggering a real prompt.
public enum BiometricPolicy {

    /// Copy shown when the device has no owner authentication configured.
    public static let noAuthConfiguredMessage =
        "This device has no passcode or biometric lock. TenantKeep won't display a local "
        + "administrator password on an unprotected device. Add a passcode in Settings to continue."

    /// The reason string shown in the system prompt. Keep it specific: a vague prompt
    /// ("Authenticate") makes people wonder what they are approving, and a wrong one (every
    /// prompt once spoke of a password, the app lock's included) teaches them not to read it.
    public static func promptReason(for purpose: BiometricPurpose) -> String {
        switch purpose {
        case .revealPassword(let device):
            return "Confirm it's you to reveal the local administrator password" + named(" for ", device) + "."
        case .revealRecoveryKey(let device):
            return "Confirm it's you to reveal a BitLocker recovery key" + named(" for ", device) + "."
        case .openApp:
            return "Confirm it's you to open TenantKeep."
        case .deviceAction(let title, let device):
            return "Confirm it's you to send " + title + named(" to ", device) + "."
        case .userAction(let title, let person):
            return "Confirm it's you to send " + title + named(" for ", person) + "."
        case .issueTemporaryAccessPass(let person):
            return "Confirm it's you to issue a Temporary Access Pass" + named(" for ", person) + "."
        case .groupChange(let adding, let member, let group):
            let who = nonEmpty(member) ?? "this person"
            return adding
                ? "Confirm it's you to add " + who + named(" to ", group) + "."
                : "Confirm it's you to remove " + who + named(" from ", group) + "."
        case .approval(let approve, let requester):
            return "Confirm it's you to " + (approve ? "approve" : "deny") + " the request" + named(" from ", requester) + "."
        }
    }

    private static func nonEmpty(_ name: String?) -> String? {
        guard let name = name?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty else { return nil }
        return name
    }

    private static func named(_ joiner: String, _ name: String?) -> String {
        nonEmpty(name).map { joiner + $0 } ?? ""
    }

    #if canImport(LocalAuthentication)
    /// Maps an LAError code onto an outcome.
    public static func outcome(forLAErrorCode code: Int) -> BiometricGateOutcome {
        switch code {
        case LAError.userCancel.rawValue,
             LAError.appCancel.rawValue,
             LAError.systemCancel.rawValue:
            return .cancelledByUser
        case LAError.userFallback.rawValue:
            return .fallbackDismissed
        case LAError.authenticationFailed.rawValue:
            return .failed
        case LAError.passcodeNotSet.rawValue:
            return .unavailable(reason: noAuthConfiguredMessage)
        case LAError.biometryNotAvailable.rawValue,
             LAError.biometryNotEnrolled.rawValue:
            // Not fatal: .deviceOwnerAuthentication still offers passcode. If we land
            // here it means passcode is unavailable too.
            return .unavailable(reason: noAuthConfiguredMessage)
        case LAError.biometryLockout.rawValue:
            // Passcode entry unlocks biometrics; the system prompt handles that itself.
            return .failed
        default:
            return .failed
        }
    }
    #endif
}

#if canImport(LocalAuthentication)

/// Wraps LAContext. One instance per authentication attempt, LAContext is not designed
/// to be reused across evaluations, and reuse can silently return a cached success.
public struct BiometricGate: Sendable {

    public init() {}

    /// Inspects the device's current capability without prompting.
    public func availability() -> BiometricAvailability {
        let context = LAContext()
        var error: NSError?

        // Ask about the strict biometric policy first, to learn the biometry kind.
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return .biometricsAvailable(kind: Self.kind(from: context))
        }

        if let code = error?.code {
            if code == LAError.biometryLockout.rawValue {
                return .biometricsLockedOut
            }
            // Biometry missing or unenrolled: fall through to check passcode.
        }

        var passcodeError: NSError?
        let passcodeContext = LAContext()
        if passcodeContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &passcodeError) {
            return .passcodeOnly
        }

        return .noneConfigured
    }

    /// Runs the gate. MUST be called and must return `.authenticated` before any
    /// credential fetch (§6 step 2). This type performs no network work of its own,
    /// so the ordering is the caller's contract.
    public func authenticate(for purpose: BiometricPurpose) async -> BiometricGateOutcome {
        let context = LAContext()
        // Deliberately NOT setting localizedFallbackTitle to "", an empty string hides
        // the passcode fallback, which would strand a locked-out admin.
        context.localizedFallbackTitle = "Use Passcode"

        var canEvaluateError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &canEvaluateError) else {
            let code = canEvaluateError?.code ?? LAError.passcodeNotSet.rawValue
            return BiometricPolicy.outcome(forLAErrorCode: code)
        }

        do {
            let ok = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: BiometricPolicy.promptReason(for: purpose)
            )
            return ok ? .authenticated : .failed
        } catch {
            let code = (error as NSError).code
            return BiometricPolicy.outcome(forLAErrorCode: code)
        }
    }

    /// Only the two kinds an iPhone can have. Optic ID (Vision Pro) is deliberately not
    /// detected: this is an iPhone app, and the availability dance it required added
    /// complexity for a platform we don't ship to.
    private static func kind(from context: LAContext) -> BiometricKind {
        switch context.biometryType {
        case .faceID: return .faceID
        case .touchID: return .touchID
        default: return .unknown
        }
    }
}

#endif
