import Foundation

/// How this device confirms it's you, for the app's own words and icons. The system
/// prompt names its method itself; the app's copy has to agree with it, and on Touch ID
/// hardware or a passcode-only device "Face ID" was wrong.
public enum ConfirmMethod: Sendable, Equatable {
    case faceID
    case touchID
    /// No usable biometrics, or locked out: the system asks for the passcode.
    case passcode

    public init(_ availability: BiometricAvailability) {
        switch availability {
        case .biometricsAvailable(kind: .faceID): self = .faceID
        case .biometricsAvailable(kind: .touchID): self = .touchID
        default: self = .passcode
        }
    }

    /// For the middle of a sentence: "Then Face ID, then…", "Require your passcode to…".
    public var name: String {
        switch self {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .passcode: return "your passcode"
        }
    }

    /// For the start of a sentence.
    public var title: String {
        switch self {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .passcode: return "Your passcode"
        }
    }

    /// An SF Symbol for it.
    public var symbol: String {
        switch self {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        case .passcode: return "lock"
        }
    }
}
