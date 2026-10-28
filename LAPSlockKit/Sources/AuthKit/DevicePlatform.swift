import Foundation

/// A managed device's platform, as far as this app tells them apart. Here rather than in
/// CredentialKit so the inventory can name a platform without linking the module that
/// holds credentials: the Mac menu bar app shows the inventory and must not contain the
/// code that reads a password (OPTIMIZATION-PLAN.md, step J, decision 6).
public enum DevicePlatform: String, Sendable, CaseIterable {
    case windows
    case macOS
    case other

    /// Maps the Intune `operatingSystem` string onto a platform.
    public init(intuneOperatingSystem raw: String?) {
        switch (raw ?? "").lowercased() {
        case let s where s.contains("windows"): self = .windows
        case let s where s.contains("macos"), let s where s.contains("mac os"): self = .macOS
        default: self = .other
        }
    }
}
