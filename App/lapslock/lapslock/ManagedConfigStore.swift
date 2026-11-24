import Foundation
import Combine
import Observation
import ManagedConfigKit

// The organization's settings, kept current. For an enrolled device iOS writes the managed
// dictionary into the app's defaults and posts a change when Intune pushes a new policy.
// For a phone that is not enrolled the same keys arrive through Intune's app channel once
// an app protection policy applies, and AppProtection writes them into the defaults too. So
// the store re-reads on every defaults change and publishes only real changes.

@MainActor
@Observable
final class ManagedConfigStore {
    static let shared = ManagedConfigStore()

    private(set) var config: ManagedConfiguration

    @ObservationIgnored private var cancellable: AnyCancellable?

    private init() {
        config = Self.read()
        cancellable = NotificationCenter.default.publisher(for: UserDefaults.didChangeNotification)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self else { return }
                let fresh = Self.read()
                if fresh != self.config { self.config = fresh }
            }
    }

    /// Readable off the main actor too, for the background notification run.
    nonisolated static func read() -> ManagedConfiguration {
        ManagedConfiguration.parse(
            device: UserDefaults.standard.dictionary(forKey: ManagedConfiguration.userDefaultsKey),
            appChannel: UserDefaults.standard.dictionary(forKey: ManagedConfiguration.appChannelDefaultsKey))
    }
}
