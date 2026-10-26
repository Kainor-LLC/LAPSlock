import Foundation
import Combine
import ManagedConfigKit

// The organization's settings, as iOS hands them over, kept current. iOS writes the
// managed dictionary into the app's defaults and posts a change when Intune pushes a new
// policy, so the store re-reads on every defaults change and publishes only real changes.

@MainActor
final class ManagedConfigStore: ObservableObject {
    static let shared = ManagedConfigStore()

    @Published private(set) var config: ManagedConfiguration

    private var cancellable: AnyCancellable?

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
        ManagedConfiguration.parse(UserDefaults.standard.dictionary(forKey: ManagedConfiguration.userDefaultsKey))
    }
}
