import SwiftUI

// TenantKeep On-Call for Apple Watch, phase 4 step B, spec 3.13. A remote for the phone:
// it shows what the phone sends and asks the phone to act. It never holds a token and
// never shows a credential; see WatchBridgeKit.

@main
struct OnCallWatchApp: App {
    /// Built once: an App is created once, so `@State` holds the model for the app's life.
    @State private var model = WatchModel()

    var body: some Scene {
        WindowGroup {
            WatchHomeView(model: model)
        }
        .backgroundTask(.watchConnectivity) {
            await model.finishPendingTransfers()
        }
    }
}
