import SwiftUI

// TenantKeep On-Call for Apple Watch, phase 4 step B, spec 3.13. A remote for the phone:
// it shows what the phone sends and asks the phone to act. It never holds a token and
// never shows a credential; see WatchBridgeKit.

@main
struct OnCallWatchApp: App {
    @StateObject private var model = WatchModel()

    var body: some Scene {
        WindowGroup {
            WatchHomeView(model: model)
        }
    }
}
