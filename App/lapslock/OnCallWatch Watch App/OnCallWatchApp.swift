import SwiftUI
import WatchBridgeKit

// TenantKeep On-Call for Apple Watch, phase 4 step B, spec 3.13. A remote for the phone:
// it shows what the phone sends and asks the phone to act. It never holds a token and
// never shows a credential; see WatchBridgeKit.

@main
struct OnCallWatchApp: App {
    /// Built once: an App is created once, so `@State` holds the model for the app's life.
    @State private var model = WatchModel()

    var body: some Scene {
        WindowGroup {
            #if DEBUG
            WatchScreenshotRoot(model: model)
            #else
            WatchHomeView(model: model)
            #endif
        }
        .backgroundTask(.watchConnectivity) {
            await model.finishPendingTransfers()
        }
    }
}

#if DEBUG
/// Debug builds only: with -LAPSlockDemo, `-LAPSlockShot approval` or `activate` opens that
/// screen on the demo glance, for the scripted App Store screenshots. Otherwise this is
/// the home view, unchanged.
private struct WatchScreenshotRoot: View {
    let model: WatchModel

    private var shot: String? {
        let args = CommandLine.arguments
        guard args.contains("-LAPSlockDemo"), let i = args.firstIndex(of: "-LAPSlockShot"), i + 1 < args.count else { return nil }
        return args[i + 1]
    }

    var body: some View {
        if shot == "approval", let approval = model.glance?.approvals.first {
            NavigationStack { WatchApprovalView(model: model, approval: approval) }
        } else if shot == "activate", let eligible = model.glance?.eligible, !eligible.isEmpty {
            NavigationStack { WatchActivateListView(model: model, eligible: eligible) }
        } else {
            WatchHomeView(model: model)
        }
    }
}
#endif
