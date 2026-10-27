import SwiftUI
import InventoryKit

// TenantKeep On-Call for Mac, phase 4 step C. A native macOS app from the same kits as the
// iPhone and iPad app, sold under the same App Store record (universal purchase). Menu bar
// first: who you are signed in as and whether the session is good, device lookup, PIM
// activation, and the tenant's pulse. The windowed modules come after.
//
// The menu bar never shows a password or a recovery key. Device lookup is inventory only.

@main
struct TenantKeepMacApp: App {
    @StateObject private var model = MacModel()

    init() {
        #if DEBUG
        MenuSnapshot.runIfAsked()
        #endif
    }

    var body: some Scene {
        MenuBarExtra {
            MacMenuView(model: model)
        } label: {
            Image(systemName: model.attention ? "exclamationmark.shield.fill" : "shield.lefthalf.filled")
                .accessibilityLabel("TenantKeep")
        }
        .menuBarExtraStyle(.window)
    }
}

#if DEBUG
/// Debug builds only: `-LAPSlockSnapshot <folder>` renders the menu's three tabs with demo
/// data to PNGs off screen and quits, for checking the layout without screen access.
@MainActor
enum MenuSnapshot {
    static func runIfAsked() {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "-LAPSlockSnapshot"), i + 1 < args.count else { return }
        let folder = URL(fileURLWithPath: args[i + 1])
        Task { @MainActor in
            let model = MacModel(demo: true)
            try? await Task.sleep(for: .seconds(3))
            for tab in MacMenuView.Tab.allCases {
                let renderer = ImageRenderer(content: MacMenuView(model: model, initialTab: tab).background(Color(nsColor: .windowBackgroundColor)))
                renderer.scale = 2
                if let image = renderer.cgImage {
                    let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
                    do {
                        try png?.write(to: folder.appendingPathComponent("menu-" + tab.rawValue + ".png"))
                    } catch {
                        FileHandle.standardError.write(Data(("snapshot write failed: " + error.localizedDescription + "\n").utf8))
                    }
                } else {
                    FileHandle.standardError.write(Data("snapshot render failed\n".utf8))
                }
            }
            exit(0)
        }
    }
}
#endif
