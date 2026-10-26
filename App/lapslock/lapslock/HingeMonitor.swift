import SwiftUI
import UIKit

// The fold. iOS 27.1 reports a device's hinge through a UIKit interaction and nothing in
// SwiftUI, so this is the one bridge: a zero-size view that carries the interaction and
// publishes the posture. The shell reads it to put a column boundary on the hinge when
// the device is open, so a credential card never straddles the fold.
//
// Status and angle are all the interaction gives; it says nothing about where the hinge
// is. On the iPhone Duo in landscape it is the vertical centre line of the inner display
// (measured in phase 1), which is what the shell's half-width rule relies on. A device
// with a hinge somewhere else needs a different rule and is a phase of its own.

enum HingePosture: Equatable {
    case unknown
    case closed
    case partiallyOpen
    case fullyOpen

    /// Open enough that the display spans the fold.
    var isOpen: Bool { self == .partiallyOpen || self == .fullyOpen }
}

struct HingeMonitor: UIViewRepresentable {
    @Binding var posture: HingePosture

    /// DEBUG only: pretend the device is open, so the half-width rule can be checked on an
    /// iPad simulator, where nothing can fold.
    static var forcedOpen: Bool {
        #if DEBUG
        return CommandLine.arguments.contains("-LAPSlockHingeOpen")
        #else
        return false
        #endif
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(binding: $posture)
    }

    func makeUIView(context: Context) -> UIView {
        let view = UIView(frame: .zero)
        view.isUserInteractionEnabled = false
        view.isAccessibilityElement = false
        if Self.forcedOpen {
            context.coordinator.report(.fullyOpen)
            return view
        }
        if #available(iOS 27.1, *) {
            let coordinator = context.coordinator
            let interaction = UIHingeInteraction { _, update in
                coordinator.report(HingePosture(update.hinge?.status))
            }
            view.addInteraction(interaction)
        }
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        context.coordinator.binding = $posture
    }

    @MainActor
    final class Coordinator {
        var binding: Binding<HingePosture>

        init(binding: Binding<HingePosture>) {
            self.binding = binding
        }

        func report(_ posture: HingePosture) {
            // A state write from inside a view update is refused; the interaction's
            // callback can land there, so the write is deferred a turn.
            Task { @MainActor [weak self] in
                guard let self, self.binding.wrappedValue != posture else { return }
                self.binding.wrappedValue = posture
            }
        }
    }
}

extension HingePosture {
    @available(iOS 27.1, *)
    init(_ status: UIHinge.Status?) {
        switch status {
        case .closed?:        self = .closed
        case .partiallyOpen?: self = .partiallyOpen
        case .fullyOpen?:     self = .fullyOpen
        default:              self = .unknown
        }
    }
}

/// The column rule, kept as a function so the arithmetic is in one place.
enum HingeLayout {
    /// When the device is open with a regular width, the sidebar hides and the content
    /// column ends at the centre of the display, which is where the hinge is, so the
    /// whole detail column, where credentials appear, sits on the other half.
    ///
    /// The centre of the DISPLAY, not of the safe area: the Duo's landscape safe area is
    /// inset on both sides, and half of the inset width landed the boundary 42 points
    /// short of the fold on the first run. The column starts at the leading inset, so its
    /// width is half the full width less that inset.
    ///
    /// When the sidebar is shown as well, it is part of the left half too: the boundary
    /// that matters is the one against the detail, so the content column gives up the
    /// sidebar's width rather than pushing the detail into a sliver, which is what the
    /// first Device Hub pass showed.
    static let sidebarWidth: CGFloat = 260
    static let minimumContent: CGFloat = 180

    static func contentWidth(fullWidth: CGFloat, leadingInset: CGFloat, sidebarShown: Bool, open: Bool, ideal: CGFloat) -> CGFloat {
        guard open else { return ideal }
        let half = (fullWidth / 2 - leadingInset).rounded(.down)
        return max(minimumContent, sidebarShown ? half - sidebarWidth : half)
    }
}
