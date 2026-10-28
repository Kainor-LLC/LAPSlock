import SwiftUI

/// A write waiting out its undo window: what is about to be sent, the seconds left, Send now
/// for an admin who is sure, and Undo as the button that stands out. In a list it is a row;
/// `floating` gives it the bar's own background for a bottom inset, so the list does not jump.
struct UndoBar: View {
    let title: String
    var detail: String? = nil
    /// The action as VoiceOver names it on the two buttons, such as "Retire".
    let spokenAction: String
    let remaining: Int
    var floating = false
    let sendNow: () -> Void
    let undo: () -> Void

    var body: some View {
        // One line when the title fits beside the buttons; otherwise the buttons go under
        // it, so a device name is not broken at its hyphen into a column 86 points wide.
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) {
                label
                Spacer()
                buttons
            }
            VStack(alignment: .leading, spacing: 8) {
                label
                HStack(spacing: 12) {
                    Spacer()
                    buttons
                }
            }
        }
        .padding(.vertical, 4)
        // Both buttons reachable: a list row otherwise exposes only one of them.
        .accessibilityElement(children: .contain)
        .padding(.horizontal, floating ? 16 : 0)
        .padding(.vertical, floating ? 4 : 0)
        .background(floating ? AnyShapeStyle(.regularMaterial) : AnyShapeStyle(.clear))
    }

    private var label: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.body.weight(.semibold))
            if let detail {
                Text(detail).font(.caption).lineLimit(2)
            }
            Text("Sending in \(remaining) s")
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
    }

    @ViewBuilder
    private var buttons: some View {
        Button(action: sendNow) {
            Text("Send now").padding(8)
        }
        .buttonStyle(.borderless)
        .accessibilityLabel("Send " + spokenAction + " now")
        Button(action: undo) {
            Text("Undo")
                .font(.body.weight(.bold))
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
        }
        .buttonStyle(.borderedProminent)
        .accessibilityLabel("Undo " + spokenAction)
    }
}
