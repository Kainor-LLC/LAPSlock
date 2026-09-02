import SwiftUI
import UIKit

// Visual identity, carried over from kainor.com so the product reads as one thing.
//
// DESIGN NOTE: the palette and the pit-lane language come from the marketing site, but
// the structure here is deliberately iOS-native — List, NavigationStack, SF Symbols.
// A heavily custom-chromed iOS app reads as a ported web page, which is the last
// impression an infrastructure tool wants to give.
//
// The one typographic conviction: every piece of MACHINE DATA is monospaced —
// passwords, device identifiers, serial numbers, the countdown. This is functional, not
// stylistic. An admin transcribing a random 14-character password into a console needs
// unambiguous glyphs and fixed advance width; proportional text turns l/1/I and 0/O
// into a guessing game and costs a failed logon attempt.

public enum Brand {

    // Hex rather than fractional components, so these values can be compared by eye against
    // `design/icons/README.md`, which is where the identity is defined. The previous
    // fractional triples were impossible to check against the mark, which is part of how the
    // accent drifted out of the palette unnoticed.

    /// The icon's navy field. Dark surfaces and the credential card.
    public static let field = fixed(0x16233A)

    /// Secondary text on the navy field.
    public static let mist = fixed(0xA9B6C6)

    /// The accent, for surfaces that follow the system appearance — buttons, tints, list
    /// rows, banners.
    ///
    /// ADAPTIVE, and it has to be. Both values are the icon's steel: as drawn for light
    /// appearance, lifted for dark. A single value cannot serve both — measured against
    /// white, the icon's steel is 5.30:1 and the lifted one only 3.09:1; against a dark
    /// system background the ranking reverses.
    public static let accent = Color(uiColor: UIColor { traits in
        traits.userInterfaceStyle == .dark ? uiFixed(0x6E96C2) : uiFixed(0x4A6E96)
    })

    /// The accent on the navy credential card, which is navy in BOTH appearances and so
    /// takes a fixed value rather than an adaptive one.
    ///
    /// The lifted steel, at 5.09:1 on the field. **The icon's steel as drawn measures 2.97:1
    /// here, below the 3.0 floor for a UI component** — which is why this token exists
    /// separately instead of the mark's colour being used directly. The countdown ring and
    /// the reveal timer live on this surface, so it is the one place the accent must not be
    /// taken on faith.
    public static let accentOnField = fixed(0x6E96C2)

    private static func fixed(_ hex: UInt32) -> Color { Color(uiColor: uiFixed(hex)) }

    private static func uiFixed(_ hex: UInt32) -> UIColor {
        UIColor(
            red:   CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue:  CGFloat(hex & 0xFF) / 255,
            alpha: 1
        )
    }

    /// Monospaced type for machine data, at a few deliberate sizes.
    public static func data(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }

    /// Small uppercase label used for field names. Encodes "this is a record field",
    /// which is true of the content rather than decorative.
    public static let fieldLabel = Font.system(size: 11, weight: .medium, design: .monospaced)
}

// MARK: - shared primitives

/// A labelled row of machine data. Label is proportional (it's prose), value is
/// monospaced (it's data) — the distinction is the point.
struct DataRow: View {
    let label: String
    let value: String?
    var monospaced: Bool = true

    var body: some View {
        if let value, !value.isEmpty {
            HStack(alignment: .firstTextBaseline) {
                Text(label.uppercased())
                    .font(Brand.fieldLabel)
                    .foregroundStyle(.secondary)
                    .frame(width: 116, alignment: .leading)
                Text(value)
                    .font(monospaced ? Brand.data(14) : .subheadline)
                    .textSelection(.enabled)
                Spacer(minLength: 0)
            }
        }
    }
}

/// Platform glyph. Kept literal — an admin scanning a list identifies by silhouette
/// faster than by reading the OS name.
struct PlatformIcon: View {
    let systemName: String
    var body: some View {
        Image(systemName: systemName)
            .font(.title3)
            .frame(width: 30)
            .foregroundStyle(.secondary)
    }
}

/// Status pill for a device's compliance / freshness. Only appears when there is
/// something worth flagging: a row with no pill is a healthy row.
struct StatusPill: View {
    enum Kind {
        case noncompliant
        case stale(days: Int)

        var text: String {
            switch self {
            case .noncompliant: return "Not compliant"
            case .stale(let days): return "Last seen \(days)d ago"
            }
        }
        var color: Color {
            switch self {
            case .noncompliant: return .orange
            case .stale: return .secondary
            }
        }
    }

    let kind: Kind

    var body: some View {
        Text(kind.text)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(kind.color.opacity(0.14), in: Capsule())
            .foregroundStyle(kind.color)
    }
}

/// Persistent demo indicator. Required, not optional: a screen showing
/// DEMO-Not-A-Real-Password must never be mistakable for a live tenant.
/// Which organization's devices are on screen.
///
/// Always shown in the live path, not only when switched. For a single-organization admin it
/// is quiet context; for an MSP it is the answer to the question that matters most before
/// revealing a password — whose directory am I actually looking at. A tool where that is
/// ambiguous is a tool that eventually reveals the right password to the wrong ticket.
///
/// Away from home it becomes a warning rather than a label. Absence of a banner is easy to
/// miss; a differently coloured banner is not.
struct TenantBanner: View {
    let label: String
    /// True when operating somewhere other than the signed-in account's own organization.
    let isAwayFromHome: Bool

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: isAwayFromHome ? "building.2.fill" : "building.2")
            Text(isAwayFromHome ? "Working in \(label)" : label)
                .font(.caption.weight(.medium))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background {
            ZStack {
                Rectangle().fill(.background)
                if isAwayFromHome {
                    Rectangle().fill(Brand.accent.opacity(0.16))
                }
            }
        }
        .foregroundStyle(isAwayFromHome ? Brand.accent : .secondary)
        .overlay(alignment: .bottom) { Divider() }
        .accessibilityLabel(isAwayFromHome
            ? "Working in another organization, \(label)"
            : "Organization, \(label)")
    }
}

struct DemoBanner: View {
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "theatermasks.fill")
            Text("Demo data — not connected to a tenant")
                .font(.caption.weight(.medium))
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        // Opaque backing, layered: a solid system background first so scrolled content
        // can't show through, then the orange wash on top for the warning colour.
        .background {
            ZStack {
                Rectangle().fill(.background)
                Rectangle().fill(Brand.accent.opacity(0.16))
            }
        }
        .foregroundStyle(Brand.accent)
        .overlay(alignment: .bottom) {
            Divider()
        }
    }
}

// MARK: - dark mode support

extension Brand {
    /// The credential card sits on the app background. In light mode the navy provides
    /// its own separation; in dark mode it can read as a muddy smudge against near-black,
    /// so a hairline border restores the edge.
    static func cardBorder(for scheme: ColorScheme) -> Color {
        scheme == .dark ? Brand.mist.opacity(0.22) : .clear
    }
}
