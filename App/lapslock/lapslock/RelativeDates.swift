import Foundation

/// Relative dates ("5 min. ago", "in 2 hours"), one formatter per style, built once. A
/// formatter per call was one for every row on every redraw, and twice a second on the
/// device screen while its countdown ran.
enum RelativeDates {
    static func abbreviated(_ date: Date, from now: Date = Date()) -> String {
        abbreviatedStyle.localizedString(for: date, relativeTo: now)
    }

    static func short(_ date: Date, from now: Date = Date()) -> String {
        shortStyle.localizedString(for: date, relativeTo: now)
    }

    static func full(_ date: Date, from now: Date = Date()) -> String {
        fullStyle.localizedString(for: date, relativeTo: now)
    }

    private static let abbreviatedStyle = formatter(.abbreviated)
    private static let shortStyle = formatter(.short)
    private static let fullStyle = formatter(.full)

    private static func formatter(_ style: RelativeDateTimeFormatter.UnitsStyle) -> RelativeDateTimeFormatter {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = style
        return formatter
    }
}
