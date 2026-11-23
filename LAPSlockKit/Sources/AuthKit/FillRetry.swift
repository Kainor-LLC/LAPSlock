import Foundation

/// How a background fill (the whole device list, the whole directory) waits before asking
/// for the same page again.
///
/// A fill of a large tenant is about fifty requests in a row. Without a retry, one dropped
/// connection or one 503 ended it: at a 1% failure rate per request four fills in ten did
/// not finish, and search then ran over part of the tenant. With three retries a page
/// fails only when all four attempts do.
///
/// It stays polite. A throttled tenant is asked again only after the time Graph named,
/// never sooner, and a wait longer than `maxWait` stops the fill instead: Graph wants this
/// tenant left alone, and the person's own taps share the same budget.
public enum FillRetry {

    /// Attempts at one page before the fill stops with what it has.
    public static let maxAttempts = 4

    /// Longest wait honoured before stopping instead.
    public static let maxWait: TimeInterval = 60

    /// What to wait when Graph throttles without saying for how long.
    public static let defaultThrottleWait: TimeInterval = 5

    public enum Problem: Sendable, Equatable {
        /// 429, with Graph's Retry-After if it sent one.
        case throttled(retryAfter: TimeInterval?)
        /// A dropped connection or a 5xx: worth asking again.
        case transient
    }

    /// Seconds to wait before asking for the page again, or nil to stop.
    ///
    /// - Parameters:
    ///   - failures: how many times this page has failed so far, counting this one.
    ///   - jitter: 0 to 1. Spreads the retries of many phones so they do not return together.
    public static func wait(after problem: Problem, failures: Int, jitter: Double = Double.random(in: 0...1)) -> TimeInterval? {
        guard failures >= 1, failures < maxAttempts else { return nil }
        let spread = min(max(jitter, 0), 1)
        switch problem {
        case .throttled(let retryAfter):
            let asked = max(retryAfter ?? defaultThrottleWait, 0)
            guard asked <= maxWait else { return nil }
            // A little late, never early.
            return asked + spread
        case .transient:
            // 1, 3 and 9 seconds, each up to a quarter longer.
            return pow(3, Double(failures - 1)) * (1 + 0.25 * spread)
        }
    }
}
