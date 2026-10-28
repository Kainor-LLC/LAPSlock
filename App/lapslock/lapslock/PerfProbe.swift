import Foundation
import os
import InventoryKit

// Measuring aids for the optimization pass (OPTIMIZATION-PLAN.md, step C), so each later step
// can say what it changed in numbers. DEBUG builds only, and silent unless asked for at launch:
//
//   -LAPSlockLargeDemo   demo mode at the size of a large customer: 20,000 devices paged 100
//                        at a time at 450 ms a page, 200 incidents, 150 policies, 300 groups,
//                        200 Message Center posts and 600 expiring items.
//   -LAPSlockPerfLog     timings and view body evaluations as notice lines in the "perf"
//                        category, read back with `log show` or `log stream`.
//   -LAPSlockRefreshAfter N
//                        a pull to refresh on the device list N seconds after it first
//                        loads, for a simulator whose synthesized drags do not set one off.
//
// A Release build compiles every call here to nothing and never looks at the arguments.

enum PerfProbe {
    static let largeDemo: Bool = {
        #if DEBUG
        return CommandLine.arguments.contains("-LAPSlockLargeDemo")
        #else
        return false
        #endif
    }()

    static let isOn: Bool = {
        #if DEBUG
        return CommandLine.arguments.contains("-LAPSlockPerfLog")
        #else
        return false
        #endif
    }()

    /// Seconds after the device list's first load to refresh it, when asked for.
    static let refreshAfter: Double? = {
        #if DEBUG
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "-LAPSlockRefreshAfter"), i + 1 < args.count else { return nil }
        return Double(args[i + 1])
        #else
        return nil
        #endif
    }()

    /// Built once: a demo provider is made per shell, and the fleet must not be rebuilt with it.
    static let largeFleet: [ManagedDeviceSummary] = largeDemo ? DemoInventoryProvider.largeFleet() : []

    private static let log = Logger(subsystem: "com.kainor.lapslock", category: "perf")

    /// Records one evaluation of a view's body. Used as `let _ = PerfProbe.body("Name")`.
    @discardableResult
    static func body(_ name: String) -> Bool {
        #if DEBUG
        if isOn { log.notice("body \(name, privacy: .public)") }
        #endif
        return true
    }

    /// Times `work` and records it with a detail line; returns its result either way.
    static func measure<T>(_ name: String, _ detail: @autoclosure () -> String = "", _ work: () -> T) -> T {
        #if DEBUG
        guard isOn else { return work() }
        let start = ContinuousClock.now
        let result = work()
        let ms = (ContinuousClock.now - start) / .milliseconds(1)
        let text = detail()
        log.notice("\(name, privacy: .public) ms=\(ms, format: .fixed(precision: 2), privacy: .public) \(text, privacy: .public)")
        return result
        #else
        return work()
        #endif
    }

    /// Records a moment, with the milliseconds since `start` when given.
    static func mark(_ name: String, since start: ContinuousClock.Instant? = nil, _ detail: @autoclosure () -> String = "") {
        #if DEBUG
        guard isOn else { return }
        let text = detail()
        if let start {
            let ms = (ContinuousClock.now - start) / .milliseconds(1)
            log.notice("\(name, privacy: .public) ms=\(ms, format: .fixed(precision: 1), privacy: .public) \(text, privacy: .public)")
        } else {
            log.notice("\(name, privacy: .public) \(text, privacy: .public)")
        }
        #endif
    }
}
