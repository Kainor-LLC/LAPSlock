import XCTest
import CredentialKit
@testable import InventoryKit

/// An inventory whose pages are scripted, including which page throttles or fails.
///
/// Mirrors the real service's contract exactly where it matters for the fill: `hasMore`
/// reflects an unconsumed next page, `loadNextPage` returns nil when exhausted, and a
/// failing page does NOT advance the cursor — so a retry re-fetches the same page, as it
/// would against Graph.
private actor ScriptedInventory: DeviceInventoryProviding {
    private let pages: [[ManagedDeviceSummary]]
    /// Errors to throw, keyed by the 1-based index of the page being fetched. Each entry is
    /// consumed once, so a page can be made to throttle once and then succeed.
    private var failures: [Int: [InventoryError]]
    /// Sleep before each page, so a cancellation test has a suspension point to land on.
    private let latency: Duration

    private(set) var loaded: [ManagedDeviceSummary] = []
    private var cursor = 0
    private(set) var fetches = 0

    init(pages: [[ManagedDeviceSummary]], failures: [Int: [InventoryError]] = [:], latency: Duration = .zero) {
        self.pages = pages
        self.failures = failures
        self.latency = latency
    }

    func loadFirstPage() async throws -> DevicePage {
        loaded = pages.first ?? []
        cursor = 1
        return DevicePage(devices: loaded, nextLink: cursor < pages.count ? "next" : nil)
    }

    func loadNextPage() async throws -> DevicePage? {
        guard cursor < pages.count else { return nil }
        fetches += 1
        if latency != .zero { try await Task.sleep(for: latency) }
        let index = cursor + 1
        if var queue = failures[index], !queue.isEmpty {
            let error = queue.removeFirst()
            failures[index] = queue
            throw error
        }
        let page = pages[cursor]
        loaded.append(contentsOf: page)
        cursor += 1
        return DevicePage(devices: page, nextLink: cursor < pages.count ? "next" : nil)
    }

    func cachedDevices() async throws -> [ManagedDeviceSummary] { loaded }
    func hasMore() async throws -> Bool { cursor < pages.count }
    func reset() async { loaded = []; cursor = 0 }
}

/// Collects what the fill reports after each page.
private actor PageLog {
    private(set) var counts: [Int] = []
    func record(_ devices: [ManagedDeviceSummary]) { counts.append(devices.count) }
}

final class InventoryFillTests: XCTestCase {

    private func page(_ n: Int, of size: Int = 3) -> [ManagedDeviceSummary] {
        (0..<size).map { i in
            ManagedDeviceSummary(
                id: "p\(n)-\(i)", entraDeviceId: "e-\(n)-\(i)",
                deviceName: "WS-\(n)-\(i)", platform: .windows)
        }
    }

    private func inventory(pages: Int, failures: [Int: [InventoryError]] = [:], latency: Duration = .zero) async throws -> ScriptedInventory {
        let scripted = ScriptedInventory(
            pages: (1...pages).map { page($0) }, failures: failures, latency: latency)
        _ = try await scripted.loadFirstPage()
        return scripted
    }

    func test_fillsEveryRemainingPageAndReportsRunningTotals() async throws {
        let inv = try await inventory(pages: 4)
        let log = PageLog()

        let outcome = await InventoryFill.run(inv) { await log.record($0) }

        XCTAssertEqual(outcome, .complete)
        // First page was 3; each subsequent page reports the full cached list so far.
        let counts = await log.counts
        XCTAssertEqual(counts, [6, 9, 12])
        let loaded = await inv.loaded.count
        XCTAssertEqual(loaded, 12, "the whole tenant is now searchable")
    }

    func test_nothingToDoWhenTheFirstPageWasTheOnlyPage() async throws {
        let inv = try await inventory(pages: 1)
        let log = PageLog()
        let outcome = await InventoryFill.run(inv) { await log.record($0) }
        XCTAssertEqual(outcome, .complete)
        let counts = await log.counts
        XCTAssertTrue(counts.isEmpty, "no page, no callback — the UI must not flicker a loading state")
    }

    func test_stopsAtTheCapAndSaysSo() async throws {
        // 10 pages available, cap at 3 more. The outcome MUST be capped, not complete:
        // the search UI shows "not all loaded" off this distinction.
        let inv = try await inventory(pages: 10)
        let outcome = await InventoryFill.run(inv, maxPages: 3) { _ in }
        XCTAssertEqual(outcome, .capped)
        let fetches = await inv.fetches
        XCTAssertEqual(fetches, 3, "exactly the cap, no more")
        let more = try await inv.hasMore()
        XCTAssertTrue(more, "manual load-more must still be possible afterwards")
    }

    func test_aTenantOfExactlyTheCapIsCompleteNotCapped() async throws {
        // Reaching the cap is not the same as being cut off by it.
        let inv = try await inventory(pages: 4)
        let outcome = await InventoryFill.run(inv, maxPages: 3) { _ in }
        XCTAssertEqual(outcome, .complete)
    }

    func test_oneThrottleIsWaitedOutAndTheFillContinues() async throws {
        // Retry-After of zero so the test does not actually wait. The page that throttled
        // is fetched again and succeeds; nothing is skipped or duplicated.
        let inv = try await inventory(pages: 4, failures: [2: [.throttled(retryAfter: 0)]])
        let log = PageLog()
        let outcome = await InventoryFill.run(inv) { await log.record($0) }
        XCTAssertEqual(outcome, .complete)
        let counts = await log.counts
        XCTAssertEqual(counts, [6, 9, 12], "the throttled page was retried, not skipped")
    }

    func test_aSecondThrottleStopsTheFillAndKeepsWhatLoaded() async throws {
        // A background job that keeps hammering a throttled tenant competes with the
        // user's own taps for the same budget. Stop, keep everything, leave load-more.
        let inv = try await inventory(pages: 5, failures: [
            2: [.throttled(retryAfter: 0)],
            3: [.throttled(retryAfter: 0)],
        ])
        let outcome = await InventoryFill.run(inv) { _ in }
        XCTAssertEqual(outcome, .failed(.throttled(retryAfter: 0)))
        let loaded = await inv.loaded.count
        XCTAssertEqual(loaded, 6, "page 2 landed before the second throttle")
    }

    func test_anyOtherErrorStopsTheFillWithoutLosingPages() async throws {
        let inv = try await inventory(pages: 5, failures: [3: [.serviceUnavailable(status: 503)]])
        let log = PageLog()
        let outcome = await InventoryFill.run(inv) { await log.record($0) }
        XCTAssertEqual(outcome, .failed(.serviceUnavailable(status: 503)))
        let counts = await log.counts
        XCTAssertEqual(counts, [6], "the page before the failure was delivered")
        let loaded = await inv.loaded.count
        XCTAssertEqual(loaded, 6)
    }

    func test_cancellationStopsPagingPromptly() async throws {
        // Refresh, sign-out and tenant switch all cancel the fill. It must notice at the
        // next suspension point rather than finishing a 50-page run nobody wants.
        let inv = try await inventory(pages: 50, latency: .milliseconds(20))
        let task = Task { await InventoryFill.run(inv) { _ in } }
        try await Task.sleep(for: .milliseconds(50))
        task.cancel()
        let outcome = await task.value
        XCTAssertEqual(outcome, .cancelled)
        let fetches = await inv.fetches
        XCTAssertLessThan(fetches, 10, "cancelled after a handful of pages, not fifty")
    }

    func test_theDefaultCapCoversFiveThousandDevices() {
        // 50 pages at the service's 100-per-page default. Pinned so that a change to
        // either number is a deliberate decision with this test in front of it.
        XCTAssertEqual(InventoryFill.defaultMaxPages * 100, 5_000)
    }
}
