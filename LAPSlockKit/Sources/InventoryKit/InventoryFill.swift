import Foundation
import AuthKit

// Filling the inventory to completion, so search covers the whole tenant.
//
// The bug this fixes: search is client-side over the pages loaded so far, because Graph's
// `managedDevices` has no usable server-side name search (`$filter` supports `eq` and a
// little `startswith`, no `contains`, and `$search` is unsupported on the resource). On a
// tenant large enough that the administrator has not scrolled to the end, searching for a
// device that EXISTS returned nothing, and that never read as "still loading", it read as
// "this app cannot find my machine". It got worse the bigger the customer.
//
// THE SHAPE. The first page renders immediately, then this pages onward in the background,
// in larger pages, until exhausted or capped, and each page's new devices are merged into
// the list as it lands. The UI says "still loading" while it runs, because the actual defect
// was that an empty result during a partial load was a lie.
//
// One pager at a time. `DeviceInventoryService` is an actor, but `loadNextPage` reads the
// next link, suspends on the fetch, then appends, so two concurrent callers read the same
// link and append the same page twice. While a fill is running it must be the only thing
// paging; the list model enforces that by making its manual "load more" a no-op meanwhile.

public enum InventoryFill {

    /// Devices before stopping, not pages: a cap in pages meant whatever the page size
    /// made it, and at 50 pages of 100 a 20,000-device tenant was a quarter searchable.
    /// Beyond this the search UI says "not all loaded", and the list asks Graph directly.
    public static let defaultMaxDevices = 50_000

    public enum Outcome: Sendable, Equatable {
        /// Every page loaded. Search results are complete.
        case complete
        /// Stopped at the cap with pages remaining. Search is NOT complete, and the UI
        /// must say so rather than showing an empty result as if it were an answer.
        case capped
        /// The caller cancelled, refresh, sign-out or tenant switch.
        case cancelled
        /// A page failed after its retries. Everything loaded so far is kept and usable.
        case failed(InventoryError)
    }

    /// Pages onward from wherever `inventory` currently is, calling `onPage` after every
    /// page with the devices that page added and how many are loaded in all, so the caller
    /// merges a page rather than re-sorting everything as results arrive.
    ///
    /// Expects `loadFirstPage` to have been called already: the first page is what the user
    /// is looking at, and it is fetched on the foreground path with its own error handling.
    ///
    /// A page that fails for a passing reason (a dropped connection, a 5xx, a 429) is asked
    /// for again, as `FillRetry` says: up to three more times, waiting as long as Graph
    /// asked, and stopping instead when Graph asks for longer than a minute. A page that
    /// fails four times, or for a lasting reason, stops the fill: whatever is loaded stays,
    /// the manual "load more" remains, and search says it is incomplete.
    public static func run(
        _ inventory: any DeviceInventoryProviding,
        maxDevices: Int = defaultMaxDevices,
        sleep: @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) },
        onPage: @Sendable (_ added: [ManagedDeviceSummary], _ total: Int) async -> Void
    ) async -> Outcome {
        var total = (try? await inventory.cachedDevices().count) ?? 0
        var failures = 0

        while total < maxDevices {
            if Task.isCancelled { return .cancelled }
            do {
                guard try await inventory.hasMore() else { return .complete }
                guard let page = try await inventory.loadNextPage() else { return .complete }
                failures = 0
                total += page.devices.count
                await onPage(page.devices, total)
            } catch is CancellationError {
                return .cancelled
            } catch {
                // A dropped connection, a timeout or a body cut off arrives as the URL
                // system's own error, or as a body that does not parse, never as an
                // InventoryError. Each is as passing as a 5xx. Before the second review
                // (R2-2, 2026-11-24) these ended the fill on the first one.
                let failure = (error as? InventoryError) ?? Self.failure(from: error)
                if failure == .cancelled { return .cancelled }
                failures += 1
                guard let problem = failure.fillRetryProblem,
                      let wait = FillRetry.wait(after: problem, failures: failures) else { return .failed(failure) }
                do {
                    try await sleep(wait)
                } catch {
                    return .cancelled
                }
            }
        }

        // At the cap. Only "capped" if something actually remains, a tenant of exactly
        // maxDevices devices is complete, not cut off.
        let more = (try? await inventory.hasMore()) ?? true
        return more ? .capped : .complete
    }

    /// What a failure that is not an `InventoryError` means to the fill: a cancelled
    /// request is a cancellation, and anything else (the URL system's errors, a body that
    /// does not parse) is a transport failure, which the fill asks again for.
    static func failure(from error: Error) -> InventoryError {
        if let url = error as? URLError, url.code == .cancelled { return .cancelled }
        return .transport(status: -1)
    }
}


extension InventoryError {
    /// Whether a fill should ask for the page again: throttling, a dropped connection or a
    /// 5xx. A refusal (consent, a role, a malformed request) is not going to change.
    var fillRetryProblem: FillRetry.Problem? {
        switch self {
        case .throttled(let retryAfter):              return .throttled(retryAfter: retryAfter)
        case .serviceUnavailable:                     return .transient
        case .transport(let status) where status < 0 || status >= 500: return .transient
        default:                                      return nil
        }
    }
}
