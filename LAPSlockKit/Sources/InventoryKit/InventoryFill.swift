import Foundation

// Filling the inventory to completion, so search covers the whole tenant.
//
// THE BUG THIS FIXES. Search is client-side over the pages loaded so far, because Graph's
// `managedDevices` has no usable server-side name search (`$filter` supports `eq` and a
// little `startswith`, no `contains`, and `$search` is unsupported on the resource). On a
// tenant large enough that the administrator has not scrolled to the end, searching for a
// device that EXISTS returned nothing — and that never read as "still loading", it read as
// "this app cannot find my machine". It got worse the bigger the customer.
//
// THE SHAPE. The first page renders immediately, then this pages onward in the background
// until exhausted or capped, and the list re-filters as each page lands. The UI says "still
// loading" while it runs, because the actual defect was that an empty result during a
// partial load was a lie.
//
// ONE PAGER AT A TIME. `DeviceInventoryService` is an actor, but `loadNextPage` reads the
// next link, suspends on the fetch, then appends — so two concurrent callers read the same
// link and append the same page twice. While a fill is running it must be the only thing
// paging; the list model enforces that by making its manual "load more" a no-op meanwhile.

public enum InventoryFill {

    /// 50 pages at 100 devices each: 5,000 devices before stopping. Named so the day a
    /// customer with more reports it, the change is one line and the search UI already
    /// knows how to say "not all loaded".
    public static let defaultMaxPages = 50

    /// Longest `Retry-After` honoured before stopping instead. Anything longer means Graph
    /// is genuinely unhappy with this tenant and a background job should get out of the way.
    static let maxRetryWait: TimeInterval = 30

    /// What to wait when Graph throttles without saying for how long.
    static let defaultRetryWait: TimeInterval = 5

    public enum Outcome: Sendable, Equatable {
        /// Every page loaded. Search results are complete.
        case complete
        /// Stopped at the cap with pages remaining. Search is NOT complete, and the UI
        /// must say so rather than showing an empty result as if it were an answer.
        case capped
        /// The caller cancelled — refresh, sign-out or tenant switch.
        case cancelled
        /// A page failed after any retry. Everything loaded so far is kept and usable.
        case failed(InventoryError)
    }

    /// Pages onward from wherever `inventory` currently is, calling `onPage` with the full
    /// cached list after every page so the caller can re-render as results arrive.
    ///
    /// Expects `loadFirstPage` to have been called already: the first page is what the user
    /// is looking at, and it is fetched on the foreground path with its own error handling.
    ///
    /// Throttling is honoured once. A second 429 stops the fill: whatever is loaded stays,
    /// the manual "load more" remains, and search says it is incomplete. Retrying further
    /// would be a background job competing with the user's own taps for the same budget.
    public static func run(
        _ inventory: any DeviceInventoryProviding,
        maxPages: Int = defaultMaxPages,
        onPage: @Sendable ([ManagedDeviceSummary]) async -> Void
    ) async -> Outcome {
        var pages = 0
        var throttledOnce = false

        while pages < maxPages {
            if Task.isCancelled { return .cancelled }
            do {
                guard try await inventory.hasMore() else { return .complete }
                guard try await inventory.loadNextPage() != nil else { return .complete }
                pages += 1
                await onPage(try await inventory.cachedDevices())
            } catch InventoryError.throttled(let retryAfter) where !throttledOnce {
                throttledOnce = true
                let wait = min(retryAfter ?? defaultRetryWait, maxRetryWait)
                do {
                    try await Task.sleep(for: .seconds(wait))
                } catch {
                    return .cancelled
                }
            } catch is CancellationError {
                return .cancelled
            } catch let error as InventoryError {
                return error == .cancelled ? .cancelled : .failed(error)
            } catch {
                return .failed(.transport(status: -1))
            }
        }

        // At the cap. Only "capped" if something actually remains — a tenant of exactly
        // maxPages pages is complete, not cut off.
        let more = (try? await inventory.hasMore()) ?? true
        return more ? .capped : .complete
    }
}
