import Foundation

// Running one saved search in every organization, phase 5 step D. MSP only, read-only kinds
// only: "which of my customers got this phishing email?"
//
// This file is the order and the limits, nothing else. It cannot reach Graph or a token:
// the app hands it one closure per organization, built on a silent-only auth for that
// tenant, the same way the background alerts run does. So the rules below are testable
// without a tenant:
//
//   * One organization at a time, in the order given. Never in parallel: a run across forty
//     customers must not look like a burst from one admin.
//   * A budget per organization. One slow tenant cannot hold the run; it is marked and the
//     next one starts.
//   * An organization that needs a sign-in or a consent is marked and skipped. Nothing here
//     can prompt, and the run goes on.
//   * Two organizations throttled in a row stops the run. Microsoft is saying slow down, and
//     the rest are marked not searched rather than hammered.
//
// Results are reported as they arrive and kept by the caller only on screen. Nothing is
// written anywhere. Writes never run across organizations; there is no write here to run.

/// One organization a search runs in.
public struct CrossTenantTarget: Sendable, Equatable, Identifiable {
    public let tenantId: String
    public let label: String
    public var id: String { tenantId }

    public init(tenantId: String, label: String) {
        self.tenantId = tenantId
        self.label = label
    }
}

/// What a search found in one organization: how many, and the first few by name.
public struct TenantHits: Sendable, Equatable {
    public static let topLimit = 3

    public let count: Int
    public let top: [String]

    public init(count: Int, top: [String]) {
        self.count = count
        self.top = Array(top.prefix(Self.topLimit))
    }
}

/// Why a search did not finish in one organization, as the closure reports it.
public enum CrossTenantFailure: Error, Sendable, Equatable {
    /// A foreground sign-in or a consent is needed. Never attempted from here.
    case needsSignIn
    /// Microsoft answered 429 after the client's own backoff.
    case throttled
    /// Anything else, in words for the row: no role, no licence, Microsoft not answering.
    case unavailable(String)
}

/// One organization's row.
public enum CrossTenantOutcome: Sendable, Equatable {
    case waiting
    case running
    case found(TenantHits)
    case needsSignIn
    case throttled
    case timedOut
    case unavailable(String)
    /// The run stopped before reaching this organization.
    case notRun
}

public enum CrossTenantStop: Sendable, Equatable {
    case finished
    /// Two organizations in a row were throttled.
    case throttled
    /// The screen closed.
    case cancelled
}

public struct CrossTenantRunner: Sendable {
    public static let defaultBudget: Duration = .seconds(30)
    /// Throttled organizations in a row before the run stops.
    public static let throttleLimit = 2

    public let budget: Duration

    public init(budget: Duration = Self.defaultBudget) {
        self.budget = budget
    }

    /// Runs `search` in each organization in turn, reporting each row as it changes by its
    /// index in `targets`. Returns why the run ended.
    public func run(
        _ targets: [CrossTenantTarget],
        search: @escaping @Sendable (CrossTenantTarget) async throws -> TenantHits,
        report: @escaping @Sendable (Int, CrossTenantOutcome) async -> Void
    ) async -> CrossTenantStop {
        var throttledInARow = 0
        for (index, target) in targets.enumerated() {
            if Task.isCancelled {
                await markRest(from: index, of: targets, report: report)
                return .cancelled
            }
            await report(index, .running)
            let outcome = await attempt(target, search: search)
            if Task.isCancelled {
                await markRest(from: index, of: targets, report: report)
                return .cancelled
            }
            await report(index, outcome)
            throttledInARow = outcome == .throttled ? throttledInARow + 1 : 0
            if throttledInARow >= Self.throttleLimit {
                await markRest(from: index + 1, of: targets, report: report)
                return .throttled
            }
        }
        return .finished
    }

    private func markRest(from start: Int, of targets: [CrossTenantTarget],
                          report: @Sendable (Int, CrossTenantOutcome) async -> Void) async {
        guard start < targets.count else { return }
        for index in start..<targets.count { await report(index, .notRun) }
    }

    /// The search raced against the budget. Whichever ends first wins and the other is
    /// cancelled. A search that ignores cancellation would hold the group open past the
    /// budget; every Graph call here goes through URLSession's async API, which does not.
    private func attempt(_ target: CrossTenantTarget,
                         search: @escaping @Sendable (CrossTenantTarget) async throws -> TenantHits) async -> CrossTenantOutcome {
        let budget = self.budget
        return await withTaskGroup(of: CrossTenantOutcome?.self) { group in
            group.addTask {
                do {
                    return .found(try await search(target))
                } catch let failure as CrossTenantFailure {
                    switch failure {
                    case .needsSignIn: return .needsSignIn
                    case .throttled: return .throttled
                    case .unavailable(let why): return .unavailable(why)
                    }
                } catch {
                    return Task.isCancelled ? nil : .unavailable("Couldn't search this organization.")
                }
            }
            group.addTask {
                do {
                    try await Task.sleep(for: budget)
                    return .timedOut
                } catch {
                    return nil
                }
            }
            var outcome: CrossTenantOutcome = .notRun
            while let next = await group.next() {
                if let next {
                    outcome = next
                    break
                }
            }
            group.cancelAll()
            return outcome
        }
    }
}

extension SavedSearch.Scope {
    /// The screens whose searches can run in every organization: read-only reads only.
    /// Conditional Access searches the policy list by name, which means little across
    /// customers, so it stays single-organization.
    public var runsAcrossTenants: Bool {
        switch self {
        case .devices, .people, .incidents, .email: return true
        case .conditionalAccess: return false
        }
    }
}
