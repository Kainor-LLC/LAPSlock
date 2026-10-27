import XCTest
@testable import SavedSearchKit

final class CrossTenantRunTests: XCTestCase {

    private let targets = ["a", "b", "c", "d"].map { CrossTenantTarget(tenantId: $0, label: $0 + ".example") }

    /// Collects every report, in order, safely from the runner's tasks.
    private actor Recorder {
        var reports: [(Int, CrossTenantOutcome)] = []
        var searched: [String] = []
        func report(_ index: Int, _ outcome: CrossTenantOutcome) { reports.append((index, outcome)) }
        func searched(_ id: String) { searched.append(id) }
        func final(_ count: Int) -> [CrossTenantOutcome] {
            (0..<count).map { index in reports.last { $0.0 == index }?.1 ?? .waiting }
        }
    }

    private func run(_ runner: CrossTenantRunner = CrossTenantRunner(budget: .seconds(5)),
                     _ search: @escaping @Sendable (CrossTenantTarget) async throws -> TenantHits) async -> (CrossTenantStop, [CrossTenantOutcome], [String]) {
        let recorder = Recorder()
        let stop = await runner.run(targets, search: { target in
            await recorder.searched(target.tenantId)
            return try await search(target)
        }, report: { await recorder.report($0, $1) })
        return (stop, await recorder.final(targets.count), await recorder.searched)
    }

    func test_eachOrganizationIsSearchedOnceInOrder() async {
        let (stop, outcomes, searched) = await run { target in
            TenantHits(count: target.tenantId == "b" ? 2 : 0, top: target.tenantId == "b" ? ["one", "two"] : [])
        }
        XCTAssertEqual(stop, .finished)
        XCTAssertEqual(searched, ["a", "b", "c", "d"])
        XCTAssertEqual(outcomes[1], .found(TenantHits(count: 2, top: ["one", "two"])))
        XCTAssertEqual(outcomes[0], .found(TenantHits(count: 0, top: [])))
    }

    func test_oneAtATimeNeverInParallel() async {
        actor Gauge {
            var now = 0, most = 0
            func enter() { now += 1; most = max(most, now) }
            func leave() { now -= 1 }
        }
        let gauge = Gauge()
        _ = await run { _ in
            await gauge.enter()
            try? await Task.sleep(for: .milliseconds(10))
            await gauge.leave()
            return TenantHits(count: 0, top: [])
        }
        let most = await gauge.most
        XCTAssertEqual(most, 1)
    }

    func test_aSlowOrganizationTimesOutAndTheNextStillRuns() async {
        let runner = CrossTenantRunner(budget: .milliseconds(100))
        let (stop, outcomes, searched) = await run(runner) { target in
            if target.tenantId == "a" { try await Task.sleep(for: .seconds(30)) }
            return TenantHits(count: 1, top: ["x"])
        }
        XCTAssertEqual(stop, .finished)
        XCTAssertEqual(outcomes[0], .timedOut)
        XCTAssertEqual(outcomes[1], .found(TenantHits(count: 1, top: ["x"])))
        XCTAssertEqual(searched, ["a", "b", "c", "d"])
    }

    func test_signInNeededIsSkippedAndTheRunGoesOn() async {
        let (stop, outcomes, _) = await run { target in
            if target.tenantId == "b" { throw CrossTenantFailure.needsSignIn }
            return TenantHits(count: 0, top: [])
        }
        XCTAssertEqual(stop, .finished)
        XCTAssertEqual(outcomes[1], .needsSignIn)
        XCTAssertEqual(outcomes[2], .found(TenantHits(count: 0, top: [])))
    }

    func test_twoThrottledInARowStopsTheRest() async {
        let (stop, outcomes, searched) = await run { target in
            if target.tenantId == "a" || target.tenantId == "b" { throw CrossTenantFailure.throttled }
            return TenantHits(count: 0, top: [])
        }
        XCTAssertEqual(stop, .throttled)
        XCTAssertEqual(searched, ["a", "b"])
        XCTAssertEqual(outcomes, [.throttled, .throttled, .notRun, .notRun])
    }

    func test_throttlesThatAreNotInARowDoNotStopIt() async {
        let (stop, outcomes, _) = await run { target in
            if target.tenantId == "a" || target.tenantId == "c" { throw CrossTenantFailure.throttled }
            return TenantHits(count: 0, top: [])
        }
        XCTAssertEqual(stop, .finished)
        XCTAssertEqual(outcomes[3], .found(TenantHits(count: 0, top: [])))
    }

    func test_otherFailuresKeepTheirWords() async {
        let (_, outcomes, _) = await run { target in
            if target.tenantId == "a" { throw CrossTenantFailure.unavailable("No role here.") }
            if target.tenantId == "b" { throw URLError(.notConnectedToInternet) }
            return TenantHits(count: 0, top: [])
        }
        XCTAssertEqual(outcomes[0], .unavailable("No role here."))
        XCTAssertEqual(outcomes[1], .unavailable("Couldn't search this organization."))
    }

    func test_closingTheScreenStopsTheRun() async {
        let recorder = Recorder()
        let runner = CrossTenantRunner(budget: .seconds(30))
        let targets = self.targets
        let task = Task {
            await runner.run(targets, search: { target in
                await recorder.searched(target.tenantId)
                try await Task.sleep(for: .seconds(30))
                return TenantHits(count: 0, top: [])
            }, report: { await recorder.report($0, $1) })
        }
        try? await Task.sleep(for: .milliseconds(100))
        task.cancel()
        let stop = await task.value
        XCTAssertEqual(stop, .cancelled)
        let searched = await recorder.searched
        XCTAssertEqual(searched, ["a"])
        let outcomes = await recorder.final(targets.count)
        XCTAssertEqual(outcomes, [.notRun, .notRun, .notRun, .notRun])
    }

    func test_topHitsAreCappedAtThree() {
        XCTAssertEqual(TenantHits(count: 9, top: ["1", "2", "3", "4", "5"]).top, ["1", "2", "3"])
    }

    func test_onlyReadOnlySearchScreensRunAcrossOrganizations() {
        XCTAssertEqual(SavedSearch.Scope.allCases.filter(\.runsAcrossTenants), [.devices, .people, .incidents, .email])
    }
}
