import XCTest
@testable import ActionGateKit

final class UndoCountdownTests: XCTestCase {

    /// Collects what a countdown reports, from any task.
    private actor Seen {
        var values: [Int] = []
        func add(_ value: Int) { values.append(value) }
    }

    private static let slow: @Sendable (TimeInterval) async throws -> Void = { _ in try await Task.sleep(for: .milliseconds(5)) }

    func test_neverShorterThanTenSeconds() {
        XCTAssertEqual(UndoCountdown(key: "k", seconds: 3).seconds, 10, "a shorter request still waits the standard ten")
        XCTAssertEqual(UndoCountdown(key: "k", seconds: 0).seconds, 10)
        XCTAssertEqual(UndoCountdown(key: "k", seconds: 30).seconds, 30, "longer is allowed for a slow automated pass")
        XCTAssertEqual(UndoCountdown(key: "k").seconds, UndoWindow.standardSeconds)
    }

    func test_registeredForTheWholeWaitAndRemovedAfter() async {
        let pending = PendingActions()
        let seen = Seen()
        let countdown = UndoCountdown(key: "dev-1", pending: pending)
        let proceed = await countdown.run(sleep: { _ in await seen.add(await pending.count) }, tick: { _ in })
        XCTAssertTrue(proceed, "a countdown nobody touched sends")
        let counts = await seen.values
        XCTAssertEqual(counts.count, 40, "ten seconds in quarter steps")
        XCTAssertTrue(counts.allSatisfy { $0 == 1 }, "registered at every step of the wait")
        let left = await pending.count
        XCTAssertEqual(left, 0, "removed once it ends")
    }

    func test_ticksTheWholeSecondsLeft() async {
        let seen = Seen()
        let countdown = UndoCountdown(key: "k", pending: PendingActions())
        _ = await countdown.run(sleep: { _ in }, tick: { await seen.add($0) })
        let ticks = await seen.values
        XCTAssertEqual(ticks, [10, 9, 8, 7, 6, 5, 4, 3, 2, 1], "the full count first, once a second, never 0")
    }

    func test_cancelThroughPendingActionsNeverSends() async {
        let pending = PendingActions()
        let countdown = UndoCountdown(key: "dev-1", pending: pending)
        let waiter = Task { await countdown.run(sleep: Self.slow, tick: { _ in }) }
        try? await Task.sleep(for: .milliseconds(30))
        let other = await pending.cancel("dev-2")
        XCTAssertFalse(other)
        let cancelled = await pending.cancel("dev-1")
        XCTAssertTrue(cancelled, "the screen closing finds the countdown by its key")
        let proceeded = await waiter.value
        XCTAssertFalse(proceeded)
        let left = await pending.count
        XCTAssertEqual(left, 0)
    }

    func test_cancelAllStopsEveryCountdown() async {
        let pending = PendingActions()
        let a = UndoCountdown(key: "a", pending: pending), b = UndoCountdown(key: "b", pending: pending)
        let first = Task { await a.run(sleep: Self.slow, tick: { _ in }) }
        let second = Task { await b.run(sleep: Self.slow, tick: { _ in }) }
        try? await Task.sleep(for: .milliseconds(30))
        await pending.cancelAll()
        let results = await [first.value, second.value]
        XCTAssertEqual(results, [false, false], "leaving the foreground cancels everything waiting")
        let left = await pending.count
        XCTAssertEqual(left, 0)
    }

    func test_undoAndSendNow() async {
        let undone = UndoCountdown(key: "u", pending: PendingActions())
        let undoWaiter = Task { await undone.run(sleep: Self.slow, tick: { _ in }) }
        try? await Task.sleep(for: .milliseconds(30))
        await undone.undo()
        let undoResult = await undoWaiter.value
        XCTAssertFalse(undoResult)

        let pending = PendingActions()
        let sure = UndoCountdown(key: "s", pending: pending)
        let sendWaiter = Task { await sure.run(sleep: Self.slow, tick: { _ in }) }
        try? await Task.sleep(for: .milliseconds(30))
        await sure.sendNow()
        let sent = await sendWaiter.value
        XCTAssertTrue(sent, "send now proceeds without waiting the full window")
        let left = await pending.count
        XCTAssertEqual(left, 0, "removed after send now too")
    }

    func test_anUndoBeatsSendNow() async {
        let countdown = UndoCountdown(key: "k", pending: PendingActions())
        await countdown.undo()
        await countdown.sendNow()
        let result = await countdown.run(sleep: { _ in }, tick: { _ in })
        XCTAssertFalse(result, "an undo that landed first is never overridden")
    }
}
