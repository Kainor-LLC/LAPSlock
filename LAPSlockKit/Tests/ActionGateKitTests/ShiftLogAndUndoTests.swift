import XCTest
@testable import ActionGateKit

final class ShiftLogAndUndoTests: XCTestCase {

    private var directory: URL!

    override func setUp() {
        super.setUp()
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("shiftlog-" + UUID().uuidString, isDirectory: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: directory)
        super.tearDown()
    }

    private func entry(_ n: Int, tenant: String = "t1") -> ShiftLogEntry {
        ShiftLogEntry(at: Date(timeIntervalSince1970: 1_800_000_000 + TimeInterval(n)), tenantId: tenant, actionId: "device.sync", actionTitle: "Sync", targetLabel: "DEV-\(n)", targetId: "id-\(n)", outcome: "requested", requestId: "r\(n)")
    }

    func test_fileLogPersistsAcrossInstancesNewestFirst() async {
        let log = FileShiftLog(directory: directory)
        await log.append(entry(1))
        await log.append(entry(2))
        let reopened = FileShiftLog(directory: directory)
        let entries = await reopened.entries(tenantId: "t1")
        XCTAssertEqual(entries.map(\.targetLabel), ["DEV-2", "DEV-1"])
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent(FileShiftLog.fileName).path))
    }

    func test_tenantsNeverSeeEachOther() async {
        let log = FileShiftLog(directory: directory)
        await log.append(entry(1, tenant: "t1"))
        await log.append(entry(2, tenant: "t2"))
        let t1 = await log.entries(tenantId: "t1")
        XCTAssertEqual(t1.map(\.targetLabel), ["DEV-1"])
        let export = await log.export(tenantId: "t2", now: Date(timeIntervalSince1970: 1_800_000_100))
        XCTAssertTrue(export.contains("Tenant t2"))
        XCTAssertTrue(export.contains("DEV-2"))
        XCTAssertFalse(export.contains("DEV-1"))
        await log.clear(tenantId: "t2")
        let t2 = await log.entries(tenantId: "t2")
        XCTAssertTrue(t2.isEmpty)
        let still = await log.entries(tenantId: "t1")
        XCTAssertEqual(still.count, 1, "clearing one tenant leaves the other")
    }

    func test_theCapDropsTheOldest() async {
        let log = FileShiftLog(directory: directory)
        for n in 0..<(FileShiftLog.cap + 5) { await log.append(entry(n)) }
        let entries = await log.entries(tenantId: "t1")
        XCTAssertEqual(entries.count, FileShiftLog.cap)
        XCTAssertEqual(entries.last?.targetLabel, "DEV-5")
    }

    func test_exportHeaderAndEmptyForm() async {
        let log = InMemoryShiftLog()
        let empty = await log.export(tenantId: "t1", now: Date(timeIntervalSince1970: 1_800_000_000))
        XCTAssertTrue(empty.hasPrefix("TenantKeep On-Call shift log\nTenant t1\nExported 2027-01-15 08:00:00Z"))
        XCTAssertTrue(empty.hasSuffix("No actions recorded."))
        XCTAssertFalse(empty.contains("\u{2014}"))
    }

    func test_pendingActionsCancelByTargetFromOutsideTheWaiter() async {
        let pending = PendingActions()
        let window = UndoWindow()
        await pending.register(window, for: "dev-1")
        // The waiter runs on its own, the way the screen's task does.
        let waiter = Task { await window.wait(seconds: 30, sleep: { _ in try await Task.sleep(for: .milliseconds(5)) }) }
        try? await Task.sleep(for: .milliseconds(30))
        let other = await pending.cancel("dev-2")
        XCTAssertFalse(other, "another device's screen closing cancels nothing here")
        let cancelled = await pending.cancel("dev-1")
        XCTAssertTrue(cancelled)
        let proceeded = await waiter.value
        XCTAssertFalse(proceeded, "a countdown cancelled from outside never sends")
        let left = await pending.count
        XCTAssertEqual(left, 0)
    }

    func test_pendingActionsCancelAll() async {
        let pending = PendingActions()
        let a = UndoWindow(), b = UndoWindow()
        await pending.register(a, for: "a")
        await pending.register(b, for: "b")
        await pending.cancelAll()
        let ac = await a.isCancelled, bc = await b.isCancelled
        XCTAssertTrue(ac && bc)
    }

    func test_sendNowEndsTheWaitAndACancelStillWins() async {
        let window = UndoWindow()
        let waiter = Task { await window.wait(seconds: 30, sleep: { _ in try await Task.sleep(for: .milliseconds(5)) }) }
        try? await Task.sleep(for: .milliseconds(30))
        await window.proceedNow()
        let sent = await waiter.value
        XCTAssertTrue(sent, "send now proceeds without waiting the full window")

        let cancelledFirst = UndoWindow()
        await cancelledFirst.cancel()
        await cancelledFirst.proceedNow()
        let result = await cancelledFirst.wait(seconds: 1, sleep: { _ in })
        XCTAssertFalse(result, "an undo that landed first is never overridden")
    }

    func test_undoWindowElapsesOrCancels() async {
        let elapsed = UndoWindow()
        let ok = await elapsed.wait(seconds: 1, sleep: { _ in })
        XCTAssertTrue(ok)
        let again = await elapsed.wait(seconds: 1, sleep: { _ in })
        XCTAssertFalse(again, "a window fires once")

        let cancelled = UndoWindow()
        let result = await cancelled.wait(seconds: 2, sleep: { _ in await cancelled.cancel() })
        XCTAssertFalse(result)
        let flag = await cancelled.isCancelled
        XCTAssertTrue(flag)
    }
}
