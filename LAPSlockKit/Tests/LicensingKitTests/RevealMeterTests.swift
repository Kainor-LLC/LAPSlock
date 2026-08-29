import XCTest
@testable import LicensingKit

@MainActor
final class RevealMeterTests: XCTestCase {

    private let hour: TimeInterval = 3600
    private let day: TimeInterval = 86_400

    private func makeMeter(
        free: Int = 5,
        window: TimeInterval = 30 * 86_400,
        grace: TimeInterval = 3600
    ) -> (RevealMeter, ManualMeterClock) {
        let clock = ManualMeterClock()
        let meter = RevealMeter(
            policy: RevealAllowancePolicy(
                freeRevealsPerWindow: free,
                window: window,
                repeatGrace: grace
            ),
            store: InMemoryRevealLedgerStore(),
            clock: clock
        )
        return (meter, clock)
    }

    // MARK: - the basic allowance

    func test_freshInstall_hasFullAllowance() {
        let (meter, _) = makeMeter()
        XCTAssertEqual(meter.remaining(isPro: false), 5)
        XCTAssertEqual(meter.check(deviceIdentifier: "a", isPro: false), .allowed(willCharge: true))
    }

    func test_eachDistinctDeviceCostsOne() {
        let (meter, clock) = makeMeter()
        for (i, id) in ["a", "b", "c", "d", "e"].enumerated() {
            XCTAssertTrue(meter.check(deviceIdentifier: id, isPro: false).isAllowed)
            meter.recordReveal(deviceIdentifier: id, isPro: false)
            XCTAssertEqual(meter.remaining(isPro: false), 4 - i)
            clock.advance(2 * hour)   // past the grace period each time
        }
        XCTAssertEqual(meter.remaining(isPro: false), 0)
    }

    func test_sixthDistinctDeviceIsBlocked() {
        let (meter, clock) = makeMeter()
        for id in ["a", "b", "c", "d", "e"] {
            meter.recordReveal(deviceIdentifier: id, isPro: false)
            clock.advance(2 * hour)
        }
        guard case .exhausted = meter.check(deviceIdentifier: "f", isPro: false) else {
            return XCTFail("expected exhausted")
        }
    }

    // MARK: - the repeat grace period

    func test_sameDeviceWithinGraceIsFree() {
        let (meter, clock) = makeMeter()
        meter.recordReveal(deviceIdentifier: "a", isPro: false)
        XCTAssertEqual(meter.remaining(isPro: false), 4)

        clock.advance(30 * 60)   // half an hour later, still at the same machine
        XCTAssertEqual(meter.check(deviceIdentifier: "a", isPro: false), .allowed(willCharge: false))
        meter.recordReveal(deviceIdentifier: "a", isPro: false)
        XCTAssertEqual(meter.remaining(isPro: false), 4, "a repeat inside the grace window must not charge again")
    }

    func test_sameDeviceAfterGraceChargesAgain() {
        let (meter, clock) = makeMeter()
        meter.recordReveal(deviceIdentifier: "a", isPro: false)
        clock.advance(2 * hour)
        XCTAssertEqual(meter.check(deviceIdentifier: "a", isPro: false), .allowed(willCharge: true))
        meter.recordReveal(deviceIdentifier: "a", isPro: false)
        XCTAssertEqual(meter.remaining(isPro: false), 3)
    }

    func test_graceDoesNotRescueAnExhaustedMeterForANewDevice() {
        let (meter, clock) = makeMeter()
        for id in ["a", "b", "c", "d", "e"] {
            meter.recordReveal(deviceIdentifier: id, isPro: false)
            clock.advance(2 * hour)
        }
        // The last device is outside its grace window now, and a new one is blocked.
        guard case .exhausted = meter.check(deviceIdentifier: "z", isPro: false) else {
            return XCTFail("expected exhausted")
        }
    }

    // MARK: - the rolling window

    func test_entriesAgeOutOfTheWindow() {
        let (meter, clock) = makeMeter()
        for id in ["a", "b", "c", "d", "e"] {
            meter.recordReveal(deviceIdentifier: id, isPro: false)
            clock.advance(2 * hour)
        }
        XCTAssertEqual(meter.remaining(isPro: false), 0)

        clock.advance(31 * day)
        XCTAssertEqual(meter.remaining(isPro: false), 5, "everything should have aged out")
        XCTAssertTrue(meter.check(deviceIdentifier: "f", isPro: false).isAllowed)
    }

    func test_windowIsRollingNotCalendar() {
        let (meter, clock) = makeMeter()
        meter.recordReveal(deviceIdentifier: "a", isPro: false)
        clock.advance(29 * day)
        meter.recordReveal(deviceIdentifier: "b", isPro: false)
        XCTAssertEqual(meter.remaining(isPro: false), 3)

        // Day 31: "a" has aged out but "b" has not.
        clock.advance(2 * day)
        XCTAssertEqual(meter.remaining(isPro: false), 4)
    }

    func test_exhaustedReportsWhenTheOldestEntryAgesOut() {
        let (meter, clock) = makeMeter()
        let start = clock.now
        for id in ["a", "b", "c", "d", "e"] {
            meter.recordReveal(deviceIdentifier: id, isPro: false)
            clock.advance(2 * hour)
        }
        guard case .exhausted(let next) = meter.check(deviceIdentifier: "f", isPro: false) else {
            return XCTFail("expected exhausted")
        }
        XCTAssertEqual(next.timeIntervalSince1970,
                       start.addingTimeInterval(30 * day).timeIntervalSince1970,
                       accuracy: 1)
    }

    // MARK: - nextAvailable, for the Settings readout

    func test_nextAvailableIsNilWhileAllowanceRemains() {
        let (meter, clock) = makeMeter()
        XCTAssertNil(meter.nextAvailable(isPro: false))
        meter.recordReveal(deviceIdentifier: "a", isPro: false)
        clock.advance(2 * hour)
        XCTAssertNil(meter.nextAvailable(isPro: false), "four reveals left is not exhausted")
    }

    func test_nextAvailableMatchesTheOldestEntryAgingOut() throws {
        let (meter, clock) = makeMeter()
        let start = clock.now
        for id in ["a", "b", "c", "d", "e"] {
            meter.recordReveal(deviceIdentifier: id, isPro: false)
            clock.advance(2 * hour)
        }
        let next = try XCTUnwrap(meter.nextAvailable(isPro: false))
        XCTAssertEqual(next.timeIntervalSince1970,
                       start.addingTimeInterval(30 * day).timeIntervalSince1970,
                       accuracy: 1)
    }

    func test_nextAvailableIsNilForPro() {
        let (meter, clock) = makeMeter()
        for id in ["a", "b", "c", "d", "e"] {
            meter.recordReveal(deviceIdentifier: id, isPro: false)
            clock.advance(2 * hour)
        }
        XCTAssertNil(meter.nextAvailable(isPro: true), "Pro has no allowance to run out")
    }

    // MARK: - Pro

    func test_proIsNeverMetered() {
        let (meter, clock) = makeMeter()
        for i in 0..<50 {
            XCTAssertEqual(meter.check(deviceIdentifier: "d\(i)", isPro: true), .unlimited)
            meter.recordReveal(deviceIdentifier: "d\(i)", isPro: true)
            clock.advance(2 * hour)
        }
        // Pro reveals must not consume free-tier credits, in case the subscription lapses.
        XCTAssertEqual(meter.remaining(isPro: false), 5)
    }

    // MARK: - persistence and privacy

    func test_ledgerSurvivesANewMeterOverTheSameStore() {
        let clock = ManualMeterClock()
        let store = InMemoryRevealLedgerStore()
        let policy = RevealAllowancePolicy()

        let first = RevealMeter(policy: policy, store: store, clock: clock)
        first.recordReveal(deviceIdentifier: "a", isPro: false)

        let second = RevealMeter(policy: policy, store: store, clock: clock)
        XCTAssertEqual(second.remaining(isPro: false), 4)
    }

    func test_deviceIdentifierIsNotStoredInTheClear() throws {
        let store = InMemoryRevealLedgerStore()
        let meter = RevealMeter(policy: .standard, store: store, clock: ManualMeterClock())
        meter.recordReveal(deviceIdentifier: "WS-4821-VERY-DISTINCTIVE", isPro: false)

        let ledger = try XCTUnwrap(store.load())
        let blob = String(decoding: try JSONEncoder().encode(ledger), as: UTF8.self)
        XCTAssertFalse(blob.contains("WS-4821-VERY-DISTINCTIVE"),
                       "the ledger must not hold a readable list of which devices were revealed")
        XCTAssertEqual(ledger.entries.count, 1)
    }

    func test_saltsDifferPerInstallSoHashesAreNotLinkable() {
        let a = RevealMeter(policy: .standard, store: InMemoryRevealLedgerStore(), clock: ManualMeterClock())
        let b = RevealMeter(policy: .standard, store: InMemoryRevealLedgerStore(), clock: ManualMeterClock())
        a.recordReveal(deviceIdentifier: "same-device", isPro: false)
        b.recordReveal(deviceIdentifier: "same-device", isPro: false)

        let storeA = try? a.debugLedger()
        let storeB = try? b.debugLedger()
        XCTAssertNotEqual(storeA?.entries.first?.deviceHash,
                          storeB?.entries.first?.deviceHash)
    }

    // MARK: - failure behaviour

    func test_meterFailsOpenWhenTheStoreThrows() {
        let meter = RevealMeter(policy: .standard, store: ThrowingStore(), clock: ManualMeterClock())
        // A broken store must never block a reveal. Losing the count is the acceptable
        // failure; blocking a legitimate user over an I/O error is not.
        XCTAssertEqual(meter.check(deviceIdentifier: "a", isPro: false), .allowed(willCharge: true))
        XCTAssertEqual(meter.remaining(isPro: false), 5)
    }

    func test_resetClearsTheLedger() {
        let (meter, clock) = makeMeter()
        for id in ["a", "b", "c"] {
            meter.recordReveal(deviceIdentifier: id, isPro: false)
            clock.advance(2 * hour)
        }
        XCTAssertEqual(meter.remaining(isPro: false), 2)
        meter.resetLedger()
        XCTAssertEqual(meter.remaining(isPro: false), 5)
    }
}

// MARK: - doubles

private struct ThrowingStore: RevealLedgerStore {
    struct Boom: Error {}
    func load() throws -> RevealLedger? { throw Boom() }
    func save(_ ledger: RevealLedger) throws { throw Boom() }
    func reset() throws { throw Boom() }
}

@MainActor
private extension RevealMeter {
    /// Test-only reach into the persisted ledger. Not part of the public surface.
    func debugLedger() throws -> RevealLedger? {
        try Mirror(reflecting: self).children
            .first { $0.label == "store" }
            .flatMap { $0.value as? RevealLedgerStore }?
            .load()
    }
}
