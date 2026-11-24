import XCTest
@testable import ManagedConfigKit

final class ManagedConfigurationTests: XCTestCase {

    func test_noPolicyIsTheSafeDefault() {
        let config = ManagedConfiguration.parse(nil)
        XCTAssertFalse(config.isManaged)
        XCTAssertEqual(config.confirmationLevel, .standard)
        XCTAssertEqual(config.groupWriteScope, .tagged)
        XCTAssertEqual(config.groupWriteAdministrativeUnit, "Helpdesk Managed Groups")
        XCTAssertNil(config.tenantPin)
        XCTAssertFalse(config.appLockRequired)
        XCTAssertTrue(config.disabledIds.isEmpty)
        XCTAssertEqual(ManagedConfiguration.parse([:]), config)
    }

    func test_everyKeyParsedFromPlistTypes() {
        let config = ManagedConfiguration.parse([
            "modules.disabled": ["deviceActions", "notifications"],
            "confirmation.level": "Strict",
            "groupWrite.scope": "none",
            "groupWrite.administrativeUnit": "HD Groups",
            "groupWrite.prefix": "HD-",
            "tenant.pin": "4470DC21-A4B7-4729-A232-56D4C0EEDF73",
            "appLock.required": true,
            "breakGlass.upns": ["BG1@contoso.com", "bg2@contoso.com"]
        ])
        XCTAssertTrue(config.isManaged)
        XCTAssertTrue(config.problems.isEmpty, "\(config.problems)")
        XCTAssertEqual(config.disabledIds, ["deviceActions", "notifications"])
        XCTAssertTrue(config.isDisabled("notifications"))
        XCTAssertEqual(config.confirmationLevel, .strict)
        XCTAssertEqual(config.groupWriteScope, .none)
        XCTAssertEqual(config.groupWriteAdministrativeUnit, "HD Groups")
        XCTAssertEqual(config.groupWritePrefix, "HD-")
        XCTAssertEqual(config.tenantPin, "4470dc21-a4b7-4729-a232-56d4c0eedf73")
        XCTAssertTrue(config.appLockRequired)
        XCTAssertEqual(config.breakGlassUPNs, ["bg1@contoso.com", "bg2@contoso.com"])
    }

    func test_keyValueDesignerStringsAreAcceptedToo() {
        let config = ManagedConfiguration.parse([
            "modules.disabled": " deviceActions , groupWrites ",
            "appLock.required": "TRUE",
            "breakGlass.upns": "bg@contoso.com"
        ])
        XCTAssertEqual(config.disabledIds, ["deviceActions", "groupWrites"])
        XCTAssertTrue(config.appLockRequired)
        XCTAssertEqual(config.breakGlassUPNs, ["bg@contoso.com"])
        XCTAssertEqual(ManagedConfiguration.parse(["appLock.required": NSNumber(value: 1)]).appLockRequired, true)
    }

    func test_badValuesAreIgnoredAndReportedNeverGuessed() {
        let config = ManagedConfiguration.parse([
            "confirmation.level": "paranoid",
            "groupWrite.scope": 3,
            "tenant.pin": "contoso.com",
            "appLock.required": "sometimes",
            "modules.disabled": ["deviceActions", "wipeEverything"],
            "breakGlass.upns": 42,
            "groupWrite.prefix": "",
            "lapslock.typo": true
        ])
        XCTAssertEqual(config.confirmationLevel, .standard)
        XCTAssertEqual(config.groupWriteScope, .tagged)
        XCTAssertNil(config.tenantPin)
        XCTAssertFalse(config.appLockRequired)
        XCTAssertEqual(config.disabledIds, ["deviceActions"], "known ids still apply")
        XCTAssertNil(config.groupWritePrefix)
        let problems = config.problems.joined(separator: "\n")
        for fragment in ["confirmation.level", "groupWrite.scope", "tenant.pin", "appLock.required", "wipeEverything", "breakGlass.upns", "groupWrite.prefix", "lapslock.typo: not a TenantKeep setting"] {
            XCTAssertTrue(problems.contains(fragment), fragment)
        }
    }

    func test_tenantPinNeedsTheExactGuidShape() {
        XCTAssertNotNil(ManagedConfiguration.canonicalTenantId("4470dc21-a4b7-4729-a232-56d4c0eedf73"))
        XCTAssertNil(ManagedConfiguration.canonicalTenantId("{4470dc21-a4b7-4729-a232-56d4c0eedf73}"))
        XCTAssertNil(ManagedConfiguration.canonicalTenantId("4470dc21a4b74729a23256d4c0eedf73"))
        XCTAssertNil(ManagedConfiguration.canonicalTenantId("zzzzzzzz-a4b7-4729-a232-56d4c0eedf73"))
    }

    func test_summaryLinesReadAsPlainWords() {
        let config = ManagedConfiguration.parse([
            "modules.disabled": ["security", "deviceActions"],
            "confirmation.level": "strict",
            "appLock.required": true,
            "tenant.pin": "4470dc21-a4b7-4729-a232-56d4c0eedf73",
            "breakGlass.upns": ["a@b.com"]
        ])
        XCTAssertEqual(config.summaryLines, [
            "Turned off: Device actions, Security",
            "Every action asks for extra confirmation",
            "Limited to one organization",
            "App lock required",
            "1 break-glass account watched"
        ])
        for line in config.summaryLines { XCTAssertFalse(line.contains("\u{2014}")) }
    }

    func test_destructiveActionsCanBeSwitchedOffAlone() {
        let config = ManagedConfiguration.parse(["modules.disabled": ["destructiveActions"]])
        XCTAssertTrue(config.isDisabled("destructiveActions"))
        XCTAssertFalse(config.isDisabled("deviceActions"))
        XCTAssertEqual(config.summaryLines, ["Turned off: Retire and wipe"])
    }

    func test_intuneOwnKeysAreNotReportedAsTypos() {
        let config = ManagedConfiguration.parse(["IntuneMAMUPN": "x@y.com"])
        XCTAssertTrue(config.problems.isEmpty)
    }

    func testTheOldSignInTriageIdStillTurnsPeopleOff() {
        let config = ManagedConfiguration.parse(["modules.disabled": ["signInTriage"]])
        XCTAssertTrue(config.isDisabled("people"))
        XCTAssertTrue(config.problems.isEmpty)
    }

    // MARK: - Intune's app channel

    /// A phone that is not enrolled gets its settings through Intune's app channel, as a
    /// list of policies. The organization-wide default goes under the policies targeted at
    /// the person, Intune's bookkeeping keys are dropped, and so is anything that is not a
    /// plain value.
    func test_appChannelPoliciesFlattenWithTargetedOverTheDefault() {
        let flat = ManagedConfiguration.flatten([
            ["confirmation.level": "strict", "watch.allowed": "false", "__PolicyId": "b"],
            ["__IsDefault": true, "confirmation.level": "standard", "appLock.required": "true"],
            ["watch.allowed": "true", "odd": ["nested": 1]]
        ])
        XCTAssertEqual(flat["confirmation.level"] as? String, "strict")
        XCTAssertEqual(flat["appLock.required"] as? String, "true", "the default still fills what nobody else set")
        XCTAssertEqual(flat["watch.allowed"] as? String, "true", "a later targeted policy is over an earlier one")
        XCTAssertNil(flat["__PolicyId"])
        XCTAssertNil(flat["__IsDefault"])
        XCTAssertNil(flat["odd"])
        XCTAssertTrue(ManagedConfiguration.flatten(nil).isEmpty)
        XCTAssertTrue(ManagedConfiguration.flatten([]).isEmpty)
    }

    /// Both channels feed one configuration. Where both set a key, the app channel's value
    /// is the one used; each fills what the other left out; neither alone still works.
    func test_theAppChannelIsReadOverTheDeviceChannel() {
        let both = ManagedConfiguration.parse(
            device: ["confirmation.level": "standard", "appLock.required": true],
            appChannel: ["confirmation.level": "strict", "tenant.pin": "4470DC21-A4B7-4729-A232-56D4C0EEDF73"])
        XCTAssertEqual(both.confirmationLevel, .strict)
        XCTAssertTrue(both.appLockRequired)
        XCTAssertEqual(both.tenantPin, "4470dc21-a4b7-4729-a232-56d4c0eedf73")
        XCTAssertTrue(both.problems.isEmpty)

        XCTAssertEqual(ManagedConfiguration.parse(device: nil, appChannel: ["appLock.required": "true"]).appLockRequired, true)
        XCTAssertEqual(ManagedConfiguration.parse(device: ["appLock.required": true], appChannel: nil).appLockRequired, true)
        XCTAssertEqual(ManagedConfiguration.parse(device: nil, appChannel: nil), ManagedConfiguration())
    }

    /// Under an Intune app protection policy the watch is sent nothing unless the
    /// organization allows it. Off is the default, and a value that is not a boolean is
    /// reported and leaves it off.
    func test_theWatchIsAllowedOnlyWhenTheOrganizationSaysSo() {
        XCTAssertFalse(ManagedConfiguration().watchAllowed)
        let allowed = ManagedConfiguration.parse(["watch.allowed": "true"])
        XCTAssertTrue(allowed.watchAllowed)
        XCTAssertEqual(allowed.summaryLines, ["Apple Watch allowed under app protection"])
        let kept = ManagedConfiguration.parse(["watch.allowed": false])
        XCTAssertFalse(kept.watchAllowed)
        XCTAssertEqual(kept.summaryLines, ["Apple Watch kept empty under app protection"])
        let bad = ManagedConfiguration.parse(["watch.allowed": "maybe"])
        XCTAssertFalse(bad.watchAllowed)
        XCTAssertEqual(bad.problems, ["watch.allowed: expected true or false"])
    }
}
