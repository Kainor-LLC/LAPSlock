import XCTest
import AuthKit
@testable import ConditionalAccessKit

// The model is tested against Graph's actual shape, nulls and all, because a tolerant
// decoder that silently drops a condition is worse than one that fails loudly: the screen
// would show a policy as broader than it is.

final class ConditionalAccessPolicyTests: XCTestCase {

    private let graphJSON = #"""
    {"value":[
      {"id":"11111111-1111-4111-8111-111111111111","displayName":"Require MFA","state":"enabled",
       "createdDateTime":"2026-01-10T08:00:00Z","modifiedDateTime":"2026-10-20T08:15:30.1234567Z",
       "conditions":{"users":{"includeUsers":["All"],"excludeUsers":null,"includeGroups":["22222222-2222-4222-8222-222222222222"],"excludeGroups":[],"includeRoles":null,"excludeRoles":null},
                     "applications":{"includeApplications":["All"],"excludeApplications":null},
                     "platforms":null,"locations":null,"clientAppTypes":["all"],"signInRiskLevels":[],"userRiskLevels":null,"devices":null},
       "grantControls":{"operator":"OR","builtInControls":["mfa"],"customAuthenticationFactors":[],"termsOfUse":[],"authenticationStrength":null},
       "sessionControls":null},
      {"id":"33333333-3333-4333-8333-333333333333","displayName":"Future state","state":"somethingNew",
       "createdDateTime":"2026-10-01T00:00:00Z","modifiedDateTime":null,
       "conditions":{"users":{"includeUsers":["None"]},"applications":{"includeApplications":["Office365"]}},
       "grantControls":null,"sessionControls":{"signInFrequency":{"value":1,"type":"hours","isEnabled":true,"frequencyInterval":"timeBased"}}}
    ]}
    """#

    private struct Page: Decodable { let value: [ConditionalAccessPolicy] }

    private func decode() throws -> [ConditionalAccessPolicy] {
        try GraphClient.decoder.decode(Page.self, from: Data(graphJSON.utf8)).value
    }

    func test_graphPayloadDecodesWithNullsAndMissingKeys() throws {
        let policies = try decode()
        XCTAssertEqual(policies.count, 2)
        let mfa = policies[0]
        XCTAssertEqual(mfa.displayName, "Require MFA")
        XCTAssertEqual(mfa.state, .enabled)
        XCTAssertEqual(mfa.conditions.users.includeUsers, ["All"])
        XCTAssertEqual(mfa.conditions.users.excludeUsers, [])
        XCTAssertEqual(mfa.conditions.users.includeGroups, ["22222222-2222-4222-8222-222222222222"])
        XCTAssertEqual(mfa.conditions.users.includeRoles, [])
        XCTAssertEqual(mfa.conditions.applications.excludeApplications, [])
        XCTAssertNil(mfa.conditions.platforms)
        XCTAssertEqual(mfa.conditions.clientAppTypes, ["all"])
        XCTAssertEqual(mfa.conditions.userRiskLevels, [])
        XCTAssertEqual(mfa.grantControls?.builtInControls, ["mfa"])
        XCTAssertEqual(mfa.grantControls?.operator, "OR")
        XCTAssertNil(mfa.sessionControls)
        XCTAssertNotNil(mfa.modifiedDateTime)
    }

    func test_anUnknownStateDecodesAsUnknownRatherThanFailing() throws {
        let policies = try decode()
        XCTAssertEqual(policies[1].state, .unknown)
        XCTAssertEqual(policies[1].state.label, "Unknown")
    }

    func test_missingConditionBlocksAreEmpty() throws {
        let later = try decode()[1]
        XCTAssertEqual(later.conditions.users.excludeGroups, [])
        XCTAssertEqual(later.conditions.clientAppTypes, [])
        XCTAssertNil(later.grantControls)
        XCTAssertEqual(later.sessionControls?.signInFrequency?.value, 1)
        XCTAssertEqual(later.sessionControls?.signInFrequency?.type, "hours")
    }

    func test_lastChangedFallsBackToCreation() throws {
        let later = try decode()[1]
        XCTAssertNil(later.modifiedDateTime)
        XCTAssertEqual(later.lastChanged, later.createdDateTime)
    }

    func test_changedWithinWindow() {
        let now = Date()
        let recent = ConditionalAccessPolicy(id: "a", displayName: "a", state: .enabled, modifiedDateTime: now.addingTimeInterval(-6 * 86_400))
        let old = ConditionalAccessPolicy(id: "b", displayName: "b", state: .enabled, modifiedDateTime: now.addingTimeInterval(-8 * 86_400))
        let undated = ConditionalAccessPolicy(id: "c", displayName: "c", state: .enabled)
        XCTAssertTrue(recent.changed(withinDays: 7, now: now))
        XCTAssertFalse(old.changed(withinDays: 7, now: now))
        XCTAssertFalse(undated.changed(withinDays: 7, now: now))
    }

    func test_referencesCollectIdsAndSkipKeywords() {
        let policy = ConditionalAccessPolicy(
            id: "p", displayName: "p", state: .enabled,
            conditions: .init(
                users: .init(includeUsers: ["All"], excludeUsers: ["44444444-4444-4444-8444-444444444444"],
                             includeGroups: ["22222222-2222-4222-8222-222222222222"],
                             includeRoles: ["62e90394-69f5-4237-9190-012177145e10"]),
                applications: .init(includeApplications: ["Office365", "797f4846-ba00-4fd7-ba43-dac1f8f63013"]),
                locations: .init(includeLocations: ["All"], excludeLocations: ["AllTrusted", "55555555-5555-4555-8555-555555555555"])))
        let refs = policy.references
        XCTAssertEqual(refs.count, 5)
        XCTAssertTrue(refs.contains(DirectoryReference(kind: .user, id: "44444444-4444-4444-8444-444444444444")))
        XCTAssertTrue(refs.contains(DirectoryReference(kind: .group, id: "22222222-2222-4222-8222-222222222222")))
        XCTAssertTrue(refs.contains(DirectoryReference(kind: .role, id: "62e90394-69f5-4237-9190-012177145e10")))
        XCTAssertTrue(refs.contains(DirectoryReference(kind: .application, id: "797f4846-ba00-4fd7-ba43-dac1f8f63013")))
        XCTAssertTrue(refs.contains(DirectoryReference(kind: .location, id: "55555555-5555-4555-8555-555555555555")))
        XCTAssertFalse(refs.contains { $0.id == "All" || $0.id == "Office365" || $0.id == "AllTrusted" })
    }

    func test_vocabularyLabels() {
        XCTAssertEqual(ConditionalAccessVocabulary.userLabel("All"), "All users")
        XCTAssertEqual(ConditionalAccessVocabulary.userLabel("GuestsOrExternalUsers"), "Guests and external users")
        XCTAssertEqual(ConditionalAccessVocabulary.applicationLabel("Office365"), "Office 365")
        XCTAssertEqual(ConditionalAccessVocabulary.locationLabel("AllTrusted"), "All trusted locations")
        XCTAssertEqual(ConditionalAccessVocabulary.clientAppLabel("other"), "Other clients (legacy authentication)")
        XCTAssertEqual(ConditionalAccessVocabulary.grantControlLabel("block"), "Block access")
        XCTAssertEqual(ConditionalAccessVocabulary.platformLabel("macOS"), "macOS")
        XCTAssertEqual(ConditionalAccessVocabulary.userLabel("not-a-keyword"), "not-a-keyword")
    }

    func test_isDirectoryIdAndShortId() {
        XCTAssertTrue(ConditionalAccessVocabulary.isDirectoryId("62e90394-69f5-4237-9190-012177145e10"))
        XCTAssertFalse(ConditionalAccessVocabulary.isDirectoryId("All"))
        XCTAssertFalse(ConditionalAccessVocabulary.isDirectoryId("62e90394-69f5-4237-9190-012177145e10x"))
        XCTAssertEqual(ConditionalAccessVocabulary.shortId("62e90394-69f5-4237-9190-012177145e10"), "62e90394…")
        XCTAssertEqual(ConditionalAccessVocabulary.shortId("Office365"), "Office365")
    }

    func test_newestChangeFirstSortsDatedBeforeUndatedThenByName() {
        let now = Date()
        let a = ConditionalAccessPolicy(id: "a", displayName: "Zed", state: .enabled, modifiedDateTime: now.addingTimeInterval(-10))
        let b = ConditionalAccessPolicy(id: "b", displayName: "Alpha", state: .enabled, modifiedDateTime: now.addingTimeInterval(-100))
        let c = ConditionalAccessPolicy(id: "c", displayName: "Beta", state: .enabled)
        let d = ConditionalAccessPolicy(id: "d", displayName: "Aardvark", state: .enabled)
        let sorted = [c, b, d, a].sorted(by: ConditionalAccessService.newestChangeFirst)
        XCTAssertEqual(sorted.map(\.id), ["a", "b", "d", "c"])
    }

    func test_chunking() {
        XCTAssertEqual([1, 2, 3, 4, 5].chunked(2), [[1, 2], [3, 4], [5]])
        XCTAssertEqual([Int]().chunked(2), [])
        XCTAssertEqual([1, 2].chunked(5), [[1, 2]])
    }
}
