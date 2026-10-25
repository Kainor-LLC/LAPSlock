import XCTest
@testable import SignInTriageKit

final class DemoSignInTriageProviderTests: XCTestCase {

    private let now = Date()

    func test_searchMatchesNameAddressAndSurname() async throws {
        let provider = DemoSignInTriageProvider(latency: .milliseconds(1), now: now)
        let byPrefix = try await provider.searchUsers(prefix: "ja")
        let bySurname = try await provider.searchUsers(prefix: "okafor")
        let byAddress = try await provider.searchUsers(prefix: "svc")
        let tooShort = try await provider.searchUsers(prefix: "j")
        XCTAssertEqual(byPrefix.map(\.id), ["u-jane"])
        XCTAssertEqual(bySurname.map(\.id), ["u-jane"])
        XCTAssertEqual(byAddress.map(\.id), ["u-svc"])
        XCTAssertTrue(tooShort.isEmpty)
    }

    func test_signInsFilterAndWindow() async throws {
        let provider = DemoSignInTriageProvider(latency: .milliseconds(1), now: now)
        let all = try await provider.signIns(SignInQuery(userPrincipalName: "jane.okafor@demo.example"))
        XCTAssertEqual(all.count, 5)
        XCTAssertEqual(all.first?.id, "s-j1", "newest first")
        let failures = try await provider.signIns(SignInQuery(userPrincipalName: "jane.okafor@demo.example", failuresOnly: true))
        XCTAssertEqual(failures.map(\.errorCode), [53000, 50074, 500121])
        let today = try await provider.signIns(SignInQuery(userPrincipalName: "JANE.OKAFOR@demo.example", last24Hours: true))
        XCTAssertEqual(today.count, 3)
    }

    func test_everyFixtureFailureCodeIsInTheGlossary() {
        let codes = Set(DemoSignInTriageProvider.signIns(now: now).map(\.errorCode))
        for code in codes {
            XCTAssertNotNil(ErrorGlossary.bundled.entry(for: code), "fixture code \(code) has no glossary entry")
        }
    }
}
