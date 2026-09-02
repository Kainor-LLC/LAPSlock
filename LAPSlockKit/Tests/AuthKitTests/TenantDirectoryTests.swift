import XCTest
@testable import AuthKit

/// Domain to tenant GUID resolution for the MSP switcher. The network call is not tested;
/// the parsing and the input validation are, because those are the parts that can be wrong
/// in a way nobody notices.
final class TenantDirectoryTests: XCTestCase {

    private let tenant = "4470dc21-a4b7-4729-a232-56d4c0eedf73"

    func test_theTenantIsExtractedFromAnIssuer() {
        XCTAssertEqual(
            TenantDirectory.tenantId(fromIssuer: "https://login.microsoftonline.com/\(tenant)/v2.0"),
            tenant)
    }

    func test_anUppercaseIssuerIsLowercased() {
        XCTAssertEqual(
            TenantDirectory.tenantId(fromIssuer: "https://login.microsoftonline.com/\(tenant.uppercased())/v2.0"),
            tenant)
    }

    func test_anIssuerWithNoGUIDYieldsNothing() {
        // Extraction is by GUID shape, so a change to the surrounding URL structure yields
        // nothing rather than a confidently wrong value.
        XCTAssertNil(TenantDirectory.tenantId(fromIssuer: "https://login.microsoftonline.com/common/v2.0"))
        XCTAssertNil(TenantDirectory.tenantId(fromIssuer: ""))
    }

    func test_theTenantIsExtractedFromADiscoveryDocument() throws {
        let json = #"{"issuer":"https://login.microsoftonline.com/\#(tenant)/v2.0","authorization_endpoint":"x"}"#
        let data = try XCTUnwrap(json.data(using: .utf8))
        XCTAssertEqual(TenantDirectory.tenantId(fromDiscovery: data), tenant)
    }

    func test_junkDiscoveryYieldsNothing() throws {
        XCTAssertNil(TenantDirectory.tenantId(fromDiscovery: Data()))
        XCTAssertNil(TenantDirectory.tenantId(fromDiscovery: try XCTUnwrap("{}".data(using: .utf8))))
        XCTAssertNil(TenantDirectory.tenantId(fromDiscovery: try XCTUnwrap(#"{"issuer":42}"#.data(using: .utf8))))
    }

    func test_plausibleDomainsAreAccepted() {
        for domain in ["contoso.com", "a-b.co.uk", "sub.domain.example.org", "x1.io"] {
            XCTAssertEqual(TenantDirectory.sanitizedDomain(domain), domain, "\(domain) should be accepted")
        }
    }

    func test_pathTraversalAndJunkAreRejected() {
        // The value is interpolated into a URL path, so a slash or a dot-dot here would be a
        // traversal attempt against the discovery endpoint.
        for bad in ["../../evil", "contoso.com/../x", "contoso .com", "contoso", "", ".com",
                    "contoso..com", "-contoso.com", "contoso.com-", "http://contoso.com",
                    "contoso.com?x=1", "contoso.com#frag"] {
            XCTAssertNil(TenantDirectory.sanitizedDomain(bad), "\(bad) should be rejected")
        }
    }

    func test_aGUIDResolvesWithoutANetworkCall() async throws {
        // Somebody who already has the tenant ID should not need a round trip. The session
        // passed here would fail the test if it were used, because the URL is unreachable.
        let resolved = try await TenantDirectory.resolve(tenant.uppercased(), session: Self.failingSession)
        XCTAssertEqual(resolved, tenant)
    }

    func test_malformedInputFailsWithoutANetworkCall() async {
        do {
            _ = try await TenantDirectory.resolve("../../evil", session: Self.failingSession)
            XCTFail("expected malformedInput")
        } catch {
            XCTAssertEqual(error as? TenantDirectoryError, .malformedInput)
        }
    }

    /// A session pointed at nothing. If resolution reaches the network when it should not,
    /// the test fails rather than quietly succeeding.
    private static let failingSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = []
        config.timeoutIntervalForRequest = 0.001
        return URLSession(configuration: config)
    }()
}
