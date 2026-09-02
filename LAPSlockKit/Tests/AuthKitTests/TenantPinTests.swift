import XCTest
@testable import AuthKit

/// The §3.3 tenant guard.
///
/// This is the single most security-relevant comparison in the auth path: it is what stops a
/// token issued for one organization being used against another. It was moved out of
/// `MSALAuthManager` into `TenantPin` precisely so it could be tested — MSALResult cannot be
/// constructed on macOS, so the comparison was previously uncovered.
final class TenantPinTests: XCTestCase {

    private let tenant = "4470dc21-a4b7-4729-a232-56d4c0eedf73"
    private let other  = "11111111-2222-3333-4444-555555555555"

    func test_aMatchingTenantPasses() throws {
        let pin = try XCTUnwrap(TenantPin(expected: tenant))
        XCTAssertNoThrow(try pin.validate(returnedTenantId: tenant))
    }

    func test_aDifferentTenantIsRefused() throws {
        let pin = try XCTUnwrap(TenantPin(expected: tenant))
        XCTAssertThrowsError(try pin.validate(returnedTenantId: other)) { error in
            XCTAssertEqual(error as? AuthError, .tenantMismatch)
        }
    }

    func test_aMissingTenantIsRefusedRatherThanWaved_through() throws {
        // A token that will not say which tenant it is for is exactly what this guard exists
        // to refuse. Treating nil as "fine" would be the classic way to defeat it.
        let pin = try XCTUnwrap(TenantPin(expected: tenant))
        for absent in [nil, "", "   "] as [String?] {
            XCTAssertThrowsError(try pin.validate(returnedTenantId: absent)) { error in
                XCTAssertEqual(error as? AuthError, .tenantMismatch)
            }
        }
    }

    func test_comparisonIsCaseAndWhitespaceInsensitive() throws {
        let pin = try XCTUnwrap(TenantPin(expected: tenant.uppercased()))
        XCTAssertEqual(pin.expected, tenant, "the pin stores the lowercase form")
        XCTAssertNoThrow(try pin.validate(returnedTenantId: " \(tenant.uppercased()) "))
    }

    func test_onlyCanonicalGUIDsCanBePinned() {
        // Several spellings of one directory would mean several pins each claiming to mean
        // the same thing. Same reasoning as the server's TryParseExact.
        XCTAssertNil(TenantPin(expected: "{\(tenant)}"))
        XCTAssertNil(TenantPin(expected: tenant.replacingOccurrences(of: "-", with: "")))
        XCTAssertNil(TenantPin(expected: "common"))
        XCTAssertNil(TenantPin(expected: "organizations"))
        XCTAssertNil(TenantPin(expected: ""))
        XCTAssertNil(TenantPin(expected: "../../evil"))
    }

    func test_theAuthorityURLIsBuiltFromThePinnedTenant() throws {
        let pin = try XCTUnwrap(TenantPin(expected: tenant))
        XCTAssertEqual(pin.authorityURL.absoluteString, "https://login.microsoftonline.com/\(tenant)")
        // Never /common: asking a multi-tenant authority and then accepting whatever comes
        // back is the shape of the bug this whole type prevents.
        XCTAssertFalse(pin.authorityURL.absoluteString.contains("common"))
    }
}
