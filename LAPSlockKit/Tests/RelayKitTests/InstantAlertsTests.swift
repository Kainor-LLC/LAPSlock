import XCTest
@testable import RelayKit

final class InstantAlertsTests: XCTestCase {

    private let key = Data([0x04] + Array(repeating: 7, count: 64))

    private func body(_ object: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: object)
    }

    func test_theRegistrationCarriesTheTokenTheKeyAndTheAccounts() throws {
        let code = PairingCode(deviceToken: String(repeating: "a", count: 64), environment: "production", publicKey: key)
        let sent = InstantAlertsRegistration(code: code, breakGlass: ["bg@contoso.com"])
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(sent)) as? [String: Any]
        XCTAssertEqual(json?["deviceToken"] as? String, code.deviceToken)
        XCTAssertEqual(json?["environment"] as? String, "production")
        XCTAssertEqual(json?["publicKey"] as? String, code.publicKey)
        XCTAssertEqual(json?["breakGlass"] as? [String], ["bg@contoso.com"])
    }

    func test_registeredGivesTheSenderKeyToPin() {
        let answer = InstantAlertsAnswer.parse(status: 200, body: body([
            "tenantId": "AAAA-1", "label": "Contoso", "senderKey": Base64URL.encode(key),
            "breakGlassAccounts": 2, "breakGlassUpdated": true, "canConfigure": true]))
        XCTAssertEqual(answer, .registered(tenantId: "aaaa-1", label: "Contoso", senderKey: key, breakGlassAccounts: 2, canConfigure: true))
    }

    func test_aMalformedSenderKeyIsAFailureNotAPin() {
        let answer = InstantAlertsAnswer.parse(status: 200, body: body(["tenantId": "t", "senderKey": "AAAA"]))
        XCTAssertEqual(answer, .failed(200))
    }

    func test_approvalIsOnlyEverMicrosoftsOwnPage() {
        let good = "https://login.microsoftonline.com/t/adminconsent?client_id=c"
        XCTAssertEqual(InstantAlertsAnswer.parse(status: 409, body: body(["error": "approval", "approvalUrl": good])), .needsApproval(URL(string: good)!))
        XCTAssertEqual(InstantAlertsAnswer.parse(status: 409, body: body(["error": "approval", "approvalUrl": "https://evil.example/consent"])), .failed(409))
    }

    func test_theOtherAnswers() {
        XCTAssertEqual(InstantAlertsAnswer.parse(status: 403, body: Data()), .notPermitted)
        XCTAssertEqual(InstantAlertsAnswer.parse(status: 400, body: body(["error": "account"])), .accountNotFound)
        XCTAssertEqual(InstantAlertsAnswer.parse(status: 400, body: body(["error": "malformed"])), .failed(400))
        XCTAssertEqual(InstantAlertsAnswer.parse(status: 401, body: Data()), .failed(401))
    }
}
