import XCTest
import CryptoKit
@testable import RelayKit

final class RelayTests: XCTestCase {

    private let tenant = "c0ffee00-1111-2222-3333-444455556666"
    private let otherTenant = "c0ffee00-9999-2222-3333-444455556666"
    private let token = Data((0..<32).map { UInt8($0) })

    private func alert(_ tenant: String, id: String = UUID().uuidString, link: String? = "tenantkeep://people") -> RelayAlert {
        RelayAlert(v: 1, id: id, at: 1_800_000_000, tenant: tenant, kind: "breakGlassSignIn", title: "Break-glass sign-in", body: "bg-admin signed in", link: link)
    }

    private func pairedPhone() throws -> (RelayPhone, PairingCode, P256.KeyAgreement.PrivateKey) {
        let phone = RelayPhone(store: MemoryRelayStateStore())
        try phone.turnOn(environment: "sandbox")
        try phone.setDeviceToken(token)
        let sender = P256.KeyAgreement.PrivateKey()
        try phone.pin(SenderPin(tenant: tenant, senderKey: sender.publicKey.x963Representation))
        return (phone, try phone.pairingCode(), sender)
    }

    func testPairingCodesRoundTripAndRejectNonsense() throws {
        let (_, code, sender) = try pairedPhone()
        XCTAssertTrue(code.text.hasPrefix("tkrelay1:"))
        XCTAssertEqual(PairingCode.parse(code.text), code)
        XCTAssertEqual(code.deviceToken.count, 64)
        let pin = SenderPin(tenant: tenant.uppercased(), senderKey: sender.publicKey.x963Representation)
        XCTAssertEqual(SenderPin.parse(pin.text)?.tenant, tenant)
        XCTAssertNil(SenderPin.parse("tksender1:not-base64!!"))
        XCTAssertNil(SenderPin.parse(SenderPin(tenant: "not-a-guid", senderKey: sender.publicKey.x963Representation).text))
        XCTAssertNil(SenderPin.parse(SenderPin(tenant: tenant, senderKey: Data([1, 2, 3])).text), "not a P-256 key")
        XCTAssertNil(PairingCode.parse("hello"))
    }

    func testAnAlertFromThePinnedSenderOpens() throws {
        let (phone, code, sender) = try pairedPhone()
        let sent = alert(tenant)
        let env = try RelayTestSender.seal(sent, to: Base64URL.decode(code.publicKey)!, deviceToken: code.deviceToken, sender: sender)
        XCTAssertEqual(try phone.open(enc: env.enc, ct: env.ct), sent)
    }

    func testAnImpostorSenderIsRefused() throws {
        let (phone, code, _) = try pairedPhone()
        let env = try RelayTestSender.seal(alert(tenant), to: Base64URL.decode(code.publicKey)!, deviceToken: code.deviceToken, sender: P256.KeyAgreement.PrivateKey())
        XCTAssertThrowsError(try phone.open(enc: env.enc, ct: env.ct)) { XCTAssertEqual($0 as? RelayError, .verificationFailed) }
    }

    func testAnotherPhonesCiphertextIsRefused() throws {
        let (phone, code, sender) = try pairedPhone()
        let env = try RelayTestSender.seal(alert(tenant), to: Base64URL.decode(code.publicKey)!, deviceToken: String(repeating: "ab", count: 32), sender: sender)
        XCTAssertThrowsError(try phone.open(enc: env.enc, ct: env.ct))
    }

    func testASenderPinnedForOneTenantCannotSpeakForAnother() throws {
        let (phone, code, sender) = try pairedPhone()
        let env = try RelayTestSender.seal(alert(otherTenant), to: Base64URL.decode(code.publicKey)!, deviceToken: code.deviceToken, sender: sender)
        XCTAssertThrowsError(try phone.open(enc: env.enc, ct: env.ct)) { XCTAssertEqual($0 as? RelayError, .verificationFailed) }
    }

    func testARepeatIsDroppedForADay() throws {
        let (phone, code, sender) = try pairedPhone()
        let seen = RelaySeenStore(url: nil)
        let env = try RelayTestSender.seal(alert(tenant, id: "6b1d2c4e-0f8a-4f3e-9d6b-2a7c1e5f9b30"), to: Base64URL.decode(code.publicKey)!, deviceToken: code.deviceToken, sender: sender)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        XCTAssertNoThrow(try phone.open(enc: env.enc, ct: env.ct, seen: seen, now: now))
        XCTAssertThrowsError(try phone.open(enc: env.enc, ct: env.ct, seen: seen, now: now.addingTimeInterval(3600))) { XCTAssertEqual($0 as? RelayError, .duplicate) }
        XCTAssertNoThrow(try phone.open(enc: env.enc, ct: env.ct, seen: seen, now: now.addingTimeInterval(25 * 3600)))
    }

    func testOnlyTenantKeepLinksSurvive() throws {
        let (phone, code, sender) = try pairedPhone()
        let env = try RelayTestSender.seal(alert(tenant, link: "https://evil.example/login"), to: Base64URL.decode(code.publicKey)!, deviceToken: code.deviceToken, sender: sender)
        XCTAssertNil(try phone.open(enc: env.enc, ct: env.ct).link)
    }

    func testTurningOffMeansNothingOpens() throws {
        let (phone, code, sender) = try pairedPhone()
        let env = try RelayTestSender.seal(alert(tenant), to: Base64URL.decode(code.publicKey)!, deviceToken: code.deviceToken, sender: sender)
        try phone.turnOff()
        XCTAssertFalse(phone.isOn)
        XCTAssertThrowsError(try phone.open(enc: env.enc, ct: env.ct)) { XCTAssertEqual($0 as? RelayError, .notPaired) }
        // Turning on again makes a new key: the old envelope still cannot be read.
        try phone.turnOn(environment: "sandbox")
        try phone.setDeviceToken(token)
        try phone.pin(SenderPin(tenant: tenant, senderKey: sender.publicKey.x963Representation))
        XCTAssertThrowsError(try phone.open(enc: env.enc, ct: env.ct))
    }

    func testOversizedTextIsRefused() throws {
        let (phone, code, sender) = try pairedPhone()
        var big = alert(tenant)
        big.body = String(repeating: "x", count: 401)
        let env = try RelayTestSender.seal(big, to: Base64URL.decode(code.publicKey)!, deviceToken: code.deviceToken, sender: sender)
        XCTAssertThrowsError(try phone.open(enc: env.enc, ct: env.ct))
    }
    /// The shipping sender is .NET. This envelope was sealed by relay/sender/Hpke.cs with the
    /// keys below, so a change on either side that breaks interop fails here.
    func testAnEnvelopeSealedByTheDotNetSenderOpens() throws {
        let recipientRaw = Data(hex: "6694AC1378D1D77CF13F935FE8BB30549FDD06968561D4BE0CB1BF1DBA262EA8")
        let state = RelayState(keyReference: recipientRaw, enclave: false, deviceToken: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                               environment: "production", pins: [tenant: "BK1QDJ_NVMCncaG5FtNPt8fgNc3aGxmbETD05OGvdInEDPe-QaLTPkhu90fNN-jCwAa1uZGyNy5etCFQM_ru_MY"])
        let phone = RelayPhone(store: MemoryRelayStateStore(state))
        let opened = try phone.open(enc: "BMPNpvOaBH4ao08KdW0pxazZZGwvYZkuiI-DqdoGXl5jUkRArypiijJ-9OlLA41NICnTfvRlE_OZrjm9vVUwo2M", ct: "H6vWTd-FN95vB-4sunP3k51hFOJNttLZ5rko9nsmi57GZfzSeZN5UTb6be0hKos81dLiKWpMLfFeJiFSTYjuHHdiPwp2onV4YeBX6HD0goKwjOFdXHANkdzJU-L0lBuc97r6B_p3x3e2QYFxuzoRLBPWOutaPRnKKcO3eTNjNwfC4NycXZ66hy4IuhH5kYO-yx5GP5MZg-sxg0edHLvZOsGkhuczK_Ev4_dU7MNSz3oHhZtuGvSRDlLWuhFPM_zwhAsWx0fifBz8BUtLY7ZunDz6QRPRJ3GvkFEoaVe3E3jCeKmiQzC0K1hlf54Kp0eOnoU2EQ9K7zCLaGLwZTc_IahlhiTP39aXYeYh3aa18F-V")
        XCTAssertEqual(opened.title, "Break-glass sign-in")
        XCTAssertEqual(opened.body, "bg-admin@contoso.com signed in from 203.0.113.7")
        XCTAssertEqual(opened.link, "tenantkeep://people")
    }
}

private extension Data {
    init(hex: String) {
        self.init()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
    }
}
