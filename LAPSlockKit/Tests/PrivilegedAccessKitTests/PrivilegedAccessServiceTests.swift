import XCTest
import AuthKit
@testable import PrivilegedAccessKit

// MARK: - test doubles

/// Records what was asked of it, and can be told to fail per scope.
final class RecordingAuth: AuthManaging, @unchecked Sendable {
    var account = AdminAccount(
        id: "aaaaaaaa-1111-2222-3333-444455556666.4470dc21-a4b7-4729-a232-56d4c0eedf73",
        tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73",
        username: "admin@example.com",
        objectId: "aaaaaaaa-1111-2222-3333-444455556666")

    /// Scopes that should throw, keyed by the first scope requested.
    var failures: [String: AuthError] = [:]
    private(set) var calls: [(scopes: [String], claims: String?, interactive: Bool)] = []

    var currentAccount: AdminAccount? { get async { account } }

    func token(scopes: [String], allowInteractive: Bool) async throws -> String {
        try await token(scopes: scopes, claims: nil, allowInteractive: allowInteractive)
    }

    func token(scopes: [String], claims: String?, allowInteractive: Bool) async throws -> String {
        calls.append((scopes, claims, allowInteractive))
        if let first = scopes.first, let error = failures[first] { throw error }
        return "token-for-\(scopes.joined(separator: "+"))"
    }

    func signIn() async throws -> AdminAccount { account }
    func signOut(account: AdminAccount) async throws {}
}

/// Serves canned HTTP responses in order, per URL path.
final class StubProtocol: URLProtocol {
    struct Reply {
        var status: Int
        var body: String
        var headers: [String: String] = [:]
    }
    /// Keyed by a substring of the path. Each entry is consumed in order.
    nonisolated(unsafe) static var replies: [String: [Reply]] = [:]
    nonisolated(unsafe) static var requests: [(path: String, method: String, body: Data?)] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let path = request.url?.path ?? ""
        Self.requests.append((path, request.httpMethod ?? "", request.httpBodyStream.flatMap { stream in
            stream.open()
            var data = Data(); var buf = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buf, maxLength: buf.count)
                if n <= 0 { break }
                data.append(buf, count: n)
            }
            stream.close()
            return data
        } ?? request.httpBody))

        let key = Self.replies.keys.first { path.lowercased().contains($0.lowercased()) }
        let reply = key.flatMap { k -> Reply? in
            guard var queue = Self.replies[k], !queue.isEmpty else { return nil }
            let next = queue.removeFirst()
            Self.replies[k] = queue
            return next
        } ?? Reply(status: 500, body: "{}")

        let response = HTTPURLResponse(
            url: request.url!, statusCode: reply.status,
            httpVersion: "HTTP/1.1", headerFields: reply.headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(reply.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func reset() { replies = [:]; requests = [] }

    static func session() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: cfg)
    }
}

// MARK: - tests

final class PrivilegedAccessServiceTests: XCTestCase {

    private var auth: RecordingAuth!
    private var service: PrivilegedAccessService!

    private let roleDef = "7698a772-787b-4ac8-901f-60d6b08affd2"

    override func setUp() {
        super.setUp()
        StubProtocol.reset()
        auth = RecordingAuth()
        service = PrivilegedAccessService(auth: auth, session: StubProtocol.session())
    }

    override func tearDown() { StubProtocol.reset(); super.tearDown() }

    private var roleBody: String {
        #"{"value":[{"id":"s1","roleDefinitionId":"\#(roleDef)","directoryScopeId":"/","roleDefinition":{"displayName":"Cloud Device Administrator"}}]}"#
    }
    private var groupBody: String {
        #"{"value":[{"id":"s2","groupId":"gggggggg-1111-2222-3333-444455556666","accessId":"member","group":{"displayName":"LAPS Readers"}}]}"#
    }
    private var claimsHeader: [String: String] {
        let json = #"{"access_token":{"acr":{"essential":true,"value":"c1"}}}"#
        return ["WWW-Authenticate": "Bearer error=\"insufficient_claims\", claims=\"\(Data(json.utf8).base64EncodedString())\""]
    }

    // MARK: reading both surfaces

    func test_bothSurfacesAreReadAndCombined() async throws {
        StubProtocol.replies = [
            "roleEligibilitySchedules": [.init(status: 200, body: roleBody)],
            "privilegedAccess/group/eligibilitySchedules": [.init(status: 200, body: groupBody)],
        ]
        let access = try await service.eligibleAccess()
        XCTAssertEqual(access.map(\.label), ["Cloud Device Administrator", "LAPS Readers"])
    }

    func test_oneSurfaceFailingDoesNotHideTheOther() async throws {
        // A tenant may use PIM for Groups and not roles, or have only one scope consented.
        // Returning what we could read beats returning nothing.
        StubProtocol.replies = [
            "roleEligibilitySchedules": [.init(status: 403, body: "{}")],
            "privilegedAccess/group/eligibilitySchedules": [.init(status: 200, body: groupBody)],
        ]
        let access = try await service.eligibleAccess()
        XCTAssertEqual(access.map(\.label), ["LAPS Readers"])
    }

    func test_bothSurfacesFailingThrows() async {
        StubProtocol.replies = [
            "roleEligibilitySchedules": [.init(status: 403, body: "{}")],
            "privilegedAccess/group/eligibilitySchedules": [.init(status: 403, body: "{}")],
        ]
        do {
            _ = try await service.eligibleAccess()
            XCTFail("expected a throw when neither surface could be read")
        } catch {
            XCTAssertEqual(error as? PrivilegedAccessError, .notAuthorized)
        }
    }

    func test_noEligibleAccessIsItsOwnOutcome() async {
        // Not an error to apologise for: it usually means the user's access is permanent
        // rather than PIM-managed.
        StubProtocol.replies = [
            "roleEligibilitySchedules": [.init(status: 200, body: #"{"value":[]}"#)],
            "privilegedAccess/group/eligibilitySchedules": [.init(status: 200, body: #"{"value":[]}"#)],
        ]
        do {
            _ = try await service.eligibleAccess()
            XCTFail("expected noEligibleAccess")
        } catch {
            XCTAssertEqual(error as? PrivilegedAccessError, .noEligibleAccess)
        }
    }

    func test_readingEligibilityNeverPromptsTheUser() async throws {
        // A consent prompt here would appear before the user has asked to activate
        // anything, which is the wrong moment.
        StubProtocol.replies = [
            "roleEligibilitySchedules": [.init(status: 200, body: roleBody)],
            "privilegedAccess/group/eligibilitySchedules": [.init(status: 200, body: #"{"value":[]}"#)],
        ]
        _ = try await service.eligibleAccess()
        XCTAssertFalse(auth.calls.contains { $0.interactive }, "reads must be silent-only")
    }

    func test_anUnconsentedScopeReportsConsentRequiredNotNotAuthorized() async {
        // A SILENT request for an unconsented scope throws interactionRequired, not
        // consentRequired. Mapping only the latter reported "not authorized", which points
        // the user at eligibility instead of at the permission they actually need.
        auth.failures = [
            PrivilegedAccessGraph.roleReadScope: .interactionRequired,
            PrivilegedAccessGraph.groupReadScope: .interactionRequired,
        ]
        do {
            _ = try await service.eligibleAccess()
            XCTFail("expected consentRequired")
        } catch {
            XCTAssertEqual(error as? PrivilegedAccessError, .consentRequired)
        }
    }

    // MARK: activation and the claims challenge

    private var role: EligibleAccess {
        EligibleAccess(
            id: "s1",
            kind: .directoryRole(roleDefinitionId: roleDef, directoryScopeId: "/"),
            displayName: "Cloud Device Administrator",
            eligibilityEndsAt: nil)
    }

    func test_activationPostsToTheRoleEndpoint() async throws {
        StubProtocol.replies = ["roleAssignmentScheduleRequests": [
            .init(status: 201, body: #"{"id":"r1","status":"Provisioned"}"#)]]

        let outcome = try await service.activate(role, justification: "ticket INC-1", ticketNumber: nil, duration: "PT1H")
        guard case .activated = outcome else { return XCTFail("expected activated") }

        let posted = StubProtocol.requests.first { $0.method == "POST" }
        XCTAssertNotNil(posted)
        let body = try XCTUnwrap(posted?.body).flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
        XCTAssertEqual(body?["action"] as? String, "selfActivate")
        // The DIRECTORY object id, not the MSAL account identifier. Using the latter would
        // target a principal that does not exist.
        XCTAssertEqual(body?["principalId"] as? String, auth.account.objectId)
    }

    func test_aClaimsChallengeTriggersExactlyOneRetryWithTheClaims() async throws {
        // The core of the design. Graph refuses until MFA is satisfied in-session; we
        // re-authenticate carrying the claims and try once more.
        StubProtocol.replies = ["roleAssignmentScheduleRequests": [
            .init(status: 401, body: "{}", headers: claimsHeader),
            .init(status: 201, body: #"{"id":"r1","status":"Provisioned"}"#),
        ]]

        let outcome = try await service.activate(role, justification: "ticket INC-1", ticketNumber: nil, duration: "PT1H")
        guard case .activated = outcome else { return XCTFail("expected activated after the retry") }

        let withClaims = auth.calls.filter { $0.claims != nil }
        XCTAssertEqual(withClaims.count, 1, "exactly one claims-carrying acquisition")
        XCTAssertTrue(withClaims.first?.claims?.contains("\"acr\"") == true)
        XCTAssertTrue(withClaims.first?.interactive == true, "a challenge must force interactive")
    }

    func test_aSecondChallengeIsNotRetriedAgain() async {
        // Retrying forever would trap the user behind a biometric prompt they cannot escape.
        StubProtocol.replies = ["roleAssignmentScheduleRequests": [
            .init(status: 401, body: "{}", headers: claimsHeader),
            .init(status: 401, body: "{}", headers: claimsHeader),
        ]]
        do {
            _ = try await service.activate(role, justification: "j", ticketNumber: nil, duration: "PT1H")
            XCTFail("expected the second challenge to surface")
        } catch {
            guard case .claimsChallenge = error as? PrivilegedAccessError else {
                return XCTFail("expected claimsChallenge, got \(error)")
            }
        }
        XCTAssertEqual(auth.calls.filter { $0.claims != nil }.count, 1, "no second retry")
    }

    func test_anOrdinary401IsNotTreatedAsAChallenge() async {
        // No claims header. Re-authenticating would not fix this, so it must not loop.
        StubProtocol.replies = ["roleAssignmentScheduleRequests": [
            .init(status: 401, body: "{}", headers: ["WWW-Authenticate": "Bearer error=\"invalid_token\""])]]
        do {
            _ = try await service.activate(role, justification: "j", ticketNumber: nil, duration: "PT1H")
            XCTFail("expected notAuthorized")
        } catch {
            XCTAssertEqual(error as? PrivilegedAccessError, .notAuthorized)
        }
        XCTAssertTrue(auth.calls.allSatisfy { $0.claims == nil }, "no claims retry for a plain 401")
    }

    func test_anAcrsFourHundredIsRetriedAsAClaimsChallenge() async throws {
        // The failure observed on device: a PIM policy requiring a Conditional Access
        // authentication context answers 400, not 401, and carries the required claim in
        // the message. Nothing watched for it, so activation died on a bare bad request.
        // Built rather than written as a literal: the message contains a JSON object, so a
        // hand-escaped literal needs backslashes, and backslashes in Swift string literals
        // have been destroyed three times today by the text-processing step that writes this
        // file. JSONSerialization does the escaping at runtime and there is nothing to eat.
        let claims = #"{"access_token":{"acrs":{"essential":true,"value":"c1"}}}"#
        let message = "RoleAssignmentRequestAcrsValidationFailed claims=" + claims
        let acrsBody = String(
            data: try JSONSerialization.data(
                withJSONObject: ["error": ["code": "UnknownError", "message": message]]),
            encoding: .utf8)!
        StubProtocol.replies = ["assignmentScheduleRequests": [
            .init(status: 400, body: acrsBody),
            .init(status: 201, body: #"{"id":"r1","status":"Provisioned"}"#),
        ]]

        let group = EligibleAccess(
            id: "g", kind: .group(groupId: "gggggggg-1111-2222-3333-444455556666", accessId: .member),
            displayName: "LAPS Readers", eligibilityEndsAt: nil)

        let outcome = try await service.activate(group, justification: "j", ticketNumber: nil, duration: "PT1H")
        guard case .activated = outcome else { return XCTFail("expected activated after re-authenticating") }

        let withClaims = auth.calls.filter { $0.claims != nil }
        XCTAssertEqual(withClaims.count, 1, "exactly one claims-carrying acquisition")
        XCTAssertTrue(withClaims.first?.claims?.contains("acrs") == true)
        XCTAssertTrue(withClaims.first?.interactive == true, "satisfying an auth context needs a sign-in")
    }

    func test_anOrdinaryFourHundredIsNotRetried() async {
        // Every other bad request must not trigger re-authentication, which cannot fix it.
        StubProtocol.replies = ["assignmentScheduleRequests": [
            .init(status: 400, body: String(
                data: try! JSONSerialization.data(withJSONObject: [
                    "error": ["code": "InvalidRequest", "message": "The duration exceeds policy"]]),
                encoding: .utf8)!)]]
        do {
            _ = try await service.activate(role, justification: "j", ticketNumber: nil, duration: "PT8H")
            XCTFail("expected serviceError")
        } catch {
            XCTAssertEqual(error as? PrivilegedAccessError, .serviceError(status: 400, code: "InvalidRequest"))
        }
        XCTAssertTrue(auth.calls.allSatisfy { $0.claims == nil }, "no claims retry for an ordinary 400")
    }

    func test_pendingApprovalSurvivesTheServiceLayer() async throws {
        StubProtocol.replies = ["roleAssignmentScheduleRequests": [
            .init(status: 201, body: #"{"id":"r9","status":"PendingApproval"}"#)]]
        let outcome = try await service.activate(role, justification: "j", ticketNumber: nil, duration: "PT1H")
        guard case .pendingApproval(let id) = outcome else { return XCTFail("expected pending") }
        XCTAssertEqual(id, "r9")
    }

    func test_anAlreadyActiveRoleIsItsOwnError() async {
        // Graph answers 400 for this. Detected by error code, not by matching localised prose.
        StubProtocol.replies = ["roleAssignmentScheduleRequests": [
            .init(status: 400, body: #"{"error":{"code":"RoleAssignmentExists","message":"already active"}}"#)]]
        do {
            _ = try await service.activate(role, justification: "j", ticketNumber: nil, duration: "PT1H")
            XCTFail("expected alreadyActive")
        } catch {
            XCTAssertEqual(error as? PrivilegedAccessError, .alreadyActive)
        }
    }

    func test_activationWithoutAnObjectIdIsRefused() async {
        // Without the oid there is no principal to activate for, and guessing would target
        // a nonexistent directory object.
        auth.account = AdminAccount(id: "x.y", tenantId: "t", username: "u", objectId: nil)
        do {
            _ = try await service.activate(role, justification: "j", ticketNumber: nil, duration: "PT1H")
            XCTFail("expected notAuthorized")
        } catch {
            XCTAssertEqual(error as? PrivilegedAccessError, .notAuthorized)
        }
        XCTAssertTrue(StubProtocol.requests.isEmpty, "nothing should reach the network")
    }
}
