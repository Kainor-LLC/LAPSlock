import XCTest
import AuthKit
import PrivilegedAccessKit
@testable import ActionGateKit

/// The role check reads a person's active roles with the read-only permission, and only
/// when the organization has not approved that does it use the activation permission the
/// person already holds. It never prompts for either.
final class RoleGateScopeTests: XCTestCase {

    /// Refuses the scopes named in `refused` the way an unapproved permission is refused.
    private final class ScopedAuth: AuthManaging, @unchecked Sendable {
        let refused: Set<String>
        private let lock = NSLock()
        private var recorded: [(scopes: [String], interactive: Bool)] = []
        init(refusing refused: Set<String>) { self.refused = refused }
        var calls: [(scopes: [String], interactive: Bool)] { lock.withLock { recorded } }
        var currentAccount: AdminAccount? {
            get async { AdminAccount(id: "a.b", tenantId: "4470dc21-a4b7-4729-a232-56d4c0eedf73", username: "admin@example.com") }
        }
        func token(scopes: [String], allowInteractive: Bool) async throws -> String {
            lock.withLock { recorded.append((scopes, allowInteractive)) }
            if scopes.contains(where: refused.contains) { throw AuthError.consentRequired }
            return "token"
        }
        func signIn() async throws -> AdminAccount { throw AuthError.noAccount }
        func signOut(account: AdminAccount) async throws {}
    }

    private final class RolesProtocol: URLProtocol {
        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func startLoading() {
            let body = #"{"value":[{"roleDefinitionId":"3A2C62DB-5318-420D-8D74-23AFFEE5D9D5","assignmentType":"Activated"}]}"#
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(body.utf8))
            client?.urlProtocolDidFinishLoading(self)
        }
        override func stopLoading() {}
    }

    private func gate(_ auth: ScopedAuth) -> GraphRoleGate {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RolesProtocol.self]
        let graph = GraphClient(auth: auth, session: URLSession(configuration: configuration))
        return GraphRoleGate(graph: graph, privileged: PrivilegedAccessService(auth: auth))
    }

    func testTheReadOnlyPermissionIsUsedWhenItIsApproved() async throws {
        let auth = ScopedAuth(refusing: [])
        let roles = try await gate(auth).activeRoleTemplateIds()
        XCTAssertEqual(roles, ["3a2c62db-5318-420d-8d74-23affee5d9d5"])
        XCTAssertEqual(auth.calls.map(\.scopes), [["RoleAssignmentSchedule.Read.Directory"]])
        XCTAssertEqual(try ScopeRouter.registration(for: [GraphRoleGate.scope]), .read)
    }

    func testTheActivationPermissionIsTheFallbackAndNeitherPrompts() async throws {
        let auth = ScopedAuth(refusing: ["RoleAssignmentSchedule.Read.Directory"])
        let roles = try await gate(auth).activeRoleTemplateIds()
        XCTAssertEqual(roles, ["3a2c62db-5318-420d-8d74-23affee5d9d5"])
        XCTAssertEqual(auth.calls.map(\.scopes), [["RoleAssignmentSchedule.Read.Directory"], ["RoleAssignmentSchedule.ReadWrite.Directory"]])
        XCTAssertTrue(auth.calls.allSatisfy { !$0.interactive })
    }

    func testWithNeitherApprovedTheGateCannotTell() async {
        let auth = ScopedAuth(refusing: ["RoleAssignmentSchedule.Read.Directory", "RoleAssignmentSchedule.ReadWrite.Directory"])
        do {
            _ = try await gate(auth).activeRoleTemplateIds()
            XCTFail("the gate answered without a permission to read with")
        } catch {
            XCTAssertEqual(error as? GraphError, .consentRequired)
        }
    }
}
