import XCTest
@testable import SecurityKit

final class SecurityVocabularyTests: XCTestCase {

    func test_knownSourcesReadAsProductNames() {
        XCTAssertEqual(SecurityVocabulary.sourceLabel("microsoftDefenderForOffice365"), "Defender for Office 365")
        XCTAssertEqual(SecurityVocabulary.sourceLabel("azureAdIdentityProtection"), "Entra ID Protection")
        XCTAssertEqual(SecurityVocabulary.sourceLabel("antivirus"), "Defender Antivirus")
    }

    func test_unknownSourcesSplitOnCapitals() {
        XCTAssertEqual(SecurityVocabulary.sourceLabel("microsoftDefenderForKeyVault"), "Microsoft defender for key vault")
        XCTAssertNil(SecurityVocabulary.sourceLabel(nil))
        XCTAssertNil(SecurityVocabulary.sourceLabel(""))
    }

    func test_categoriesAndVerdicts() {
        XCTAssertEqual(SecurityVocabulary.categoryLabel("InitialAccess"), "Initial access")
        XCTAssertEqual(SecurityVocabulary.categoryLabel("Malware"), "Malware")
        XCTAssertEqual(SecurityVocabulary.verdictLabel("truePositive"), "True positive")
        XCTAssertEqual(SecurityVocabulary.verdictLabel("multiStagedAttack"), "Multi staged attack")
        XCTAssertNil(SecurityVocabulary.verdictLabel("unknown"))
        XCTAssertNil(SecurityVocabulary.verdictLabel(nil))
    }
}
