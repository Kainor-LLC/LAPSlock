import Foundation

// The plain-English glossary for sign-in error codes. Spec section 3.4.
//
// It ships inside the app so it works with no network and no search, which is the
// situation an on-call administrator is usually in. The same JSON is published on the
// website by scripts/build-glossary.py, so the phone and the page never disagree.
//
// Entries are deliberately short: what it means, then what to do. An administrator who
// wants Microsoft's full text has the code and can look it up; what they cannot get from
// Microsoft is the one-line answer at 2 am.

public struct GlossaryEntry: Codable, Sendable, Equatable, Identifiable {
    public let code: Int
    public let title: String
    public let meaning: String
    public let action: String

    public var id: Int { code }

    public init(code: Int, title: String, meaning: String, action: String) {
        self.code = code
        self.title = title
        self.meaning = meaning
        self.action = action
    }
}

public struct ErrorGlossary: Sendable, Equatable {
    public let entries: [GlossaryEntry]
    private let byCode: [Int: GlossaryEntry]

    public init(entries: [GlossaryEntry]) {
        self.entries = entries.sorted { $0.code < $1.code }
        self.byCode = Dictionary(entries.map { ($0.code, $0) }, uniquingKeysWith: { first, _ in first })
    }

    public func entry(for code: Int) -> GlossaryEntry? {
        byCode[code]
    }

    /// The bundled glossary. Loading cannot fail at runtime without a broken build, so
    /// a missing resource is a programmer error and not something to handle quietly.
    public static let bundled: ErrorGlossary = {
        guard let url = Bundle.module.url(forResource: "ErrorGlossary", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let file = try? JSONDecoder().decode(GlossaryFile.self, from: data)
        else {
            preconditionFailure("ErrorGlossary.json is missing from the SignInTriageKit bundle")
        }
        return ErrorGlossary(entries: file.entries)
    }()

    struct GlossaryFile: Codable {
        let entries: [GlossaryEntry]
    }
}
