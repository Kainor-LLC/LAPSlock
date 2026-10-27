import Foundation
import AuthKit

// Investigate email, phase 3 step H, spec 3.12. Threat Explorer has no Graph API; advanced
// hunting does. So: a short, fixed list of read-only hunting queries behind plain buttons,
// never a free-text KQL box, so what the app can ask stays small and explainable.
//
// The one thing a person types is a value: a sender, a recipient, a subject, a domain. It
// is checked against a strict pattern before it goes anywhere near the query, and the
// pattern excludes the quote and the backslash, so a value can never end the string it
// sits in. The builder refuses anything that slipped past, as a second line.
//
// The call is POST /security/runHuntingQuery: a POST that changes nothing. It is sent
// through the client directly, not the write gate, and like every non-GET it is never
// retried.

public enum HuntingScopes {
    /// Requested the first time a query is run, never when Security opens.
    public static let hunting = "ThreatHunting.Read.All"
}

/// How far back. Advanced hunting keeps thirty days.
public enum HuntWindow: Int, Sendable, CaseIterable, Identifiable {
    case day = 1, week = 7, month = 30

    public var id: Int { rawValue }
    public var label: String {
        switch self {
        case .day:   return "24 hours"
        case .week:  return "7 days"
        case .month: return "30 days"
        }
    }
    /// ISO 8601, for the call's timespan.
    public var timespan: String { "P" + String(rawValue) + "D" }
}

public enum HuntParameter: Sendable, Equatable {
    case senderOrDomain, recipient, subject, linkDomain

    public var prompt: String {
        switch self {
        case .senderOrDomain: return "Sender address or domain"
        case .recipient:      return "Recipient address"
        case .subject:        return "Words in the subject"
        case .linkDomain:     return "Domain in the link"
        }
    }

    public var example: String {
        switch self {
        case .senderOrDomain: return "invoices@contoso-billing.com"
        case .recipient:      return "jane.okafor@contoso.com"
        case .subject:        return "Payment overdue"
        case .linkDomain:     return "contoso-login.com"
        }
    }

    private static let address = try! NSRegularExpression(pattern: "^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$")
    private static let domain = try! NSRegularExpression(pattern: "^[A-Za-z0-9-]{1,63}(\\.[A-Za-z0-9-]{1,63})+$")
    private static let subjectText = try! NSRegularExpression(pattern: "^[\\p{L}\\p{N} .,:;!?()&#@/_'+=%$-]{3,120}$")

    private static func matches(_ regex: NSRegularExpression, _ text: String) -> Bool {
        regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
    }

    public static func isAddress(_ text: String) -> Bool { matches(address, text) }

    /// The value as it will go into the query, or nil when it is not allowed.
    public func validate(_ raw: String) -> String? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= 254 else { return nil }
        switch self {
        case .senderOrDomain:
            return Self.matches(Self.address, text) || Self.matches(Self.domain, text) ? text.lowercased() : nil
        case .recipient:
            return Self.matches(Self.address, text) ? text.lowercased() : nil
        case .subject:
            return Self.matches(Self.subjectText, text) ? text : nil
        case .linkDomain:
            return Self.matches(Self.domain, text) ? text.lowercased() : nil
        }
    }

    public var invalidMessage: String {
        switch self {
        case .senderOrDomain: return "Enter an email address or a domain, such as contoso.com."
        case .recipient:      return "Enter an email address."
        case .subject:        return "Three to 120 characters. Quotes and backslashes are not allowed."
        case .linkDomain:     return "Enter a domain, such as contoso.com."
        }
    }
}

public enum HuntError: Error, Sendable, Equatable {
    case invalidValue(String)
    case consentRequired
    case notAuthorized
    case badQuery(code: String?)
    case throttled
    case unavailable
    case decodeFailure

    public var message: String {
        switch self {
        case .invalidValue(let why): return why
        case .consentRequired: return "This organization hasn't granted TenantKeep permission to run hunting queries yet."
        case .notAuthorized: return "Your account can't run advanced hunting. Security Reader or a Defender role with hunting access is needed, and the tenant needs Defender for Office 365."
        case .badQuery(let code): return "Microsoft rejected the query" + (code.map { " (" + $0 + ")" } ?? "") + ". The hunting tables may have changed."
        case .throttled: return "Advanced hunting is rate limited. Wait a minute and try again."
        case .unavailable: return "Microsoft Defender isn't answering right now. Try again shortly."
        case .decodeFailure: return "Microsoft returned something unexpected."
        }
    }
}

/// One fixed query. The text is written here, in the open source, and nowhere else.
public enum EmailHunt: String, Sendable, CaseIterable, Identifiable {
    case fromSender, toRecipient, bySubject, deliveredThreats, removedAfterDelivery, linkClicks

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .fromSender:           return "Messages From a Sender"
        case .toRecipient:          return "Messages to a Person"
        case .bySubject:            return "Messages by Subject"
        case .deliveredThreats:     return "Phish or Malware Delivered"
        case .removedAfterDelivery: return "Removed After Delivery"
        case .linkClicks:           return "Who Clicked a Link"
        }
    }

    public var detail: String {
        switch self {
        case .fromSender:           return "Everything a sender or domain sent, who got it, and the verdict."
        case .toRecipient:          return "What reached one person, with each verdict and where it landed."
        case .bySubject:            return "Messages whose subject contains the words, across the tenant."
        case .deliveredThreats:     return "Messages flagged phish or malware that still reached an inbox."
        case .removedAfterDelivery: return "Messages pulled out of mailboxes after delivery, by zero-hour auto purge or an admin."
        case .linkClicks:           return "Safe Links clicks on a domain: who, when, and whether they went through."
        }
    }

    public var symbol: String {
        switch self {
        case .fromSender:           return "envelope.arrow.triangle.branch"
        case .toRecipient:          return "person.crop.circle.badge.checkmark"
        case .bySubject:            return "text.magnifyingglass"
        case .deliveredThreats:     return "exclamationmark.triangle"
        case .removedAfterDelivery: return "tray.and.arrow.up"
        case .linkClicks:           return "link"
        }
    }

    public var parameter: HuntParameter? {
        switch self {
        case .fromSender:           return .senderOrDomain
        case .toRecipient:          return .recipient
        case .bySubject:            return .subject
        case .linkClicks:           return .linkDomain
        case .deliveredThreats, .removedAfterDelivery: return nil
        }
    }

    /// The hunting tables this reads, for the Graph change watch.
    public var tables: [String] {
        switch self {
        case .removedAfterDelivery: return ["EmailPostDeliveryEvents", "EmailEvents"]
        case .linkClicks:           return ["UrlClickEvents"]
        default:                    return ["EmailEvents"]
        }
    }

    static let messageColumns = "Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes, EmailDirection, NetworkMessageId"

    /// The KQL. Throws when the value fails its pattern or carries a character that could
    /// leave the string literal.
    public func query(value: String?, window: HuntWindow) throws -> String {
        var checked: String?
        if let parameter {
            guard let raw = value, let valid = parameter.validate(raw) else {
                throw HuntError.invalidValue(parameter.invalidMessage)
            }
            guard !valid.contains("\""), !valid.contains("\\"), !valid.contains("\n") else {
                throw HuntError.invalidValue(parameter.invalidMessage)
            }
            checked = valid
        }
        let since = "| where Timestamp > ago(" + String(window.rawValue) + "d)"
        let literal = "\"" + (checked ?? "") + "\""
        let lines: [String]
        switch self {
        case .fromSender:
            let filter = HuntParameter.isAddress(checked ?? "") ? "| where SenderFromAddress =~ " + literal : "| where SenderFromDomain =~ " + literal
            lines = ["EmailEvents", since, filter, "| project " + Self.messageColumns, "| order by Timestamp desc", "| take 200"]
        case .toRecipient:
            lines = ["EmailEvents", since, "| where RecipientEmailAddress =~ " + literal, "| project " + Self.messageColumns, "| order by Timestamp desc", "| take 200"]
        case .bySubject:
            lines = ["EmailEvents", since, "| where Subject contains " + literal, "| project " + Self.messageColumns, "| order by Timestamp desc", "| take 200"]
        case .deliveredThreats:
            lines = ["EmailEvents", since, "| where DeliveryAction == \"Delivered\"", "| where ThreatTypes has_any (\"Phish\", \"Malware\")",
                     "| project " + Self.messageColumns, "| order by Timestamp desc", "| take 200"]
        case .removedAfterDelivery:
            lines = ["EmailPostDeliveryEvents", since,
                     "| join kind=leftouter (EmailEvents " + since + " | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress) on NetworkMessageId, RecipientEmailAddress",
                     "| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Action, ActionType, ActionTrigger, ActionResult, DeliveryLocation, ThreatTypes, NetworkMessageId",
                     "| order by Timestamp desc", "| take 200"]
        case .linkClicks:
            lines = ["UrlClickEvents", since, "| where Url has " + literal,
                     "| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, Workload, NetworkMessageId",
                     "| order by Timestamp desc", "| take 200"]
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - results

/// One cell, kept as text for display; the type comes from the result's schema.
public struct HuntRow: Sendable, Equatable, Identifiable {
    public let id: Int
    public let values: [String: String]
    public init(id: Int, values: [String: String]) {
        self.id = id
        self.values = values
    }
    public subscript(_ column: String) -> String? { values[column].flatMap { $0.isEmpty ? nil : $0 } }
}

public struct HuntResult: Sendable, Equatable {
    public let columns: [String]
    public let rows: [HuntRow]
    public init(columns: [String], rows: [HuntRow]) {
        self.columns = columns
        self.rows = rows
    }

    /// From Graph's `{ "schema": [{ "name", "type" }], "results": [{ column: value }] }`.
    public static func parse(_ data: Data) throws -> HuntResult {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw HuntError.decodeFailure }
        let schema = (json["schema"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
        let results = json["results"] as? [[String: Any]] ?? []
        var rows: [HuntRow] = []
        for (index, item) in results.enumerated() {
            var values: [String: String] = [:]
            for (key, value) in item { values[key] = text(value) }
            rows.append(HuntRow(id: index, values: values))
        }
        let columns = schema.isEmpty ? Array(Set(results.flatMap { $0.keys })).sorted() : schema
        return HuntResult(columns: columns, rows: rows)
    }

    static func text(_ value: Any) -> String {
        switch value {
        case let s as String:
            // ThreatTypes and the like arrive as a JSON array written into a string.
            if s.hasPrefix("["), let data = s.data(using: .utf8), let list = try? JSONSerialization.jsonObject(with: data) as? [Any] {
                return list.map { text($0) }.joined(separator: ", ")
            }
            return s
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return n.boolValue ? "Yes" : "No" }
            return n.stringValue
        case let list as [Any]:
            return list.map { text($0) }.joined(separator: ", ")
        case is NSNull:
            return ""
        default:
            if let data = try? JSONSerialization.data(withJSONObject: value), let s = String(data: data, encoding: .utf8) { return s }
            return String(describing: value)
        }
    }

    /// Plain text for a ticket: the query's title, the window, and one line per row.
    public func text(for hunt: EmailHunt, value: String?, window: HuntWindow, at date: Date) -> String {
        let stamp = ISO8601DateFormatter().string(from: date)
        var lines = [hunt.title + (value.map { ": " + $0 } ?? "") + ", last " + window.label, "Run " + stamp + " from TenantKeep On-Call, " + String(rows.count) + " results", ""]
        for row in rows {
            lines.append(columns.compactMap { column in row[column].map { column + "=" + $0 } }.joined(separator: "  "))
        }
        lines.append("")
        lines.append("Advanced hunting in Microsoft Defender is authoritative.")
        return lines.joined(separator: "\n")
    }
}

public protocol EmailHuntingProviding: Sendable {
    func run(_ hunt: EmailHunt, value: String?, window: HuntWindow, allowInteractive: Bool) async throws -> HuntResult
}

public actor EmailHuntingService: EmailHuntingProviding {
    public static let path = "/security/runHuntingQuery"
    private let graph: GraphClient

    public init(graph: GraphClient) {
        self.graph = graph
    }

    public func run(_ hunt: EmailHunt, value: String?, window: HuntWindow, allowInteractive: Bool) async throws -> HuntResult {
        let kql = try hunt.query(value: value, window: window)
        let body = try JSONSerialization.data(withJSONObject: ["query": kql, "timespan": window.timespan])
        let request = GraphRequest(method: .post, path: Self.path, body: body,
                                   scopes: [HuntingScopes.hunting], allowInteractive: allowInteractive)
        do {
            return try HuntResult.parse(try await graph.send(request).data)
        } catch let error as GraphError {
            switch error {
            case .consentRequired:            throw HuntError.consentRequired
            case .notAuthorized:              throw HuntError.notAuthorized
            case .badRequest(let code):       throw HuntError.badQuery(code: code)
            case .throttled:                  throw HuntError.throttled
            case .decodeFailure:              throw HuntError.decodeFailure
            default:                          throw HuntError.unavailable
            }
        }
    }
}

/// Demo: plausible rows for each query, so a reviewer sees the shapes. Nothing is real.
public actor DemoEmailHuntingProvider: EmailHuntingProviding {
    private let latency: Duration
    /// Demo mode's second sample customer: the queries run and find nothing, as in a
    /// tenant the campaign never reached.
    private let quiet: Bool
    public init(latency: Duration = .milliseconds(800), quiet: Bool = false) {
        self.latency = latency
        self.quiet = quiet
    }

    public func run(_ hunt: EmailHunt, value: String?, window: HuntWindow, allowInteractive: Bool) async throws -> HuntResult {
        _ = try hunt.query(value: value, window: window)
        try? await Task.sleep(for: latency)
        if quiet {
            return HuntResult(columns: EmailHunt.messageColumns.components(separatedBy: ", "), rows: [])
        }
        let now = Date()
        func at(_ minutesAgo: Int) -> String { ISO8601DateFormatter().string(from: now.addingTimeInterval(TimeInterval(-60 * minutesAgo))) }
        var sender = "invoices@contoso-billing.com"
        if hunt == .fromSender, let value {
            sender = HuntParameter.isAddress(value) ? value : "invoices@" + value
        }
        let message: [String] = EmailHunt.messageColumns.components(separatedBy: ", ")
        func row(_ i: Int, _ values: [String: String]) -> HuntRow { HuntRow(id: i, values: values) }
        switch hunt {
        case .linkClicks:
            let columns = ["Timestamp", "AccountUpn", "Url", "ActionType", "IsClickedThrough", "Workload", "NetworkMessageId"]
            return HuntResult(columns: columns, rows: [
                row(0, ["Timestamp": at(12), "AccountUpn": "jane.okafor@demo.example", "Url": "https://" + (value ?? "contoso-login.com") + "/reset", "ActionType": "ClickBlocked", "IsClickedThrough": "No", "Workload": "Email", "NetworkMessageId": "demo-7a1"]),
                row(1, ["Timestamp": at(40), "AccountUpn": "sam.reyes@demo.example", "Url": "https://" + (value ?? "contoso-login.com") + "/reset", "ActionType": "ClickAllowed", "IsClickedThrough": "Yes", "Workload": "Email", "NetworkMessageId": "demo-7a2"])
            ])
        case .removedAfterDelivery:
            let columns = ["Timestamp", "SenderFromAddress", "RecipientEmailAddress", "Subject", "Action", "ActionType", "ActionTrigger", "ActionResult", "DeliveryLocation", "ThreatTypes", "NetworkMessageId"]
            return HuntResult(columns: columns, rows: [
                row(0, ["Timestamp": at(25), "SenderFromAddress": sender, "RecipientEmailAddress": "jane.okafor@demo.example", "Subject": "Invoice 4471 overdue", "Action": "Moved to quarantine", "ActionType": "Phish ZAP", "ActionTrigger": "SpecialAction", "ActionResult": "Success", "DeliveryLocation": "Quarantine", "ThreatTypes": "Phish", "NetworkMessageId": "demo-7a1"]),
                row(1, ["Timestamp": at(26), "SenderFromAddress": sender, "RecipientEmailAddress": "sam.reyes@demo.example", "Subject": "Invoice 4471 overdue", "Action": "Moved to quarantine", "ActionType": "Phish ZAP", "ActionTrigger": "SpecialAction", "ActionResult": "Success", "DeliveryLocation": "Quarantine", "ThreatTypes": "Phish", "NetworkMessageId": "demo-7a2"])
            ])
        default:
            let recipient = hunt == .toRecipient ? (value ?? "jane.okafor@demo.example") : "jane.okafor@demo.example"
            let subject = hunt == .bySubject ? ((value ?? "Invoice") + " - action needed") : "Invoice 4471 overdue"
            if hunt == .deliveredThreats {
                // Only what reached an inbox, as the query asks.
                return HuntResult(columns: message, rows: [
                    row(0, ["Timestamp": at(30), "SenderFromAddress": sender, "RecipientEmailAddress": "jane.okafor@demo.example", "Subject": "Invoice 4471 overdue", "DeliveryAction": "Delivered", "DeliveryLocation": "Inbox/folder", "ThreatTypes": "Phish", "EmailDirection": "Inbound", "NetworkMessageId": "demo-7a1"]),
                    row(1, ["Timestamp": at(95), "SenderFromAddress": "docs@sharefile-secure.net", "RecipientEmailAddress": "sam.reyes@demo.example", "Subject": "Shared document: Q4 bonus", "DeliveryAction": "Delivered", "DeliveryLocation": "Inbox/folder", "ThreatTypes": "Malware", "EmailDirection": "Inbound", "NetworkMessageId": "demo-7b2"])
                ])
            }
            return HuntResult(columns: message, rows: [
                row(0, ["Timestamp": at(30), "SenderFromAddress": sender, "RecipientEmailAddress": recipient, "Subject": subject, "DeliveryAction": "Delivered", "DeliveryLocation": "Inbox/folder", "ThreatTypes": "Phish", "EmailDirection": "Inbound", "NetworkMessageId": "demo-7a1"]),
                row(1, ["Timestamp": at(31), "SenderFromAddress": sender, "RecipientEmailAddress": "sam.reyes@demo.example", "Subject": subject, "DeliveryAction": "Junked", "DeliveryLocation": "Junk folder", "ThreatTypes": "Phish", "EmailDirection": "Inbound", "NetworkMessageId": "demo-7a2"]),
                row(2, ["Timestamp": at(33), "SenderFromAddress": sender, "RecipientEmailAddress": "priya.n@demo.example", "Subject": subject, "DeliveryAction": "Blocked", "DeliveryLocation": "Quarantine", "ThreatTypes": "Phish, Malware", "EmailDirection": "Inbound", "NetworkMessageId": "demo-7a3"])
            ])
        }
    }
}
