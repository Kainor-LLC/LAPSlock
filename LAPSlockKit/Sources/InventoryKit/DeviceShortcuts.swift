import Foundation

// Favourites and recents: getting back to a device you have already found.
//
// Search answers "I know the name". This answers "I was just here" and "I am here every
// week" — a lab bench, a row of kiosks, the one server that keeps breaking.
//
// WHAT IS STORED, AND WHY IT IS SO LITTLE. Device IDs and nothing else. No names, no users,
// no serials. A stored hostname would be tenant data sitting on a phone for no reason; an
// ID is enough to look the row up in inventory the app has already loaded, and it is
// meaningless to anyone who cannot query that tenant.
//
// TENANT-SCOPED, WHICH IS NOT OPTIONAL. An MSP switches between customer organizations in
// one install. Favourites from customer A appearing while operating in customer B would be
// a cross-customer leak of which machines matter to whom — small, but exactly the kind of
// thing this product cannot afford. Every read and write is keyed by tenant.
//
// NOT the Keychain. These are not secrets and they do not need to survive a reinstall; the
// reveal meter uses the Keychain specifically because it MUST survive one, and reusing that
// store here would blur a distinction worth keeping sharp.

/// One tenant's shortcuts.
public struct DeviceShortcuts: Sendable, Equatable {
    /// Pinned device IDs, most recently pinned first.
    public let favourites: [String]
    /// Recently opened device IDs, most recent first.
    public let recents: [String]

    public init(favourites: [String] = [], recents: [String] = []) {
        self.favourites = favourites
        self.recents = recents
    }

    public static let empty = DeviceShortcuts()

    public var isEmpty: Bool { favourites.isEmpty && recents.isEmpty }

    public func isFavourite(_ deviceId: String) -> Bool { favourites.contains(deviceId) }
}

public protocol DeviceShortcutStoring: Sendable {
    func shortcuts(tenantId: String) -> DeviceShortcuts
    @discardableResult
    func toggleFavourite(_ deviceId: String, tenantId: String) -> DeviceShortcuts
    @discardableResult
    func recordVisit(_ deviceId: String, tenantId: String) -> DeviceShortcuts
    /// Wipes one tenant's shortcuts. Called on sign-out (§7 teardown).
    func clear(tenantId: String)
}

public final class DeviceShortcutStore: DeviceShortcutStoring, @unchecked Sendable {

    /// How many recents to keep.
    ///
    /// Five, matching the free reveal allowance by coincidence rather than design: a list
    /// long enough to hold a working session and short enough to scan without reading. A
    /// long recents list is just a second device list, which is not worth screen space.
    public static let maxRecents = 5

    private let defaults: UserDefaults
    private let lock = NSLock()

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    // MARK: - the pure list rules, which are the part worth testing

    /// Adds or removes an ID, newest-pinned first.
    static func toggling(_ deviceId: String, in list: [String]) -> [String] {
        if list.contains(deviceId) {
            return list.filter { $0 != deviceId }
        }
        return [deviceId] + list
    }

    /// Moves an ID to the front, de-duplicated, capped.
    ///
    /// Re-visiting a device already in the list moves it up rather than adding a second
    /// entry — otherwise a list of five recents becomes five copies of the machine somebody
    /// is currently working on, which is the opposite of useful.
    static func recording(_ deviceId: String, in list: [String], cap: Int = maxRecents) -> [String] {
        ([deviceId] + list.filter { $0 != deviceId }).prefix(max(0, cap)).map { $0 }
    }

    // MARK: - storage

    public func shortcuts(tenantId: String) -> DeviceShortcuts {
        lock.lock(); defer { lock.unlock() }
        return read(tenantId)
    }

    @discardableResult
    public func toggleFavourite(_ deviceId: String, tenantId: String) -> DeviceShortcuts {
        mutate(tenantId) { current in
            DeviceShortcuts(
                favourites: Self.toggling(deviceId, in: current.favourites),
                recents: current.recents)
        }
    }

    @discardableResult
    public func recordVisit(_ deviceId: String, tenantId: String) -> DeviceShortcuts {
        mutate(tenantId) { current in
            DeviceShortcuts(
                favourites: current.favourites,
                recents: Self.recording(deviceId, in: current.recents))
        }
    }

    public func clear(tenantId: String) {
        lock.lock(); defer { lock.unlock() }
        defaults.removeObject(forKey: Self.key(tenantId, "favourites"))
        defaults.removeObject(forKey: Self.key(tenantId, "recents"))
    }

    @discardableResult
    private func mutate(
        _ tenantId: String,
        _ transform: (DeviceShortcuts) -> DeviceShortcuts
    ) -> DeviceShortcuts {
        lock.lock(); defer { lock.unlock() }
        let updated = transform(read(tenantId))
        defaults.set(updated.favourites, forKey: Self.key(tenantId, "favourites"))
        defaults.set(updated.recents, forKey: Self.key(tenantId, "recents"))
        return updated
    }

    private func read(_ tenantId: String) -> DeviceShortcuts {
        DeviceShortcuts(
            favourites: defaults.stringArray(forKey: Self.key(tenantId, "favourites")) ?? [],
            recents: defaults.stringArray(forKey: Self.key(tenantId, "recents")) ?? [])
    }

    /// Lowercased tenant id in the key, because Graph and MSAL disagree about GUID casing
    /// and a case difference would silently give one tenant two separate shortcut lists.
    static func key(_ tenantId: String, _ suffix: String) -> String {
        "shortcuts.\(tenantId.lowercased()).\(suffix)"
    }
}
