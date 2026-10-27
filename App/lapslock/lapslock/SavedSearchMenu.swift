import SwiftUI
import SavedSearchKit
import Combine

// Saved searches on screen, phase 5 step C. A bookmark menu in each searchable module's
// toolbar: recall a saved search, save the one on screen, remove one. Pro, like the
// modules most of them belong to; demo shows three examples kept in memory.

@MainActor
final class SavedSearchLibrary: ObservableObject {
    @Published private(set) var all: [SavedSearch] = []
    /// Why the last save did not happen, in words for an alert.
    @Published var problem: String?

    private let store: any SavedSearchStoring
    /// False until a load has succeeded. The file has complete protection, so it cannot be
    /// read while the phone is locked, and a background launch must never be mistaken for
    /// an empty list that the next save would then write over the real one.
    private var loaded = false

    init(store: any SavedSearchStoring) {
        self.store = store
    }

    /// Reads the file once, in the foreground.
    func loadIfNeeded() {
        guard !loaded else { return }
        if let list = try? store.load() {
            all = list
            loaded = true
        }
    }

    func searches(in scope: SavedSearch.Scope) -> [SavedSearch] {
        SavedSearchList.searches(in: scope, from: all)
    }

    func save(name: String, scope: SavedSearch.Scope, query: String, options: [String: String]) {
        loadIfNeeded()
        guard loaded else {
            problem = "Saved searches can't be read right now. Unlock the device and try again."
            return
        }
        do {
            let updated = try SavedSearchList.adding(
                SavedSearch(name: name, scope: scope, query: query, options: options), to: all)
            try store.save(updated)
            all = updated
        } catch SavedSearchList.Problem.full {
            problem = "You have " + String(SavedSearchList.limit) + " saved searches. Remove one to save another."
        } catch SavedSearchList.Problem.emptyName {
            problem = "Give the search a name."
        } catch {
            problem = "Couldn't save the search on this device."
        }
    }

    func remove(_ search: SavedSearch) {
        loadIfNeeded()
        guard loaded else { return }
        let updated = SavedSearchList.removing(search.id, from: all)
        if (try? store.save(updated)) != nil { all = updated }
    }

    /// Sign-out: the searches go with the rest of the account's working data.
    func clear() {
        try? store.clear()
        all = []
        loaded = false
    }
}

/// The bookmark menu. `current` is what is on screen now, or nil when there is nothing
/// worth saving; leave it out entirely where this column cannot save (Email's list, whose
/// query lives in the detail column). `runEverywhere` is the MSP run across organizations,
/// nil where it is not offered.
struct SavedSearchMenu: View {
    @ObservedObject var library: SavedSearchLibrary
    let scope: SavedSearch.Scope
    var current: (() -> (query: String, options: [String: String])?)? = nil
    let apply: (SavedSearch) -> Void
    var runEverywhere: ((SavedSearch) -> Void)? = nil

    @State private var naming = false
    @State private var name = ""
    @State private var pending: (query: String, options: [String: String])?

    var body: some View {
        let saved = library.searches(in: scope)
        Menu {
            if !saved.isEmpty {
                Section("Saved Searches") {
                    ForEach(saved) { search in
                        Button(search.name) { apply(search) }
                    }
                }
            }
            if let current {
                Button {
                    if let now = current() {
                        pending = now
                        name = now.query
                        naming = true
                    }
                } label: {
                    Label("Save this search", systemImage: "plus")
                }
                .disabled(current() == nil)
            }
            if let runEverywhere, scope.runsAcrossTenants, !saved.isEmpty {
                Menu {
                    ForEach(saved) { search in
                        Button(search.name) { runEverywhere(search) }
                    }
                } label: {
                    Label("Search every organization", systemImage: "building.2.crop.circle")
                }
            }
            if !saved.isEmpty {
                Menu {
                    ForEach(saved) { search in
                        Button(search.name, role: .destructive) { library.remove(search) }
                    }
                } label: {
                    Label("Remove", systemImage: "trash")
                }
            }
        } label: {
            Image(systemName: saved.isEmpty ? "bookmark" : "bookmark.fill")
        }
        .accessibilityLabel("Saved searches")
        .onAppear { library.loadIfNeeded() }
        .alert("Save Search", isPresented: $naming) {
            TextField("Name", text: $name)
            Button("Save") {
                if let pending {
                    library.save(name: name, scope: scope, query: pending.query, options: pending.options)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Kept on this device only. It saves the search, not the results.")
        }
        .alert("Couldn't Save", isPresented: Binding(
            get: { library.problem != nil },
            set: { if !$0 { library.problem = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(library.problem ?? "")
        }
    }
}
