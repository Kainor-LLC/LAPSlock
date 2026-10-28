import SwiftUI

/// Owns an `@Observable` model for as long as the view keeps its identity, and builds it
/// once, the first time the view reads it. This is what `@StateObject` did for the
/// `ObservableObject` models (OPTIMIZATION-PLAN.md, step O).
///
/// Plain `@State` is not the same. It evaluates its initial value every time the view's
/// initializer runs, which for a screen inside the shell is every redraw of its parent.
/// SwiftUI keeps the first model and drops the others, but each one is still built, and
/// building one can read the Keychain or the shortcut store. Here the expression runs once.
///
/// The model is a reference, so reading it records nothing; the views that read its
/// properties are what Observation tracks. `$model` gives bindings into it, as `@State`'s
/// does.
@propertyWrapper
struct StateModel<Model: AnyObject & Observable>: DynamicProperty {
    @State private var holder = Holder()
    private let make: @MainActor () -> Model

    init(wrappedValue: @autoclosure @escaping @MainActor () -> Model) {
        make = wrappedValue
    }

    var wrappedValue: Model { holder.model(make) }

    var projectedValue: Bindable<Model> { Bindable(wrappedValue) }

    private final class Holder {
        private var model: Model?

        func model(_ make: @MainActor () -> Model) -> Model {
            if let model { return model }
            let made = make()
            model = made
            return made
        }
    }
}
