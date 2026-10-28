import SwiftUI

/// Asks for the permission a screen was refused, showing progress while the prompt is up.
/// Consent is granted per organization, so an admin who works across tenants meets this on
/// every new one. `finished` hears nil when it was granted, or the reason it was not.
struct ConsentRequestButton: View {
    var title = "Request permission"
    let request: () async -> String?
    let finished: (String?) async -> Void
    @State private var isRequesting = false

    var body: some View {
        Button {
            Task {
                isRequesting = true
                let refusal = await request()
                isRequesting = false
                await finished(refusal)
            }
        } label: {
            HStack {
                if isRequesting { ProgressView().padding(.trailing, 6) }
                Text(isRequesting ? "Requesting…" : title)
            }
        }
        .disabled(isRequesting)
    }
}
