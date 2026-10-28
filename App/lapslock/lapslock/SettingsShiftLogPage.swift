import SwiftUI
import ActionGateKit

/// What this app asked Microsoft to do in this tenant, to export or clear.
struct SettingsShiftLogPage: View {
    let shiftLog: (any ShiftLogging)?
    /// The tenant whose lines the export shows.
    let shiftLogTenantId: String?

    var body: some View {
        Form {
            shiftLogSection
        }
        .navigationTitle("Shift Log")
    }

    // MARK: - shift log

    @State private var shiftLogExport: String?
    @State private var shiftLogCount: Int?
    @State private var confirmingClear = false

    @ViewBuilder
    private var shiftLogSection: some View {
        if let shiftLog, let tenant = shiftLogTenantId {
            Section {
                if let count = shiftLogCount {
                    LabeledContent("Entries", value: String(count))
                }
                if let export = shiftLogExport {
                    ShareLink(item: export, subject: Text("TenantKeep shift log")) {
                        Label("Export shift log", systemImage: "square.and.arrow.up")
                    }
                }
                Button(role: .destructive) {
                    confirmingClear = true
                } label: {
                    Label("Clear shift log", systemImage: "trash")
                }
                .disabled((shiftLogCount ?? 0) == 0)
                .confirmationDialog("Clear the shift log for this tenant?", isPresented: $confirmingClear, titleVisibility: .visible) {
                    Button("Clear", role: .destructive) {
                        Task {
                            await shiftLog.clear(tenantId: tenant)
                            await refreshShiftLog(shiftLog, tenant: tenant)
                        }
                    }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("The tenant's audit log at Microsoft is not affected.")
                }
            } footer: {
                Text("Every device, user and group action requested from this app, with the time, the target, the outcome and Microsoft's request id. On this device only; the tenant audit log is authoritative. Demo mode keeps its own log, not this one.")
            }
            .task { await refreshShiftLog(shiftLog, tenant: tenant) }
        }
    }

    private func refreshShiftLog(_ log: any ShiftLogging, tenant: String) async {
        let entries = await log.entries(tenantId: tenant)
        shiftLogCount = entries.count
        shiftLogExport = await log.export(tenantId: tenant, now: Date())
    }
}
