import WidgetKit
import SwiftUI
import WatchBridgeKit

// Watch face complications, phase 4 step B, spec 3.13. Counts and one time, never a name:
// approvals waiting, degraded services, open incidents, and when the next active role
// ends. Fed by the watch app from the phone's glance, so each says when it was last updated
// and is only as fresh as the phone's last refresh.

struct ComplicationEntry: TimelineEntry {
    let date: Date
    let snapshot: ComplicationSnapshot?
}

struct ComplicationProvider: TimelineProvider {
    private var defaults: UserDefaults? { UserDefaults(suiteName: ComplicationSnapshot.appGroup) }

    func placeholder(in context: Context) -> ComplicationEntry {
        ComplicationEntry(date: Date(), snapshot: ComplicationSnapshot(updatedAt: Date(), approvalsWaiting: 2, degradedServices: 1,
                                                                      openIncidents: 0, nextRoleEnds: Date().addingTimeInterval(5400), isDemo: true))
    }

    func getSnapshot(in context: Context, completion: @escaping (ComplicationEntry) -> Void) {
        completion(context.isPreview ? placeholder(in: context) : ComplicationEntry(date: Date(), snapshot: ComplicationSnapshot.load(from: defaults)))
    }

    /// One entry now, and one when the next role ends so the countdown clears itself.
    func getTimeline(in context: Context, completion: @escaping (Timeline<ComplicationEntry>) -> Void) {
        let snapshot = ComplicationSnapshot.load(from: defaults)
        var entries = [ComplicationEntry(date: Date(), snapshot: snapshot)]
        if let end = snapshot?.nextRoleEnds, end > Date() {
            var cleared = snapshot
            cleared?.nextRoleEnds = nil
            entries.append(ComplicationEntry(date: end, snapshot: cleared))
        }
        completion(Timeline(entries: entries, policy: .never))
    }
}

struct ComplicationView: View {
    @Environment(\.widgetFamily) private var family
    let entry: ComplicationEntry

    var body: some View {
        if let snap = entry.snapshot {
            switch family {
            case .accessoryCircular:
                ZStack {
                    AccessoryWidgetBackground()
                    VStack(spacing: 0) {
                        Image(systemName: snap.needsAttention ? "exclamationmark.shield" : "checkmark.shield")
                            .font(.caption)
                        Text(String(snap.approvalsWaiting))
                            .font(.title3.bold())
                            .widgetAccentable()
                    }
                }
                .accessibilityLabel(String(snap.approvalsWaiting) + " PIM approvals waiting")
            case .accessoryInline:
                Text(inline(snap))
            case .accessoryCorner:
                Text(String(snap.approvalsWaiting))
                    .widgetCurvesContent()
                    .widgetLabel { Text("PIM waiting") }
            default:
                VStack(alignment: .leading, spacing: 1) {
                    Text("TenantKeep").font(.headline).widgetAccentable()
                    Text(String(snap.approvalsWaiting) + " PIM waiting · " + String(snap.degradedServices ?? 0) + " degraded")
                        .font(.caption)
                    if let end = snap.nextRoleEnds, end > entry.date {
                        Text("Role ends ") + Text(end, style: .relative)
                    } else {
                        Text("Updated ") + Text(snap.updatedAt, style: .relative) + Text(" ago")
                    }
                }
                .font(.caption2)
            }
        } else {
            Text(family == .accessoryInline ? "TenantKeep: open on iPhone" : "Open iPhone")
                .font(.caption2)
        }
    }

    private func inline(_ snap: ComplicationSnapshot) -> String {
        if snap.approvalsWaiting > 0 { return String(snap.approvalsWaiting) + " PIM waiting" }
        if let degraded = snap.degradedServices, degraded > 0 { return String(degraded) + " services degraded" }
        return "TenantKeep: all quiet"
    }
}

struct OnCallComplications: Widget {
    let kind = "OnCallComplications"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: ComplicationProvider()) { entry in
            ComplicationView(entry: entry)
                .containerBackground(.fill.tertiary, for: .widget)
        }
        .configurationDisplayName("TenantKeep")
        .description("PIM approvals waiting, degraded services and your next role's end. Counts only.")
        .supportedFamilies([.accessoryCircular, .accessoryRectangular, .accessoryInline, .accessoryCorner])
    }
}

#Preview(as: .accessoryRectangular) {
    OnCallComplications()
} timeline: {
    ComplicationEntry(date: .now, snapshot: ComplicationSnapshot(updatedAt: .now, approvalsWaiting: 3, degradedServices: 1, openIncidents: 2,
                                                                nextRoleEnds: .now.addingTimeInterval(8040), isDemo: true))
    ComplicationEntry(date: .now, snapshot: nil)
}

#Preview(as: .accessoryCircular) {
    OnCallComplications()
} timeline: {
    ComplicationEntry(date: .now, snapshot: ComplicationSnapshot(updatedAt: .now, approvalsWaiting: 3, degradedServices: 1, openIncidents: 2,
                                                                nextRoleEnds: nil, isDemo: true))
}
