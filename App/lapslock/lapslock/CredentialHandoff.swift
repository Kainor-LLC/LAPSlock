import AuthKit
import CredentialKit
import InventoryKit

// The hand-off from the device list to the credential layer. Here, in the phone app,
// because this is the one target that links both: InventoryKit no longer depends on
// CredentialKit, so the Mac menu bar app, which shows the inventory, does not contain the
// code that reads a password (OPTIMIZATION-PLAN.md, step J, decision 6).

extension ManagedDeviceSummary {
    /// Carries both identifiers (§2.5).
    var credentialTarget: DeviceCredentialTarget {
        DeviceCredentialTarget(
            platform: platform,
            entraDeviceId: entraDeviceId,
            managedDeviceId: id,
            deviceName: deviceName
        )
    }
}
