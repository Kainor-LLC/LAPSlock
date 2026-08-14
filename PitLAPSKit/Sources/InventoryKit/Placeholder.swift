// InventoryKit — device list/detail, NON-sensitive metadata, tenant-scoped cache.
// Build Spec §2.2, §2.5, §5. NOT YET IMPLEMENTED.
//
// Next session builds here:
//   * ManagedDeviceSummary model carrying BOTH identifiers (§2.5 two-identifier join):
//     Intune managedDeviceId + Entra azureADDeviceId
//   * paging over /deviceManagement/managedDevices via $top + @odata.nextLink
//   * client-side search (server-side $search/$filter support is inconsistent)
//   * per-device enrichment for fields that are null in list responses
//   * tenantId-scoped cache, fully torn down on account switch (§3.3)
//
// This file exists only so SwiftPM has a source file for the target.
enum InventoryKitPlaceholder {}
