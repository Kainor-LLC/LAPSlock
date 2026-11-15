using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Core;
using Azure.Data.Tables;

namespace Kainor.TenantKeep.Watch;

// What the watcher keeps (HOSTED-WATCH-PLAN.md, section 4): per organization, the label it
// is announced with, the break-glass accounts' object IDs and a cursor; per phone, what the
// relay needs to reach it. No names, addresses or log content.

public sealed class TenantRecord : ITableEntity
{
    public string PartitionKey { get; set; } = "tenant";
    public string RowKey { get; set; } = "";
    public DateTimeOffset? Timestamp { get; set; }
    public ETag ETag { get; set; }

    /// <summary>How alerts name the organization, for example "Contoso".</summary>
    public string Label { get; set; } = "";
    /// <summary>The break-glass accounts' object IDs, comma separated.</summary>
    public string BreakGlassIds { get; set; } = "";
    /// <summary>The newest sign-in time seen. Null until the first run sets the baseline.</summary>
    public DateTimeOffset? SignInCursor { get; set; }
    /// <summary>The ids of the sign-ins already seen in the overlap window, comma separated.</summary>
    public string SeenSignInIds { get; set; } = "";
    /// <summary>ok, noConsent, or error, from the last run.</summary>
    public string State { get; set; } = "new";
    public DateTimeOffset? LastRun { get; set; }

    // Derived, not stored: Table Storage cannot hold an array.
    [IgnoreDataMember] public string TenantId => RowKey;
    [IgnoreDataMember] public string[] BreakGlass => BreakGlassIds.Split(',', StringSplitOptions.RemoveEmptyEntries);
}

public sealed class DeviceRecord : ITableEntity
{
    /// <summary>The tenant the phone gets alerts for.</summary>
    public string PartitionKey { get; set; } = "";
    /// <summary>A hash of the push token, so the token is not a key that shows in logs.</summary>
    public string RowKey { get; set; } = "";
    public DateTimeOffset? Timestamp { get; set; }
    public ETag ETag { get; set; }

    public string DeviceToken { get; set; } = "";
    public string Environment { get; set; } = "production";
    /// <summary>The phone's Secure Enclave public key, X9.63, base64url.</summary>
    public string PublicKey { get; set; } = "";
    public DateTimeOffset? LastSeen { get; set; }

    public static string KeyFor(string deviceToken) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(deviceToken)));
}

public sealed class WatchStore
{
    readonly TableClient tenants;
    readonly TableClient devices;
    int ready;

    public WatchStore(WatchOptions options, TokenCredential credential)
    {
        var service = new TableServiceClient(new Uri($"https://{options.StorageAccount}.table.core.windows.net"), credential);
        tenants = service.GetTableClient("tenants");
        devices = service.GetTableClient("devices");
    }

    async Task EnsureAsync(CancellationToken ct)
    {
        if (Volatile.Read(ref ready) == 1) return;
        await tenants.CreateIfNotExistsAsync(ct);
        await devices.CreateIfNotExistsAsync(ct);
        Volatile.Write(ref ready, 1);
    }

    public async Task<List<TenantRecord>> TenantsAsync(CancellationToken ct)
    {
        await EnsureAsync(ct);
        var all = new List<TenantRecord>();
        await foreach (var t in tenants.QueryAsync<TenantRecord>(t => t.PartitionKey == "tenant", cancellationToken: ct)) all.Add(t);
        return all;
    }

    public async Task<TenantRecord?> TenantAsync(string tenantId, CancellationToken ct)
    {
        await EnsureAsync(ct);
        var found = await tenants.GetEntityIfExistsAsync<TenantRecord>("tenant", tenantId, cancellationToken: ct);
        return found.HasValue ? found.Value : null;
    }

    public async Task SaveAsync(TenantRecord tenant, CancellationToken ct)
    {
        await EnsureAsync(ct);
        await tenants.UpsertEntityAsync(tenant, TableUpdateMode.Replace, ct);
    }

    public async Task<List<DeviceRecord>> DevicesAsync(string tenantId, CancellationToken ct)
    {
        await EnsureAsync(ct);
        var all = new List<DeviceRecord>();
        await foreach (var d in devices.QueryAsync<DeviceRecord>(d => d.PartitionKey == tenantId, cancellationToken: ct)) all.Add(d);
        return all;
    }

    public async Task SaveAsync(DeviceRecord device, CancellationToken ct)
    {
        await EnsureAsync(ct);
        await devices.UpsertEntityAsync(device, TableUpdateMode.Replace, ct);
    }

    public async Task DeleteTenantAsync(string tenantId, CancellationToken ct)
    {
        await EnsureAsync(ct);
        await tenants.DeleteEntityAsync("tenant", tenantId, cancellationToken: ct);
    }

    public async Task DeleteDeviceAsync(string tenantId, string deviceKey, CancellationToken ct)
    {
        await EnsureAsync(ct);
        await devices.DeleteEntityAsync(tenantId, deviceKey, cancellationToken: ct);
    }
}
