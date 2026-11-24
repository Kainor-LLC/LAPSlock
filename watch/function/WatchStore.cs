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
    /// <summary>The newest Conditional Access audit time seen. Null until that check's baseline.</summary>
    public DateTimeOffset? PolicyCursor { get; set; }
    public string SeenPolicyIds { get; set; } = "";
    /// <summary>The newest incident update seen. Null until that check's baseline.</summary>
    public DateTimeOffset? IncidentCursor { get; set; }
    /// <summary>Incidents already announced, as id:severity, comma separated.</summary>
    public string SeenIncidents { get; set; } = "";
    /// <summary>ok, noConsent, or error, from the last run.</summary>
    public string State { get; set; } = "new";
    /// <summary>
    /// When the state first became noConsent and has stayed so. The nightly cleanup deletes
    /// an organization only after a day of it, never on one run's answer.
    /// </summary>
    public DateTimeOffset? NoConsentSince { get; set; }
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

    /// <summary>
    /// Writes the row only if nobody has written it since it was read. If someone has, it is
    /// read again, <paramref name="change"/> applies this writer's own fields to what is there
    /// now, and that is written. Before the second review (R2-12, 2026-11-24) rows were
    /// replaced outright, so a minute's run that read an organization before an
    /// administrator's change wrote its stale copy over it, every daily check-in included.
    /// </summary>
    public async Task SaveAsync(TenantRecord tenant, Action<TenantRecord> change, CancellationToken ct)
    {
        await EnsureAsync(ct);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                var written = tenant.ETag == default
                    ? await tenants.AddEntityAsync(tenant, ct)
                    : await tenants.UpdateEntityAsync(tenant, tenant.ETag, TableUpdateMode.Replace, ct);
                tenant.ETag = written.Headers.ETag ?? default;
                return;
            }
            catch (RequestFailedException e) when (e.Status is 409 or 412)
            {
                var now = await TenantAsync(tenant.TenantId, ct) ?? new TenantRecord { RowKey = tenant.RowKey };
                change(now);
                tenant = now;
            }
        }
        throw new InvalidOperationException("An organization's row kept changing while it was written.");
    }

    public async Task<List<DeviceRecord>> DevicesAsync(string tenantId, CancellationToken ct)
    {
        await EnsureAsync(ct);
        var all = new List<DeviceRecord>();
        await foreach (var d in devices.QueryAsync<DeviceRecord>(d => d.PartitionKey == tenantId, cancellationToken: ct)) all.Add(d);
        return all;
    }

    /// <summary>
    /// No more than <paramref name="limit"/> of the organization's phones: the minute run's
    /// read, so an organization with more phones than it may have cannot make every run
    /// longer for the organizations after it (second review, R2-5).
    /// </summary>
    public async Task<List<DeviceRecord>> DevicesAsync(string tenantId, int limit, CancellationToken ct)
    {
        await EnsureAsync(ct);
        var some = new List<DeviceRecord>();
        await foreach (var d in devices.QueryAsync<DeviceRecord>(d => d.PartitionKey == tenantId, maxPerPage: limit, cancellationToken: ct))
        {
            some.Add(d);
            if (some.Count >= limit) break;
        }
        return some;
    }

    /// <summary>Whether this phone is registered for the organization already. A point read of its key.</summary>
    public async Task<bool> HasDeviceAsync(string tenantId, string deviceKey, CancellationToken ct)
    {
        await EnsureAsync(ct);
        var found = await devices.GetEntityIfExistsAsync<TableEntity>(tenantId, deviceKey, select: ["RowKey"], cancellationToken: ct);
        return found.HasValue;
    }

    /// <summary>The organization's phones, counted up to <paramref name="upTo"/> and no further. Only their keys are read.</summary>
    public async Task<int> CountDevicesAsync(string tenantId, int upTo, CancellationToken ct)
    {
        await EnsureAsync(ct);
        var count = 0;
        await foreach (var _ in devices.QueryAsync<TableEntity>(TableClient.CreateQueryFilter($"PartitionKey eq {tenantId}"), maxPerPage: upTo, select: ["RowKey"], cancellationToken: ct))
            if (++count >= upTo) break;
        return count;
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
