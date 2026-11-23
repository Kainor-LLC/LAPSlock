using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Kainor.TenantKeep.Watch;

/// <summary>
/// Once a day: a phone not seen for 30 days is deleted (HOSTED-WATCH-PLAN.md, decision 6), and
/// an organization that removed TenantKeep Watch loses everything held for it, once Entra
/// has said so for a full day.
/// </summary>
public sealed class Housekeeping(WatchStore store, ILogger<Housekeeping> log)
{
    static readonly TimeSpan PhoneLifetime = TimeSpan.FromDays(30);
    /// <summary>How long an organization must have been reported gone before it is deleted.</summary>
    internal static readonly TimeSpan GoneFor = TimeSpan.FromHours(24);

    /// <summary>
    /// Whether everything held for an organization should go. Not on one run's answer: the
    /// run a minute before this job could have failed for a passing reason, and deleting
    /// then removed every phone of every organization it touched, with nothing to tell them.
    /// </summary>
    internal static bool IsGone(TenantRecord tenant, DateTimeOffset now) =>
        tenant.State == "noConsent" && tenant.NoConsentSince is { } since && now - since >= GoneFor;

    [Function("Housekeeping")]
    public async Task Run([TimerTrigger("0 15 3 * * *")] TimerInfo timer, CancellationToken ct)
    {
        int phones = 0, organizations = 0;
        var cutoff = DateTimeOffset.UtcNow - PhoneLifetime;
        foreach (var tenant in await store.TenantsAsync(ct))
        {
            var devices = await store.DevicesAsync(tenant.TenantId, ct);
            var removed = IsGone(tenant, DateTimeOffset.UtcNow);
            foreach (var device in devices.Where(d => removed || (d.LastSeen ?? DateTimeOffset.MinValue) < cutoff))
            {
                await store.DeleteDeviceAsync(tenant.TenantId, device.RowKey, ct);
                phones++;
            }
            if (removed)
            {
                await store.DeleteTenantAsync(tenant.TenantId, ct);
                organizations++;
            }
        }
        log.LogInformation("Housekeeping phones={Phones} organizations={Organizations}", phones, organizations);
    }
}
