using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Kainor.TenantKeep.Watch;

/// <summary>
/// Once a day: a phone not seen for 30 days is deleted (HOSTED-WATCH-PLAN.md, decision 6), and
/// an organization that removed TenantKeep Watch loses everything held for it.
/// </summary>
public sealed class Housekeeping(WatchStore store, ILogger<Housekeeping> log)
{
    static readonly TimeSpan PhoneLifetime = TimeSpan.FromDays(30);

    [Function("Housekeeping")]
    public async Task Run([TimerTrigger("0 15 3 * * *")] TimerInfo timer, CancellationToken ct)
    {
        int phones = 0, organizations = 0;
        var cutoff = DateTimeOffset.UtcNow - PhoneLifetime;
        foreach (var tenant in await store.TenantsAsync(ct))
        {
            var devices = await store.DevicesAsync(tenant.TenantId, ct);
            var removed = tenant.State == "noConsent";
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
