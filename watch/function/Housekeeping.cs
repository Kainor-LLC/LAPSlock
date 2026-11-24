using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Kainor.TenantKeep.Watch;

/// <summary>
/// Once a day: a phone not seen for 30 days is deleted (HOSTED-WATCH-PLAN.md, decision 6); an
/// organization that removed TenantKeep Watch loses everything held for it, once Entra has
/// said so for a full day; and an organization with no phones left loses its row.
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

    /// <summary>How long a row with no phones must have been left alone before it is deleted.</summary>
    internal static readonly TimeSpan QuietFor = TimeSpan.FromHours(1);

    /// <summary>
    /// Whether an organization's row goes tonight: it was found gone for a day, or it has no
    /// phones left. A row with no phones alerts nobody, and the minute run skips it before
    /// anything is asked, so the service never learned the app was removed and kept the
    /// organization's name, break-glass accounts and last events for good (second review,
    /// R2-6, 2026-11-24). The hour is for a registration that has saved the row and not yet
    /// its phone.
    /// </summary>
    internal static bool ShouldDelete(TenantRecord tenant, bool gone, int phonesLeft, DateTimeOffset now) =>
        gone || (phonesLeft == 0 && (tenant.Timestamp ?? DateTimeOffset.MinValue) <= now - QuietFor);

    /// <summary>
    /// More organizations reported gone in one night than this is a mistake on Kainor's side,
    /// such as the wrong WATCH_CLIENT_ID or the Watch registration disabled, which makes every
    /// organization look gone; the cleanup then deletes none of them and says so. Three, or a
    /// tenth of all organizations, whichever is more (second review, R2-16, 2026-11-24).
    /// </summary>
    internal static bool TooManyGone(int gone, int organizations) => gone > Math.Max(3, organizations / 10);

    [Function("Housekeeping")]
    public async Task Run([TimerTrigger("0 15 3 * * *")] TimerInfo timer, CancellationToken ct)
    {
        int phones = 0, organizations = 0;
        var now = DateTimeOffset.UtcNow;
        var cutoff = now - PhoneLifetime;
        var tenants = await store.TenantsAsync(ct);
        var gone = tenants.Where(t => IsGone(t, now)).Select(t => t.TenantId).ToHashSet();
        if (TooManyGone(gone.Count, tenants.Count))
        {
            log.LogWarning("Housekeeping refused gone={Gone} organizations={All}: more than a night's limit", gone.Count, tenants.Count);
            gone.Clear();
        }
        foreach (var tenant in tenants)
        {
            var devices = await store.DevicesAsync(tenant.TenantId, ct);
            var removed = gone.Contains(tenant.TenantId);
            var left = 0;
            foreach (var device in devices)
            {
                if (removed || (device.LastSeen ?? DateTimeOffset.MinValue) < cutoff)
                {
                    await store.DeleteDeviceAsync(tenant.TenantId, device.RowKey, ct);
                    phones++;
                }
                else left++;
            }
            if (ShouldDelete(tenant, removed, left, now))
            {
                await store.DeleteTenantAsync(tenant.TenantId, ct);
                organizations++;
            }
        }
        log.LogInformation("Housekeeping phones={Phones} organizations={Organizations}", phones, organizations);
    }
}
