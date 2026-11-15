using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Kainor.TenantKeep.Watch;

/// <summary>
/// Every minute, for every organization with break-glass accounts named: their sign-ins since
/// the cursor, and an alert to each registered phone for any not seen before. One run covers
/// every organization, which is what keeps the cost flat. The first run for an organization
/// only sets the cursor. Sign-ins reach the log a few minutes late, so each read looks back
/// fifteen minutes and drops ids already seen.
/// </summary>
public sealed class BreakGlassWatch(WatchStore store, GraphReader graph, AlertSender sender, ILogger<BreakGlassWatch> log)
{
    static readonly TimeSpan Overlap = TimeSpan.FromMinutes(15);

    [Function("BreakGlassWatch")]
    public async Task Run([TimerTrigger("0 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        int organizations = 0, alerts = 0, failures = 0;
        foreach (var tenant in await store.TenantsAsync(ct))
        {
            if (tenant.BreakGlass.Length == 0) continue;
            organizations++;
            try
            {
                alerts += await CheckAsync(tenant, ct);
                tenant.State = "ok";
            }
            catch (GraphException e)
            {
                tenant.State = e.IsConsent ? "noConsent" : "error";
                failures++;
            }
            catch (HttpRequestException)
            {
                tenant.State = "error";
                failures++;
            }
            tenant.LastRun = DateTimeOffset.UtcNow;
            await store.SaveAsync(tenant, ct);
        }
        // Counts only: no tenant, account or device.
        log.LogInformation("BreakGlassWatch organizations={Organizations} alerts={Alerts} failures={Failures}", organizations, alerts, failures);
    }

    async Task<int> CheckAsync(TenantRecord tenant, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var baseline = tenant.SignInCursor is null;
        var since = (tenant.SignInCursor ?? now) - Overlap;
        var users = string.Join(" or ", tenant.BreakGlass.Select(id => $"userId eq '{id}'"));
        var filter = $"({users}) and createdDateTime ge {since.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ}";
        using var page = await graph.GetAsync(tenant.TenantId,
            "/auditLogs/signIns?$select=id,createdDateTime&$top=100&$filter=" + Uri.EscapeDataString(filter), ct);

        var seen = tenant.SeenSignInIds.Split(',', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
        var fresh = new List<string>();
        var newest = tenant.SignInCursor ?? now;
        foreach (var item in page.RootElement.GetProperty("value").EnumerateArray())
        {
            var id = item.GetProperty("id").GetString() ?? "";
            if (item.TryGetProperty("createdDateTime", out var at) && at.TryGetDateTimeOffset(out var when) && when > newest) newest = when;
            if (!seen.Contains(id)) fresh.Add(id);
        }
        tenant.SignInCursor = newest;
        tenant.SeenSignInIds = string.Join(',', seen.Concat(fresh).TakeLast(200));
        if (baseline || fresh.Count == 0) return 0;

        var body = fresh.Count == 1 ? $"{tenant.Label}: break-glass sign-in" : $"{tenant.Label}: {fresh.Count} break-glass sign-ins";
        var sent = 0;
        foreach (var device in await store.DevicesAsync(tenant.TenantId, ct))
        {
            var status = await sender.SendAsync(tenant.TenantId, device, "breakGlassSignIn", "Break-glass sign-in", body, timeSensitive: true, ct);
            if (status == 202) sent++;
            if (status == 410) await store.DeleteDeviceAsync(tenant.TenantId, device.RowKey, ct);
        }
        return sent;
    }
}
