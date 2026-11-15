using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Kainor.TenantKeep.Watch;

/// <summary>
/// Every minute, one run for every organization with a registered phone (HOSTED-WATCH-PLAN.md,
/// decision 1): break-glass sign-ins every minute, Conditional Access changes and security
/// incidents every five. One run for all organizations is what keeps the cost flat. Each
/// check's first run only sets its cursor, so nothing from before is announced. Logs reach
/// Graph a few minutes late, so each read looks back fifteen minutes and drops what was seen.
///
/// An alert names the kind and the organization, never a person or a policy (decision 5):
/// the phone reads the detail itself, as the administrator, when it is tapped.
/// </summary>
public sealed class TenantWatch(WatchStore store, GraphReader graph, AlertSender sender, ILogger<TenantWatch> log)
{
    static readonly TimeSpan Overlap = TimeSpan.FromMinutes(15);

    [Function("TenantWatch")]
    public async Task Run([TimerTrigger("0 */1 * * * *")] TimerInfo timer, CancellationToken ct)
    {
        var slow = DateTime.UtcNow.Minute % 5 == 0;
        int organizations = 0, alerts = 0, failures = 0;
        foreach (var tenant in await store.TenantsAsync(ct))
        {
            var devices = await store.DevicesAsync(tenant.TenantId, ct);
            if (devices.Count == 0) continue;
            organizations++;
            var pending = new List<(string Kind, string Title, string Body, string Link, bool Urgent)>();
            try
            {
                if (tenant.BreakGlass.Length > 0 && await NewBreakGlassAsync(tenant, ct) is > 0 and var n)
                    pending.Add(("breakGlassSignIn", "Break-glass sign-in",
                        n == 1 ? $"{tenant.Label}: break-glass sign-in" : $"{tenant.Label}: {n} break-glass sign-ins",
                        "tenantkeep://people", true));
                if (slow)
                {
                    if (await NewPolicyChangesAsync(tenant, ct) is > 0 and var p)
                        pending.Add(("conditionalAccessChange", "Conditional Access change",
                            p == 1 ? $"{tenant.Label}: a Conditional Access policy changed" : $"{tenant.Label}: {p} Conditional Access changes",
                            "tenantkeep://conditionalAccess", false));
                    if (await NewIncidentsAsync(tenant, ct) is { Count: > 0 } incidents)
                        pending.Add(("securityIncident", "Security incident",
                            IncidentBody(tenant.Label, incidents), "tenantkeep://security", incidents.Contains("high")));
                }
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

            foreach (var alert in pending)
                foreach (var device in devices)
                {
                    var status = await sender.SendAsync(tenant.TenantId, device, alert.Kind, alert.Title, alert.Body, alert.Link, alert.Urgent, ct);
                    if (status == 202) alerts++;
                    if (status == 410) await store.DeleteDeviceAsync(tenant.TenantId, device.RowKey, ct);
                }
        }
        // Counts only: no tenant, account, policy or device.
        log.LogInformation("TenantWatch organizations={Organizations} alerts={Alerts} failures={Failures}", organizations, alerts, failures);
    }

    internal static string IncidentBody(string label, List<string> severities)
    {
        if (severities.Count == 1) return $"{label}: new {severities[0]} severity incident";
        var high = severities.Count(s => s == "high");
        return high > 0 ? $"{label}: {severities.Count} incidents, {high} high severity" : $"{label}: {severities.Count} new incidents";
    }

    /// <summary>Sign-ins by the named break-glass accounts not seen before.</summary>
    async Task<int> NewBreakGlassAsync(TenantRecord tenant, CancellationToken ct)
    {
        var (since, baseline) = Since(tenant.SignInCursor);
        var users = string.Join(" or ", tenant.BreakGlass.Select(id => $"userId eq '{id}'"));
        var filter = $"({users}) and createdDateTime ge {since.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ}";
        using var page = await graph.GetAsync(tenant.TenantId,
            "/auditLogs/signIns?$select=id,createdDateTime&$top=100&$filter=" + Uri.EscapeDataString(filter), ct);
        var (fresh, newest, seen) = Fresh(page, "createdDateTime", tenant.SignInCursor, tenant.SeenSignInIds);
        tenant.SignInCursor = newest;
        tenant.SeenSignInIds = seen;
        return baseline ? 0 : fresh;
    }

    /// <summary>Conditional Access policies added, updated or deleted, from the directory audit log.</summary>
    async Task<int> NewPolicyChangesAsync(TenantRecord tenant, CancellationToken ct)
    {
        var (since, baseline) = Since(tenant.PolicyCursor);
        var filter = $"loggedByService eq 'Conditional Access' and activityDateTime ge {since.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ}";
        using var page = await graph.GetAsync(tenant.TenantId,
            "/auditLogs/directoryAudits?$select=id,activityDateTime&$top=100&$filter=" + Uri.EscapeDataString(filter), ct);
        var (fresh, newest, seen) = Fresh(page, "activityDateTime", tenant.PolicyCursor, tenant.SeenPolicyIds);
        tenant.PolicyCursor = newest;
        tenant.SeenPolicyIds = seen;
        return baseline ? 0 : fresh;
    }

    /// <summary>
    /// The severities of incidents that are new, or whose severity rose, and are still open.
    /// An organization without Microsoft Defender XDR answers 403 here; that is not a missing
    /// approval, so it is skipped rather than failing the organization.
    /// </summary>
    async Task<List<string>> NewIncidentsAsync(TenantRecord tenant, CancellationToken ct)
    {
        var (since, baseline) = Since(tenant.IncidentCursor);
        var filter = $"lastUpdateDateTime ge {since.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ}";
        JsonDocument page;
        try
        {
            page = await graph.GetAsync(tenant.TenantId,
                "/security/incidents?$select=id,severity,status,lastUpdateDateTime&$top=50&$filter=" + Uri.EscapeDataString(filter), ct);
        }
        catch (GraphException e) when (e.Status == System.Net.HttpStatusCode.Forbidden)
        {
            return [];
        }
        using (page)
        {
            var seen = tenant.SeenIncidents.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Split(':')).Where(x => x.Length == 2).ToDictionary(x => x[0], x => x[1]);
            var newest = tenant.IncidentCursor ?? DateTimeOffset.UtcNow;
            var announce = new List<string>();
            foreach (var item in page.RootElement.GetProperty("value").EnumerateArray())
            {
                var id = item.GetProperty("id").GetString() ?? "";
                var severity = (item.TryGetProperty("severity", out var s) ? s.GetString() : null)?.ToLowerInvariant() ?? "unknown";
                var status = (item.TryGetProperty("status", out var st) ? st.GetString() : null)?.ToLowerInvariant() ?? "";
                if (item.TryGetProperty("lastUpdateDateTime", out var at) && at.TryGetDateTimeOffset(out var when) && when > newest) newest = when;
                var open = status is "active" or "inprogress";
                var rose = seen.TryGetValue(id, out var before) && Rank(severity) > Rank(before);
                if (open && (!seen.ContainsKey(id) || rose) && Rank(severity) >= Rank("medium")) announce.Add(severity);
                seen[id] = severity;
            }
            tenant.IncidentCursor = newest;
            tenant.SeenIncidents = string.Join(',', seen.TakeLast(200).Select(kv => kv.Key + ":" + kv.Value));
            return baseline ? [] : announce;
        }
    }

    static int Rank(string severity) => severity switch { "high" => 3, "medium" => 2, "low" => 1, _ => 0 };

    static (DateTimeOffset Since, bool Baseline) Since(DateTimeOffset? cursor) =>
        ((cursor ?? DateTimeOffset.UtcNow) - Overlap, cursor is null);

    /// <summary>How many items are new, the newest time, and the ids to remember.</summary>
    internal static (int Fresh, DateTimeOffset Newest, string Seen) Fresh(JsonDocument page, string timeField, DateTimeOffset? cursor, string seenIds)
    {
        var seen = seenIds.Split(',', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
        var fresh = new List<string>();
        var newest = cursor ?? DateTimeOffset.UtcNow;
        foreach (var item in page.RootElement.GetProperty("value").EnumerateArray())
        {
            var id = item.GetProperty("id").GetString() ?? "";
            if (item.TryGetProperty(timeField, out var at) && at.TryGetDateTimeOffset(out var when) && when > newest) newest = when;
            if (!seen.Contains(id)) fresh.Add(id);
        }
        return (fresh.Count, newest, string.Join(',', seen.Concat(fresh).TakeLast(200)));
    }
}
