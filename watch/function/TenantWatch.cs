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
            // One organization's failure, whatever it is, must not end the run for the
            // organizations after it: a timeout, a storage error, a relay outage or a
            // registered key that cannot be used once stopped everyone later in the list.
            try
            {
                var (watched, sent, failed) = await WatchOneAsync(tenant, slow, ct);
                if (watched) organizations++;
                alerts += sent;
                failures += failed;
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                failures++;
            }
        }
        // Counts only: no tenant, account, policy or device.
        log.LogInformation("TenantWatch organizations={Organizations} alerts={Alerts} failures={Failures}", organizations, alerts, failures);
    }

    async Task<(bool Watched, int Alerts, int Failures)> WatchOneAsync(TenantRecord tenant, bool slow, CancellationToken ct)
    {
        var devices = await store.DevicesAsync(tenant.TenantId, ct);
        if (devices.Count == 0) return (false, 0, 0);
        var pending = new List<(string Kind, string Title, string Body, string Link, bool Urgent)>();
        bool failed = false, notInTenant = false;

        // Each check on its own: a tenant without Entra ID P1 is refused the sign-in log,
        // and that must not stop its Conditional Access and incident checks from running.
        async Task Check(Func<Task> check)
        {
            try
            {
                await check();
            }
            catch (GraphException e)
            {
                failed = true;
                notInTenant |= e.IsNotInTenant;
            }
            catch (Exception e) when (e is HttpRequestException or JsonException or KeyNotFoundException or InvalidOperationException
                                      || (e is OperationCanceledException && !ct.IsCancellationRequested))
            {
                // A network error, a timeout, or a body that is not the shape expected.
                failed = true;
            }
        }

        if (tenant.BreakGlass.Length > 0)
            await Check(async () =>
            {
                if (await NewBreakGlassAsync(tenant, ct) is > 0 and var n)
                    pending.Add(("breakGlassSignIn", "Break-glass sign-in",
                        n == 1 ? $"{tenant.Label}: break-glass sign-in" : $"{tenant.Label}: {n} break-glass sign-ins",
                        "tenantkeep://people", true));
            });
        if (slow && !notInTenant)
        {
            await Check(async () =>
            {
                if (await NewPolicyChangesAsync(tenant, ct) is > 0 and var p)
                    pending.Add(("conditionalAccessChange", "Conditional Access change",
                        p == 1 ? $"{tenant.Label}: a Conditional Access policy changed" : $"{tenant.Label}: {p} Conditional Access changes",
                        "tenantkeep://conditionalAccess", false));
            });
            await Check(async () =>
            {
                if (await NewIncidentsAsync(tenant, ct) is { Count: > 0 } incidents)
                    pending.Add(("securityIncident", "Security incident",
                        IncidentBody(tenant.Label, incidents), "tenantkeep://security", incidents.Contains("high")));
            });
        }
        Settle(tenant, notInTenant, failed, DateTimeOffset.UtcNow);
        await store.SaveAsync(tenant, ct);

        int alerts = 0, failures = failed ? 1 : 0;
        foreach (var alert in pending)
            foreach (var device in devices)
            {
                // Each phone on its own too: one that cannot be sent to does not cost the others their alert.
                try
                {
                    var status = await sender.SendAsync(tenant.TenantId, device, alert.Kind, alert.Title, alert.Body, alert.Link, alert.Urgent, ct);
                    if (status == 202) alerts++;
                    else if (status == 410) await store.DeleteDeviceAsync(tenant.TenantId, device.RowKey, ct);
                    // Anything else is an alert that did not go. Counted, so a relay that
                    // refuses every one shows in the run's line instead of passing as quiet:
                    // a 402 for every subscriber once went unnoticed for exactly that reason.
                    else failures++;
                }
                catch (Exception) when (!ct.IsCancellationRequested)
                {
                    failures++;
                }
            }
        return (true, alerts, failures);
    }

    /// <summary>
    /// The state a run leaves. "noConsent" only on Entra's definite answer, with the time it
    /// was first given kept until a run succeeds or fails some other way: the nightly
    /// cleanup deletes after a day of it, never on one run.
    /// </summary>
    internal static void Settle(TenantRecord tenant, bool notInTenant, bool failed, DateTimeOffset now)
    {
        if (notInTenant)
        {
            tenant.State = "noConsent";
            tenant.NoConsentSince ??= now;
        }
        else
        {
            tenant.State = failed ? "error" : "ok";
            tenant.NoConsentSince = null;
        }
        tenant.LastRun = now;
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
