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
        var notSent = new Dictionary<int, int>();
        var outcomes = new Outcomes();
        var secondTries = new Budget(10);
        foreach (var tenant in await store.TenantsAsync(ct))
        {
            // One organization's failure, whatever it is, must not end the run for the
            // organizations after it: a timeout, a storage error, a relay outage or a
            // registered key that cannot be used once stopped everyone later in the list.
            try
            {
                var (watched, sent, failed) = await WatchOneAsync(tenant, slow, notSent, outcomes, secondTries, ct);
                if (watched) organizations++;
                alerts += sent;
                failures += failed;
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                failures++;
            }
        }
        // Counts only: no tenant, account, policy or device. The relay's answers to alerts
        // that did not go are counted by status, because the relay keeps no request log and
        // nothing else says why a phone was not reached. `outcomes` says the same for every
        // alert, with Apple's word for a refusal and which of Apple's services the address is for.
        log.LogInformation("TenantWatch organizations={Organizations} alerts={Alerts} failures={Failures} notSent={NotSent} outcomes={Outcomes}",
            organizations, alerts, failures, NotSent(notSent), outcomes.ToString());
    }

    /// <summary>
    /// The alerts that did not go, as the relay's status and how many: "403x1,429x2", or
    /// "none". Status 0 is a request that got no answer at all.
    /// </summary>
    internal static string NotSent(Dictionary<int, int> byStatus) =>
        byStatus.Count == 0 ? "none" : string.Join(',', byStatus.OrderBy(s => s.Key).Select(s => $"{s.Key}x{s.Value}"));

    /// <summary>
    /// An address Apple will never deliver to, so it is dropped: 410 is an app that is gone,
    /// and BadDeviceToken is an address that does not belong to the service it was
    /// registered for. The second is counted as a failure the once, because a phone
    /// registered it believing it would be reached; left in place it failed on every alert
    /// for thirty days. A phone still in use registers again at its next check-in.
    /// </summary>
    internal static bool DeadAddress(int status, string? reason) =>
        status == 410 || (status == 502 && reason == "BadDeviceToken");

    /// <summary>
    /// What became of each alert in a run, as counts: the relay's status, its word for an
    /// alert that did not go (Apple's own, when Apple refused), and whether the phone's
    /// address is for Apple's production or sandbox service. "202 production x1, 502
    /// BadDeviceToken sandbox x2; newest 202 production". No organization, account or phone.
    /// `newest` is the same for the phone that registered or checked in last: the one
    /// somebody is usually holding when they ask why nothing arrived.
    /// </summary>
    internal sealed class Outcomes
    {
        readonly SortedDictionary<string, int> counts = new(StringComparer.Ordinal);
        (DateTimeOffset Seen, string What)? newest;

        public void Add(int status, string? reason, string? environment, DateTimeOffset? seen)
        {
            var what = status + (reason is null ? "" : " " + reason) + " " + (environment is "production" or "sandbox" ? environment : "unknown");
            counts[what] = counts.GetValueOrDefault(what) + 1;
            var at = seen ?? DateTimeOffset.MinValue;
            if (newest is not { } held || at >= held.Seen) newest = (at, what);
        }

        public override string ToString() =>
            newest is not { } last ? "none" : string.Join(", ", counts.Select(c => $"{c.Key} x{c.Value}")) + "; newest " + last.What;
    }

    /// <summary>A count that runs out: the run's second tries at alerts the relay did not take.</summary>
    internal sealed class Budget(int count)
    {
        int left = count;
        public bool Take() => left > 0 && left-- > 0;
    }

    async Task<(bool Watched, int Alerts, int Failures)> WatchOneAsync(TenantRecord tenant, bool slow, Dictionary<int, int> notSent, Outcomes outcomes, Budget secondTries, CancellationToken ct)
    {
        // No more phones than an organization may register, so no organization's alerts can
        // hold the run, or the relay's one ceiling, for long (second review, R2-5).
        var devices = await store.DevicesAsync(tenant.TenantId, DeviceFunctions.MaxPhonesPerOrganization, ct);
        if (devices.Count == 0) return (false, 0, 0);
        var pending = new List<(string Kind, string Title, string Body, string Link, bool Urgent)>();
        bool failed = false, notInTenant = false, ran = false;

        // Each check on its own: a tenant without Entra ID P1 is refused the sign-in log,
        // and that must not stop its Conditional Access and incident checks from running.
        async Task Check(Func<Task> check)
        {
            ran = true;
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
        Settle(tenant, ran, notInTenant, failed, DateTimeOffset.UtcNow);
        var ranFor = tenant.BreakGlassIds;
        var outcome = Snapshot(tenant);
        await store.SaveAsync(tenant, now => Reapply(outcome, ranFor, to: now), ct);

        int alerts = 0, failures = failed ? 1 : 0;
        foreach (var alert in pending)
            foreach (var device in devices)
            {
                // Each phone on its own too: one that cannot be sent to does not cost the others their alert.
                try
                {
                    var (status, reason) = await sender.SendAsync(tenant.TenantId, device, alert.Kind, alert.Title, alert.Body, alert.Link, alert.Urgent, ct, secondTries.Take);
                    outcomes.Add(status, reason, device.Environment, device.LastSeen);
                    if (status == 202) alerts++;
                    // Anything but Apple's own 410 is an alert that did not go. Counted, so a
                    // relay that refuses every one shows in the run's line instead of passing
                    // as quiet: a 402 for every subscriber once went unnoticed for exactly that reason.
                    else if (status != 410)
                    {
                        failures++;
                        notSent[status] = notSent.GetValueOrDefault(status) + 1;
                    }
                    if (DeadAddress(status, reason)) await store.DeleteDeviceAsync(tenant.TenantId, device.RowKey, ct);
                }
                catch (Exception) when (!ct.IsCancellationRequested)
                {
                    failures++;
                    notSent[0] = notSent.GetValueOrDefault(0) + 1;
                    outcomes.Add(0, null, device.Environment, device.LastSeen);
                }
            }
        return (true, alerts, failures);
    }

    /// <summary>
    /// The state a run leaves. "noConsent" only on Entra's definite answer, with the time it
    /// was first given kept until a run succeeds or fails some other way: the nightly
    /// cleanup deletes after a day of it, never on one run.
    ///
    /// A minute in which no check ran says nothing about the organization and leaves the
    /// state as the last check left it. Before the second review (R2-6, 2026-11-24) it set
    /// "ok" and cleared the clock, so an organization with no break-glass accounts named,
    /// checked every fifth minute, was found gone and cleared again the next minute, and
    /// was never deleted.
    /// </summary>
    internal static void Settle(TenantRecord tenant, bool ran, bool notInTenant, bool failed, DateTimeOffset now)
    {
        if (!ran) return;
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

    /// <summary>What a run writes to an organization's row: its cursors and its state, never the configuration.</summary>
    internal static TenantRecord Snapshot(TenantRecord ran) => new()
    {
        RowKey = ran.RowKey,
        SignInCursor = ran.SignInCursor,
        SeenSignInIds = ran.SeenSignInIds,
        PolicyCursor = ran.PolicyCursor,
        SeenPolicyIds = ran.SeenPolicyIds,
        IncidentCursor = ran.IncidentCursor,
        SeenIncidents = ran.SeenIncidents,
        State = ran.State,
        NoConsentSince = ran.NoConsentSince,
        LastRun = ran.LastRun,
    };

    /// <summary>
    /// A run's outcome applied to a row someone else wrote meanwhile. The name and the
    /// break-glass accounts stay as they are now. The sign-in cursor is the run's only if
    /// the accounts are the ones it checked: a registration that changed them started that
    /// baseline again, and the run's cursor belongs to the accounts before.
    /// </summary>
    internal static void Reapply(TenantRecord outcome, string ranForBreakGlass, TenantRecord to)
    {
        if (to.BreakGlassIds == ranForBreakGlass)
        {
            to.SignInCursor = outcome.SignInCursor;
            to.SeenSignInIds = outcome.SeenSignInIds;
        }
        to.PolicyCursor = outcome.PolicyCursor;
        to.SeenPolicyIds = outcome.SeenPolicyIds;
        to.IncidentCursor = outcome.IncidentCursor;
        to.SeenIncidents = outcome.SeenIncidents;
        to.State = outcome.State;
        to.NoConsentSince = outcome.NoConsentSince;
        to.LastRun = outcome.LastRun;
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
