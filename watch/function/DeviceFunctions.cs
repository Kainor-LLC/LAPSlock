using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Kainor.TenantKeep.Watch;

/// <summary>
/// What the app calls when an administrator turns Instant alerts on or off (HOSTED-WATCH-PLAN.md,
/// H4). Authenticated by a Microsoft token for the On-Call app's Alerts.Register scope from
/// an account holding a role in PhoneCaller.MayRegister; the organization is the token's own.
/// Registering again is the daily check-in: it refreshes the phone's last-seen time, its push
/// token, and, from an administrator who may configure, the break-glass accounts.
/// </summary>
public sealed partial class DeviceFunctions(WatchOptions options, PhoneToken tokens, WatchStore store, TenantSetup setup, AlertSender sender, ILogger<DeviceFunctions> log)
{
    [GeneratedRegex("^[0-9a-f]{64,200}$")]
    private static partial Regex TokenPattern();

    /// <summary>
    /// Phones one organization may have registered. Before the second review (R2-5,
    /// 2026-11-24) there was no limit, so one organization, a free trial tenant included,
    /// could register phones without end and hold every run, and the relay's one ceiling,
    /// for its own alerts. A phone already registered is checking in and always may.
    /// </summary>
    internal const int MaxPhonesPerOrganization = 20;

    internal static bool OverPhoneLimit(int registered, bool alreadyRegistered) =>
        !alreadyRegistered && registered >= MaxPhonesPerOrganization;

    internal static bool SameAccounts(IEnumerable<string> sent, IEnumerable<string> kept) =>
        sent.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(kept);

    /// <summary>
    /// What a registration writes to its organization's row: the name, and from an
    /// administrator who may configure, the break-glass accounts. Whether the accounts changed.
    /// The same accounts in another order are not a change: each change starts the sign-in
    /// baseline again (second review, R2-13, 2026-11-24).
    /// </summary>
    internal static bool Apply(TenantRecord tenant, string label, IReadOnlyCollection<string>? breakGlass)
    {
        tenant.Label = label;
        if (breakGlass is null || SameAccounts(breakGlass, tenant.BreakGlass)) return false;
        tenant.BreakGlassIds = string.Join(',', breakGlass.OrderBy(id => id, StringComparer.OrdinalIgnoreCase));
        tenant.SignInCursor = null;
        tenant.SeenSignInIds = "";
        return true;
    }

    public sealed record RegisterBody(string DeviceToken, string Environment, string PublicKey, string[]? BreakGlass);
    public sealed record UnregisterBody(string DeviceToken);

    [Function("RegisterDevice")]
    public async Task<IActionResult> Register(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "v1/devices")] HttpRequest request, CancellationToken ct)
    {
        var (found, refusal) = await tokens.CheckAsync(request.Headers.Authorization, ct);
        if (found is not { } caller) return Refused("RegisterDevice", refusal);

        RegisterBody? body;
        try { body = await JsonSerializer.DeserializeAsync<RegisterBody>(request.Body, JsonSerializerOptions.Web, ct); }
        catch (JsonException) { body = null; }
        if (body is null || !TokenPattern().IsMatch(body.DeviceToken ?? "") || body.Environment is not ("production" or "sandbox")
            || !IsPublicKey(body.PublicKey))
            return new BadRequestObjectResult(new { error = "malformed" });

        string label;
        try
        {
            label = await setup.NameAsync(caller.TenantId, ct);
        }
        catch (GraphException e) when (e.IsConsent)
        {
            return new ObjectResult(new { error = "approval", approvalUrl = TenantSetup.ApprovalUrl(caller.TenantId, options.WatchClientId) }) { StatusCode = 409 };
        }

        // The token's wids claim when present; otherwise the caller's active roles from Graph.
        if (caller.Roles.Count == 0) caller = caller.WithRoles(await setup.ActiveRolesAsync(caller.TenantId, caller.ObjectId, ct));
        if (!caller.CanRegister)
            return new ObjectResult(new { error = "role", message = "An active Global Administrator, Security Administrator, Security Operator, Security Reader or Global Reader role is needed." }) { StatusCode = 403 };

        var deviceKey = DeviceRecord.KeyFor(body.DeviceToken!);
        if (OverPhoneLimit(await store.CountDevicesAsync(caller.TenantId, MaxPhonesPerOrganization, ct),
                           await store.HasDeviceAsync(caller.TenantId, deviceKey, ct)))
        {
            log.LogInformation("RegisterDevice refused reason=limit");
            return new ObjectResult(new { error = "limit", limit = MaxPhonesPerOrganization }) { StatusCode = 429 };
        }

        List<string>? ids = null;
        if (body.BreakGlass is { } accounts && caller.CanConfigure)
        {
            try { ids = await setup.ObjectIdsAsync(caller.TenantId, accounts, ct); }
            catch (GraphException e) when (e.Status == HttpStatusCode.NotFound)
            {
                return new BadRequestObjectResult(new { error = "account", message = "One of the break-glass accounts was not found in this organization." });
            }
        }
        var tenant = await store.TenantAsync(caller.TenantId, ct) ?? new TenantRecord { RowKey = caller.TenantId };
        var breakGlassUpdated = Apply(tenant, label, ids);
        // Applied again to what is there now if a run wrote the row meanwhile (R2-12).
        await store.SaveAsync(tenant, now => breakGlassUpdated = Apply(now, label, ids) || breakGlassUpdated, ct);

        await store.SaveAsync(new DeviceRecord
        {
            PartitionKey = caller.TenantId,
            RowKey = deviceKey,
            DeviceToken = body.DeviceToken!,
            Environment = body.Environment,
            PublicKey = body.PublicKey,
            LastSeen = DateTimeOffset.UtcNow,
        }, ct);

        return new OkObjectResult(new
        {
            tenantId = caller.TenantId,
            label,
            senderKey = await sender.SenderKeyAsync(ct),
            breakGlassAccounts = tenant.BreakGlass.Length,
            breakGlassUpdated,
            canConfigure = caller.CanConfigure,
        });
    }

    [Function("UnregisterDevice")]
    public async Task<IActionResult> Unregister(
        [HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "v1/devices")] HttpRequest request, CancellationToken ct)
    {
        var (found, refusal) = await tokens.CheckAsync(request.Headers.Authorization, ct);
        if (found is not { } caller) return Refused("UnregisterDevice", refusal);
        UnregisterBody? body;
        try { body = await JsonSerializer.DeserializeAsync<UnregisterBody>(request.Body, JsonSerializerOptions.Web, ct); }
        catch (JsonException) { body = null; }
        if (body is null || !TokenPattern().IsMatch(body.DeviceToken ?? "")) return new BadRequestObjectResult(new { error = "malformed" });
        await store.DeleteDeviceAsync(caller.TenantId, DeviceRecord.KeyFor(body.DeviceToken!), ct);
        return new NoContentResult();
    }

    /// <summary>
    /// 401, with the kind of refusal in the log. A phone that is refused only sees "401", and
    /// until this line the log said no more than that.
    /// </summary>
    private UnauthorizedResult Refused(string endpoint, string? reason)
    {
        log.LogInformation("{Endpoint} refused reason={Reason}", endpoint, reason ?? "invalid");
        return new UnauthorizedResult();
    }

    /// <summary>
    /// A point on P-256, not only 65 bytes that begin 0x04. A key of the right shape that is
    /// not on the curve used to be stored, and then threw in the middle of every run that
    /// had an alert for its organization.
    /// </summary>
    internal static bool IsPublicKey(string? text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        try
        {
            var key = Base64Url.Decode(text);
            if (key.Length != 65 || key[0] != 0x04) return false;
            using var imported = global::TenantKeep.Relay.Hpke.Key(key);
            return true;
        }
        catch (FormatException) { return false; }
        catch (System.Security.Cryptography.CryptographicException) { return false; }
        catch (ArgumentException) { return false; }
    }
}
