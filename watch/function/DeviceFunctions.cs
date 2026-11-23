using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Kainor.TenantKeep.Watch;

/// <summary>
/// What the app calls when an administrator turns Instant alerts on or off (HOSTED-WATCH-PLAN.md,
/// H4). Authenticated by a Microsoft token for the On-Call app's Alerts.Register scope from
/// an account holding a role in PhoneCaller.MayRegister; the organization is the token's own.
/// Registering again is the daily check-in: it refreshes the phone's last-seen time, its push
/// token, and, from an administrator who may configure, the break-glass accounts.
/// </summary>
public sealed partial class DeviceFunctions(WatchOptions options, PhoneToken tokens, WatchStore store, TenantSetup setup, AlertSender sender)
{
    [GeneratedRegex("^[0-9a-f]{64,200}$")]
    private static partial Regex TokenPattern();

    public sealed record RegisterBody(string DeviceToken, string Environment, string PublicKey, string[]? BreakGlass);
    public sealed record UnregisterBody(string DeviceToken);

    [Function("RegisterDevice")]
    public async Task<IActionResult> Register(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "v1/devices")] HttpRequest request, CancellationToken ct)
    {
        var caller = await tokens.ValidateAsync(request.Headers.Authorization, ct);
        if (caller is null) return new UnauthorizedResult();

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

        var tenant = await store.TenantAsync(caller.TenantId, ct) ?? new TenantRecord { RowKey = caller.TenantId };
        tenant.Label = label;
        var breakGlassUpdated = false;
        if (body.BreakGlass is { } accounts && caller.CanConfigure)
        {
            List<string> ids;
            try { ids = await setup.ObjectIdsAsync(caller.TenantId, accounts, ct); }
            catch (GraphException e) when (e.Status == HttpStatusCode.NotFound)
            {
                return new BadRequestObjectResult(new { error = "account", message = "One of the break-glass accounts was not found in this organization." });
            }
            var joined = string.Join(',', ids);
            if (joined != tenant.BreakGlassIds)
            {
                tenant.BreakGlassIds = joined;
                tenant.SignInCursor = null;
                tenant.SeenSignInIds = "";
                breakGlassUpdated = true;
            }
        }
        await store.SaveAsync(tenant, ct);

        await store.SaveAsync(new DeviceRecord
        {
            PartitionKey = caller.TenantId,
            RowKey = DeviceRecord.KeyFor(body.DeviceToken!),
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
        var caller = await tokens.ValidateAsync(request.Headers.Authorization, ct);
        if (caller is null) return new UnauthorizedResult();
        UnregisterBody? body;
        try { body = await JsonSerializer.DeserializeAsync<UnregisterBody>(request.Body, JsonSerializerOptions.Web, ct); }
        catch (JsonException) { body = null; }
        if (body is null || !TokenPattern().IsMatch(body.DeviceToken ?? "")) return new BadRequestObjectResult(new { error = "malformed" });
        await store.DeleteDeviceAsync(caller.TenantId, DeviceRecord.KeyFor(body.DeviceToken!), ct);
        return new NoContentResult();
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
