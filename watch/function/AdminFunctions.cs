using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Kainor.TenantKeep.Watch;

/// <summary>
/// Kainor's own setup endpoints, for the first end-to-end test before the app registers
/// phones itself (H4). Each needs the function's key, which only Kainor holds; none is
/// reachable by a customer. They store only what WatchStore describes. Routes start manage/,
/// because Azure Functions keeps admin/ for its own host API.
/// </summary>
public sealed partial class AdminFunctions(WatchStore store, TenantSetup setup, AlertSender sender)
{
    [GeneratedRegex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    private static partial Regex TenantPattern();

    [GeneratedRegex("^[0-9a-f]{64,200}$")]
    private static partial Regex TokenPattern();

    public sealed record TenantBody(string Label, string[] BreakGlass);
    public sealed record DeviceBody(string PairingCode);

    /// <summary>Kainor-only endpoints say what failed, so a setup problem explains itself.</summary>
    static async Task<IActionResult> Explain(Func<Task<IActionResult>> work)
    {
        try
        {
            return await work();
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return new ObjectResult(new { error = e.GetType().Name, message = e.Message }) { StatusCode = 500 };
        }
    }

    /// <summary>Names the organization and its break-glass accounts (sign-in addresses or object IDs).</summary>
    [Function("AdminPutTenant")]
    public Task<IActionResult> PutTenant(
        [HttpTrigger(AuthorizationLevel.Function, "put", Route = "manage/tenants/{tenantId}")] HttpRequest request, string tenantId, CancellationToken ct) =>
        Explain(() => PutTenantCore(request, tenantId, ct));

    async Task<IActionResult> PutTenantCore(HttpRequest request, string tenantId, CancellationToken ct)
    {
        tenantId = tenantId.ToLowerInvariant();
        if (!TenantPattern().IsMatch(tenantId)) return new BadRequestObjectResult(new { error = "tenantId must be a GUID" });
        var body = await JsonSerializer.DeserializeAsync<TenantBody>(request.Body, JsonSerializerOptions.Web, ct);
        if (body is null || string.IsNullOrWhiteSpace(body.Label) || body.BreakGlass is not { Length: > 0 })
            return new BadRequestObjectResult(new { error = "label and breakGlass are required" });

        List<string> ids;
        try
        {
            ids = await setup.ObjectIdsAsync(tenantId, body.BreakGlass, ct);
        }
        catch (GraphException e)
        {
            return new ObjectResult(new { error = e.IsConsent ? "TenantKeep Watch is not approved in this tenant" : e.Message }) { StatusCode = 502 };
        }

        var tenant = await store.TenantAsync(tenantId, ct) ?? new TenantRecord { RowKey = tenantId };
        tenant.Label = body.Label.Trim();
        tenant.BreakGlassIds = string.Join(',', ids);
        tenant.SignInCursor = null;
        tenant.SeenSignInIds = "";
        tenant.State = "new";
        await store.SaveAsync(tenant, ct);
        return new OkObjectResult(new { tenantId, label = tenant.Label, breakGlassAccounts = ids.Count });
    }

    /// <summary>Registers a phone from the pairing code TenantKeep shows (tkrelay1), and returns the code the phone pins (tksender1).</summary>
    [Function("AdminAddDevice")]
    public Task<IActionResult> AddDevice(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = "manage/tenants/{tenantId}/devices")] HttpRequest request, string tenantId, CancellationToken ct) =>
        Explain(() => AddDeviceCore(request, tenantId, ct));

    async Task<IActionResult> AddDeviceCore(HttpRequest request, string tenantId, CancellationToken ct)
    {
        tenantId = tenantId.ToLowerInvariant();
        if (await store.TenantAsync(tenantId, ct) is null) return new NotFoundObjectResult(new { error = "set up the tenant first" });
        var body = await JsonSerializer.DeserializeAsync<DeviceBody>(request.Body, JsonSerializerOptions.Web, ct);
        if (body?.PairingCode is not { } code || !code.StartsWith("tkrelay1:", StringComparison.Ordinal))
            return new BadRequestObjectResult(new { error = "pairingCode must start tkrelay1:" });

        using var pairing = JsonDocument.Parse(Encoding.UTF8.GetString(Base64Url.Decode(code["tkrelay1:".Length..])));
        var root = pairing.RootElement;
        var token = root.GetProperty("deviceToken").GetString() ?? "";
        var environment = root.TryGetProperty("environment", out var env) ? env.GetString() ?? "production" : "production";
        var publicKey = root.GetProperty("publicKey").GetString() ?? "";
        if (!TokenPattern().IsMatch(token) || environment is not ("production" or "sandbox") || Base64Url.Decode(publicKey).Length != 65)
            return new BadRequestObjectResult(new { error = "the pairing code is malformed" });

        await store.SaveAsync(new DeviceRecord
        {
            PartitionKey = tenantId,
            RowKey = DeviceRecord.KeyFor(token),
            DeviceToken = token,
            Environment = environment,
            PublicKey = publicKey,
            LastSeen = DateTimeOffset.UtcNow,
        }, ct);
        return new OkObjectResult(new { senderCode = await sender.SenderCodeAsync(tenantId, ct) });
    }

    /// <summary>Sends a test alert to every phone registered for the tenant.</summary>
    [Function("AdminTest")]
    public Task<IActionResult> Test(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = "manage/tenants/{tenantId}/test")] HttpRequest request, string tenantId, CancellationToken ct) =>
        Explain(() => TestCore(request, tenantId, ct));

    async Task<IActionResult> TestCore(HttpRequest request, string tenantId, CancellationToken ct)
    {
        tenantId = tenantId.ToLowerInvariant();
        var tenant = await store.TenantAsync(tenantId, ct);
        if (tenant is null) return new NotFoundObjectResult(new { error = "set up the tenant first" });
        var results = new List<int>();
        foreach (var device in await store.DevicesAsync(tenantId, ct))
            results.Add(await sender.SendAsync(tenantId, device, "test", "Instant alerts test", $"{tenant.Label}: Instant alerts work on this phone.", null, timeSensitive: false, ct));
        return new OkObjectResult(new { phones = results.Count, relayStatuses = results });
    }

    /// <summary>The tenant's state: last run, phones, accounts. No identifiers beyond the counts.</summary>
    [Function("AdminGetTenant")]
    public Task<IActionResult> GetTenant(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "manage/tenants/{tenantId}")] HttpRequest request, string tenantId, CancellationToken ct) =>
        Explain(() => GetTenantCore(request, tenantId, ct));

    async Task<IActionResult> GetTenantCore(HttpRequest request, string tenantId, CancellationToken ct)
    {
        tenantId = tenantId.ToLowerInvariant();
        var tenant = await store.TenantAsync(tenantId, ct);
        if (tenant is null) return new NotFoundResult();
        var phones = (await store.DevicesAsync(tenantId, ct)).Count;
        return new OkObjectResult(new { tenantId, tenant.Label, breakGlassAccounts = tenant.BreakGlass.Length, phones, tenant.State, tenant.LastRun, tenant.SignInCursor, tenant.PolicyCursor, tenant.IncidentCursor });
    }
}
