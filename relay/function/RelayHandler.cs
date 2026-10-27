using System.Text.Json;

namespace Kainor.TenantKeep.Relay;

/// <summary>
/// The relay's whole job, outside the Functions runtime so it can be tested: check, limit,
/// forward, answer. It keeps nothing and logs nothing from the request. Its only output is
/// the status and the JSON body, which never echo a device token, an envelope, a tenant ID
/// or an entitlement token. docs/RELAY-API.md sections 2 to 9.
/// </summary>
public sealed class RelayHandler
{
    readonly EntitlementCheck _entitlement;
    readonly RelayRateLimiter _limiter;
    readonly IApnsSender _apns;

    public RelayHandler(EntitlementCheck entitlement, RelayRateLimiter limiter, IApnsSender apns)
    {
        _entitlement = entitlement;
        _limiter = limiter;
        _apns = apns;
    }

    public sealed record Answer(int Status, string Body, int? RetryAfter = null);

    static Answer Error(int status, string code, string message, int? retryAfter = null) =>
        new(status, JsonSerializer.Serialize(new { error = code, message }), retryAfter);

    public async Task<Answer> HandleAsync(byte[] body, bool hasQuery, string? address, CancellationToken cancel)
    {
        if (body.Length > RelayRequest.BodyLimit) return Error(413, "too_large", "The body is over 6 KiB.");
        if (hasQuery) return Error(400, "bad_request", "No query string is accepted.");
        var (request, problem) = RelayRequest.Parse(body);
        if (request is null)
            return problem == "too_large" ? Error(413, "too_large", "The ciphertext is over its limit.") : Error(400, "bad_request", "The request does not match version 1 of the contract.");
        var (verdict, tenant) = _entitlement.Verify(request.Entitlement);
        if (verdict == EntitlementCheck.Result.Invalid) return Error(401, "entitlement_invalid", "The entitlement token did not verify.");
        if (verdict == EntitlementCheck.Result.Unpaid) return Error(402, "entitlement_tier", "Relayed alerts are part of Pro.");
        if (!_limiter.TryAcquire(tenant!, request.DeviceToken, address, request.Environment == "sandbox"))
            return Error(429, "rate_limited", "Too many requests. Try again shortly.", _limiter.SecondsUntilNextWindow);
        var result = await _apns.SendAsync(request.DeviceToken, request.Environment == "sandbox", request.Urgency == "time-sensitive", request.Enc, request.Ct, cancel);
        return result.Status switch
        {
            200 => new Answer(202, JsonSerializer.Serialize(new { apnsId = result.ApnsId })),
            410 => Error(410, "device_unregistered", "Apple no longer recognizes this device token. Pair the phone again."),
            429 or >= 500 => Error(503, "apns_unavailable", "Apple did not take the notification. Nothing was kept; try again later."),
            _ => Error(502, "apns_rejected", "Apple refused the notification: " + SafeReason(result.Reason) + "."),
        };
    }

    /// Apple's reason strings are short identifiers such as BadDeviceToken; anything else is
    /// not passed on.
    static string SafeReason(string? reason) =>
        reason is { Length: > 0 and <= 40 } && reason.All(char.IsLetterOrDigit) ? reason : "no reason given";
}
