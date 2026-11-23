using System.Text.Json;

namespace Kainor.TenantKeep.Relay;

/// <summary>
/// The relay's whole job, outside the Functions runtime so it can be tested: check, limit,
/// forward, answer. It keeps nothing and logs nothing from the request. Its only output is
/// the status and the JSON body, which never echo a device token, an envelope, a tenant ID
/// or a token of either kind. docs/RELAY-API.md sections 2 to 9, and 15 for the alert
/// service's route.
/// </summary>
public sealed class RelayHandler
{
    readonly EntitlementCheck _entitlement;
    readonly RelayRateLimiter _limiter;
    readonly IApnsSender _apns;
    readonly ServiceCaller? _service;

    public RelayHandler(EntitlementCheck entitlement, RelayRateLimiter limiter, IApnsSender apns, ServiceCaller? service = null)
    {
        _entitlement = entitlement;
        _limiter = limiter;
        _apns = apns;
        _service = service;
    }

    public sealed record Answer(int Status, string Body, int? RetryAfter = null);

    static Answer Error(int status, string code, string message, int? retryAfter = null) =>
        new(status, JsonSerializer.Serialize(new { error = code, message }), retryAfter);

    /// <summary>POST /relay: a sender with a paying tenant's entitlement token in the body.</summary>
    public async Task<Answer> HandleAsync(byte[] body, bool hasQuery, string? address, CancellationToken cancel)
    {
        if (Refused(body, hasQuery) is { } refused) return refused;
        if (Parsed(body, service: false, out var request) is { } malformed) return malformed;
        var (verdict, tenant) = _entitlement.Verify(request!.Entitlement!);
        if (verdict == EntitlementCheck.Result.Invalid) return Error(401, "entitlement_invalid", "The entitlement token did not verify.");
        if (verdict == EntitlementCheck.Result.Unpaid) return Error(402, "entitlement_tier", "Relayed alerts are part of Pro.");
        if (!_limiter.TryAcquire(tenant!, request.DeviceToken, address, request.Environment == "sandbox")) return Limited();
        return await ForwardAsync(request, cancel);
    }

    /// <summary>
    /// POST /relay/service: Kainor's own alert service, by its identity's token in the
    /// Authorization header. The caller is checked before the body is read, and the body
    /// carries no tenant and no entitlement token, so this route never sees whose alert it is.
    /// </summary>
    public async Task<Answer> HandleServiceAsync(byte[] body, bool hasQuery, string? authorization, CancellationToken cancel)
    {
        if (Refused(body, hasQuery) is { } refused) return refused;
        var caller = _service is null ? ServiceCaller.Result.Invalid : await _service.VerifyAsync(authorization, cancel);
        if (caller == ServiceCaller.Result.Unavailable) return Error(503, "keys_unavailable", "The caller could not be checked just now. Nothing was kept; try again shortly.");
        if (caller != ServiceCaller.Result.Valid) return Error(401, "service_token_invalid", "This route is for Kainor's alert service.");
        if (Parsed(body, service: true, out var request) is { } malformed) return malformed;
        if (!_limiter.TryAcquireService(request!.DeviceToken, request.Environment == "sandbox")) return Limited();
        return await ForwardAsync(request, cancel);
    }

    static Answer? Refused(byte[] body, bool hasQuery)
    {
        if (body.Length > RelayRequest.BodyLimit) return Error(413, "too_large", "The body is over 6 KiB.");
        return hasQuery ? Error(400, "bad_request", "No query string is accepted.") : null;
    }

    static Answer? Parsed(byte[] body, bool service, out RelayRequest? request)
    {
        (request, var problem) = RelayRequest.Parse(body, service);
        if (request is not null) return null;
        return problem == "too_large" ? Error(413, "too_large", "The ciphertext is over its limit.") : Error(400, "bad_request", "The request does not match version 1 of the contract.");
    }

    Answer Limited() => Error(429, "rate_limited", "Too many requests. Try again shortly.", _limiter.SecondsUntilNextWindow);

    async Task<Answer> ForwardAsync(RelayRequest request, CancellationToken cancel)
    {
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
