using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Kainor.TenantKeep.Relay;

/// <summary>Where the keys that sign Microsoft Entra ID's tokens for Kainor's tenant come from.</summary>
public interface IServiceKeys
{
    Task<IEnumerable<SecurityKey>> GetAsync(CancellationToken cancel);
}

/// <summary>Microsoft's published keys, fetched over HTTPS and refreshed as Microsoft rotates them.</summary>
public sealed class EntraServiceKeys(string tenantId) : IServiceKeys
{
    readonly ConfigurationManager<OpenIdConnectConfiguration> _configuration = new(
        $"https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration",
        new OpenIdConnectConfigurationRetriever(),
        new HttpDocumentRetriever { RequireHttps = true });

    public async Task<IEnumerable<SecurityKey>> GetAsync(CancellationToken cancel) =>
        (await _configuration.GetConfigurationAsync(cancel)).SigningKeys;
}

/// <summary>
/// docs/RELAY-API.md section 15: who is calling the alert service's route. The caller must be
/// Kainor's own alert service: a token Microsoft Entra ID issued in Kainor's tenant, for the
/// relay and nothing else, to an identity Kainor has given the Alerts.Send role. It names no
/// customer and nothing in it comes from one. Any failure is one answer.
/// </summary>
public sealed class ServiceCaller
{
    public enum Result { Valid, Invalid, Unavailable }

    public const string Role = "Alerts.Send";

    readonly string _tenantId;
    readonly string[] _audiences;
    readonly string[] _issuers;
    readonly IServiceKeys _keys;
    readonly string? _callerId;
    readonly JsonWebTokenHandler _handler = new();

    /// <param name="tenantId">Kainor's own tenant: the only one whose tokens are accepted.</param>
    /// <param name="clientId">The relay's app registration, which the token must be issued for.</param>
    /// <param name="callerId">The alert service's managed identity, by object ID. When given, the
    /// token must be that identity's: before the second review (R2-11, 2026-11-24) any identity in
    /// Kainor's tenant that was given the role was accepted.</param>
    public ServiceCaller(string tenantId, string clientId, IServiceKeys keys, string? callerId = null)
    {
        _tenantId = tenantId.ToLowerInvariant();
        _audiences = [clientId, "api://" + clientId];
        _issuers = [$"https://login.microsoftonline.com/{_tenantId}/v2.0", $"https://sts.windows.net/{_tenantId}/"];
        _keys = keys;
        _callerId = callerId;
    }

    public async Task<Result> VerifyAsync(string? authorization, CancellationToken cancel)
    {
        if (authorization is null || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return Result.Invalid;
        IEnumerable<SecurityKey> keys;
        try
        {
            keys = await _keys.GetAsync(cancel);
        }
        catch (Exception e) when (e is not OperationCanceledException || !cancel.IsCancellationRequested)
        {
            // Microsoft's keys could not be fetched: not the caller's fault, and worth their trying again.
            return Result.Unavailable;
        }
        var result = await _handler.ValidateTokenAsync(authorization["Bearer ".Length..].Trim(), new TokenValidationParameters
        {
            ValidAudiences = _audiences,
            ValidIssuers = _issuers,
            IssuerSigningKeys = keys,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ClockSkew = TimeSpan.FromMinutes(2),
        });
        if (!result.IsValid || result.SecurityToken is not JsonWebToken token) return Result.Invalid;
        if (!token.TryGetPayloadValue<string>("tid", out var tid) || !string.Equals(tid, _tenantId, StringComparison.OrdinalIgnoreCase)) return Result.Invalid;
        // An application's own token, never a person's: a delegated token carries scp.
        if (token.TryGetPayloadValue<string>("scp", out _)) return Result.Invalid;
        if (!(token.TryGetPayloadValue<string[]>("roles", out var roles) && roles.Contains(Role))) return Result.Invalid;
        // The alert service itself, when the relay has been told which identity that is.
        if (_callerId is { } expected
            && !(token.TryGetPayloadValue<string>("oid", out var oid) && string.Equals(oid, expected, StringComparison.OrdinalIgnoreCase)))
            return Result.Invalid;
        return Result.Valid;
    }
}
