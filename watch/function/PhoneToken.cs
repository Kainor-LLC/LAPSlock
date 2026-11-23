using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Kainor.TenantKeep.Watch;

/// <summary>Who is registering a phone: their organization, their object ID, and their roles.</summary>
public sealed record PhoneCaller(string TenantId, string ObjectId, IReadOnlySet<string> Roles)
{
    /// <summary>The same caller with their roles as read from Graph.</summary>
    public PhoneCaller WithRoles(IEnumerable<string> roles) => this with { Roles = roles.ToHashSet() };

    // Entra role template IDs, as they appear in the token's wids claim. Only active roles
    // appear there: a PIM-eligible role has to be activated first.
    public const string GlobalAdministrator = "62e90394-69f5-4237-9190-012177145e10";
    public const string SecurityAdministrator = "194ae4cb-b126-40b2-bd5b-6091b380977d";
    public const string SecurityOperator = "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f";
    public const string SecurityReader = "5d6b6bb7-de71-4623-b4af-96380a352509";
    public const string GlobalReader = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";

    /// <summary>HOSTED-WATCH-PLAN.md decision 3: who may register a phone for an organization.</summary>
    public static readonly IReadOnlySet<string> MayRegister = new HashSet<string>
        { GlobalAdministrator, SecurityAdministrator, SecurityOperator, SecurityReader, GlobalReader };

    /// <summary>Who may choose which accounts are watched as break-glass accounts.</summary>
    public static readonly IReadOnlySet<string> MayConfigure = new HashSet<string>
        { GlobalAdministrator, SecurityAdministrator };

    public bool CanRegister => Roles.Overlaps(MayRegister);
    public bool CanConfigure => Roles.Overlaps(MayConfigure);
}

/// <summary>
/// Checks the bearer token a phone sends: issued by Microsoft Entra ID for the Alerts.Register
/// scope of the TenantKeep Alerts registration, signed by Entra's published keys, in date,
/// and from the tenant it names. No Graph token ever reaches the watcher; this one is good only for registering.
/// </summary>
public sealed class PhoneToken(WatchOptions options)
{
    const string Scope = "Alerts.Register";

    readonly ConfigurationManager<OpenIdConnectConfiguration> keys = new(
        "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
        new OpenIdConnectConfigurationRetriever(),
        new HttpDocumentRetriever { RequireHttps = true });

    readonly JsonWebTokenHandler handler = new();

    /// <summary>The caller, or null when the token is missing, invalid, or for something else.</summary>
    public async Task<PhoneCaller?> ValidateAsync(string? authorization, CancellationToken ct)
    {
        if (authorization is null || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        var configuration = await keys.GetConfigurationAsync(ct);
        var result = await handler.ValidateTokenAsync(authorization["Bearer ".Length..].Trim(), new TokenValidationParameters
        {
            ValidAudiences = options.AlertsApiAudiences,
            IssuerSigningKeys = configuration.SigningKeys,
            // Multi-tenant: the issuer must be Entra's for the tenant the token itself names.
            IssuerValidator = (issuer, token, _) =>
            {
                var tid = (token as JsonWebToken)?.GetPayloadValue<string>("tid");
                var expected = $"https://login.microsoftonline.com/{tid}/v2.0";
                return tid is not null && string.Equals(issuer, expected, StringComparison.OrdinalIgnoreCase)
                    ? issuer
                    : throw new SecurityTokenInvalidIssuerException("Issuer does not match the token's tenant.");
            },
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2),
        });
        if (!result.IsValid || result.SecurityToken is not JsonWebToken token) return null;

        var scopes = token.TryGetPayloadValue<string>("scp", out var scp) ? scp.Split(' ') : [];
        if (!scopes.Contains(Scope)) return null;
        // wids appears only when the app registration asks for directory roles in tokens;
        // the On-Call app does not, so an empty list means "not stated", and the endpoint
        // reads the caller's active roles from Graph instead (DeviceFunctions).
        var roles = token.TryGetPayloadValue<string[]>("wids", out var wids) ? wids : [];
        return new PhoneCaller(
            token.GetPayloadValue<string>("tid").ToLowerInvariant(),
            token.GetPayloadValue<string>("oid"),
            roles.ToHashSet());
    }
}
