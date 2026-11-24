namespace Kainor.TenantKeep.Relay;

/// <summary>Configuration, from app settings. Nothing here is a secret: the APNs signing key
/// stays in Key Vault and is reached through the managed identity.</summary>
/// <param name="ServiceTenantId">Kainor's own tenant, whose tokens the alert service's route accepts.</param>
/// <param name="ServiceClientId">The relay's app registration, which those tokens must be issued for.
/// With either unset the alert service's route refuses everyone; the route in section 2 is unaffected.</param>
/// <param name="ServiceCallerId">The alert service's managed identity, by its object (principal) ID.
/// When set, a token on the alert service's route must be that identity's.</param>
public sealed record RelayOptions(string ApnsKeyId, string TeamId, string KeyVaultKeyId, string Topic, string? ServiceTenantId = null, string? ServiceClientId = null, string? ServiceCallerId = null)
{
    public static RelayOptions FromEnvironment() => new(
        Require("APNS_KEY_ID"),
        Require("APNS_TEAM_ID"),
        Require("APNS_KEYVAULT_KEY_ID"),
        Environment.GetEnvironmentVariable("APNS_TOPIC") ?? "com.kainor.lapslock",
        Optional("SERVICE_TENANT_ID"),
        Optional("SERVICE_CLIENT_ID"),
        Optional("SERVICE_CALLER_ID"));

    static string? Optional(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } v && Guid.TryParse(v, out var id) ? id.ToString() : null;

    static string Require(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : throw new InvalidOperationException(name + " is not set");
}
