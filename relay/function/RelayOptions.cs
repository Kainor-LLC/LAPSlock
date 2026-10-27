namespace Kainor.TenantKeep.Relay;

/// <summary>Configuration, from app settings. Nothing here is a secret: the APNs signing key
/// stays in Key Vault and is reached through the managed identity.</summary>
public sealed record RelayOptions(string ApnsKeyId, string TeamId, string KeyVaultKeyId, string Topic)
{
    public static RelayOptions FromEnvironment() => new(
        Require("APNS_KEY_ID"),
        Require("APNS_TEAM_ID"),
        Require("APNS_KEYVAULT_KEY_ID"),
        Environment.GetEnvironmentVariable("APNS_TOPIC") ?? "com.kainor.lapslock");

    static string Require(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : throw new InvalidOperationException(name + " is not set");
}
