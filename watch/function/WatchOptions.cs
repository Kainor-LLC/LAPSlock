namespace Kainor.TenantKeep.Watch;

/// <summary>The function's settings, from the app settings main.bicep writes.</summary>
public sealed class WatchOptions
{
    public required string StorageAccount { get; init; }
    public required string WatchClientId { get; init; }
    public required string SenderKeySecretUri { get; init; }
    public required string RelayUrl { get; init; }
    public required string EntitlementUrl { get; init; }
    /// <summary>The On-Call app's client ID: phones present tokens issued for its Alerts.Register scope.</summary>
    public required string AlertsApiAudience { get; init; }

    public static WatchOptions FromEnvironment() => new()
    {
        StorageAccount = Required("WATCH_STORAGE_ACCOUNT"),
        WatchClientId = Required("WATCH_CLIENT_ID"),
        SenderKeySecretUri = Required("SENDER_KEY_SECRET_URI"),
        RelayUrl = Required("RELAY_URL"),
        EntitlementUrl = Required("ENTITLEMENT_URL"),
        AlertsApiAudience = Required("ALERTS_API_AUDIENCE"),
    };

    static string Required(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"The app setting {name} is not set.");
}
