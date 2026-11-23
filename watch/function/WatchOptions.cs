namespace Kainor.TenantKeep.Watch;

/// <summary>The function's settings, from the app settings main.bicep writes.</summary>
public sealed class WatchOptions
{
    public required string StorageAccount { get; init; }
    public required string WatchClientId { get; init; }
    public required string SenderKeySecretUri { get; init; }
    public required string RelayUrl { get; init; }
    public required string EntitlementUrl { get; init; }
    /// <summary>
    /// The relay's own app registration, as api://client-id: what this function's identity
    /// asks Microsoft Entra ID for a token for, to send as the alert service itself
    /// (RELAY-API.md section 15). While it is unset, alerts go the earlier way, with each
    /// organization's entitlement token, which delivers only to an organization licence.
    /// </summary>
    public string? RelayServiceAudience { get; init; }

    /// <summary>The alert service's route on the relay: beside the one RELAY_URL names.</summary>
    public string RelayServiceUrl => RelayUrl.TrimEnd('/') + "/service";
    /// <summary>
    /// The client ID of the registration that defines Alerts.Register: phones present tokens
    /// issued for that scope. More than one may be listed, separated by commas, while phones
    /// move from one registration to another.
    /// </summary>
    public required string AlertsApiAudience { get; init; }

    /// <summary>Each accepted audience, as the bare client ID and as its api:// form.</summary>
    public IReadOnlyList<string> AlertsApiAudiences =>
        [.. AlertsApiAudience
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .SelectMany(id => new[] { id, "api://" + id })];

    public static WatchOptions FromEnvironment() => new()
    {
        StorageAccount = Required("WATCH_STORAGE_ACCOUNT"),
        WatchClientId = Required("WATCH_CLIENT_ID"),
        SenderKeySecretUri = Required("SENDER_KEY_SECRET_URI"),
        RelayUrl = Required("RELAY_URL"),
        EntitlementUrl = Required("ENTITLEMENT_URL"),
        RelayServiceAudience = Environment.GetEnvironmentVariable("RELAY_SERVICE_AUDIENCE") is { Length: > 0 } audience ? audience.TrimEnd('/') : null,
        AlertsApiAudience = Required("ALERTS_API_AUDIENCE"),
    };

    static string Required(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"The app setting {name} is not set.");
}
