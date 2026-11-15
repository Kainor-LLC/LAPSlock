using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;

namespace Kainor.TenantKeep.Watch;

/// <summary>A Graph call refused or failed; carries only the status.</summary>
public sealed class GraphException(HttpStatusCode status) : Exception($"Microsoft Graph answered {(int)status}.")
{
    public HttpStatusCode Status { get; } = status;
    /// <summary>The organization has not approved TenantKeep Watch, or removed it.</summary>
    public bool IsConsent => Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden;
}

/// <summary>
/// Reads an organization's tenant as the TenantKeep Watch app. There is no secret: the app's
/// federated credential trusts this function's managed identity, whose token is the
/// assertion. A tenant that has not approved the app, or removed it, fails here.
/// </summary>
public sealed class GraphReader(WatchOptions options, TokenCredential managedIdentity, HttpClient http)
{
    static readonly string[] GraphScope = ["https://graph.microsoft.com/.default"];
    static readonly string[] ExchangeScope = ["api://AzureADTokenExchange/.default"];
    readonly ConcurrentDictionary<string, ClientAssertionCredential> credentials = new();

    TokenCredential For(string tenantId) => credentials.GetOrAdd(tenantId, t =>
        new ClientAssertionCredential(t, options.WatchClientId, async ct =>
            (await managedIdentity.GetTokenAsync(new TokenRequestContext(ExchangeScope), ct)).Token));

    public async Task<JsonDocument> GetAsync(string tenantId, string pathAndQuery, CancellationToken ct)
    {
        AccessToken token;
        try
        {
            token = await For(tenantId).GetTokenAsync(new TokenRequestContext(GraphScope), ct);
        }
        catch (AuthenticationFailedException)
        {
            // No service principal in that tenant, or consent withdrawn.
            throw new GraphException(HttpStatusCode.Unauthorized);
        }
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0" + pathAndQuery);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using var response = await http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode) throw new GraphException(response.StatusCode);
        await using var body = await response.Content.ReadAsStreamAsync(ct);
        return await JsonDocument.ParseAsync(body, cancellationToken: ct);
    }
}
