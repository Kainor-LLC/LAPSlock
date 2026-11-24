using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;

namespace Kainor.TenantKeep.Watch;

/// <summary>A Graph call refused or failed; carries only the status, and whether Entra said the app is not in the tenant.</summary>
public sealed class GraphException(HttpStatusCode status, bool notInTenant = false) : Exception($"Microsoft Graph answered {(int)status}.")
{
    public HttpStatusCode Status { get; } = status;
    /// <summary>
    /// The organization has not approved TenantKeep Watch, removed it, or approved less than
    /// a read needs. Right for a registration, which answers with the approval link.
    /// </summary>
    public bool IsConsent => Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden;
    /// <summary>
    /// Entra itself said the app is not in that tenant, when the token was asked for. The
    /// only signal the nightly cleanup acts on: a 403 from one read (no Entra ID P1 for the
    /// sign-in log, no Defender), a token endpoint that is briefly down, and a 401 from
    /// Microsoft Graph itself are none of them. Before the second review (R2-16,
    /// 2026-11-24) a Graph 401 counted, though only Entra's answer was meant to.
    /// </summary>
    public bool IsNotInTenant { get; } = notInTenant;
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
        catch (AuthenticationFailedException e)
        {
            // Only Entra saying the app is not in that tenant is "removed". Every other
            // failure to get a token (the managed identity or the token endpoint briefly
            // unavailable, throttling) is a passing one: reporting those as 401 too had the
            // nightly cleanup delete every organization the failure touched.
            throw IsNotInTenant(e)
                ? new GraphException(HttpStatusCode.Unauthorized, notInTenant: true)
                : new GraphException(HttpStatusCode.ServiceUnavailable);
        }
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0" + pathAndQuery);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using var response = await http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode) throw new GraphException(response.StatusCode);
        await using var body = await response.Content.ReadAsStreamAsync(ct);
        return await JsonDocument.ParseAsync(body, cancellationToken: ct);
    }

    /// <summary>
    /// Whether a failed token request is Entra's definite answer that TenantKeep Watch is not
    /// in the tenant: no application there (AADSTS700016), no service principal
    /// (AADSTS7000229), the service principal disabled by the organization (AADSTS7000112),
    /// or no such tenant (AADSTS90002). A credential that could not be used at all is never
    /// that.
    /// </summary>
    internal static bool IsNotInTenant(Exception e)
    {
        if (e is CredentialUnavailableException) return false;
        var text = e.ToString();
        return NotInTenantCodes.Any(code => text.Contains(code, StringComparison.Ordinal));
    }

    static readonly string[] NotInTenantCodes = ["AADSTS700016", "AADSTS7000229", "AADSTS7000112", "AADSTS90002"];
}
