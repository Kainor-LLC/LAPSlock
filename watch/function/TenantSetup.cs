namespace Kainor.TenantKeep.Watch;

/// <summary>Reading an organization as the Watch app: its name, and its break-glass accounts' object IDs.</summary>
public sealed class TenantSetup(GraphReader graph)
{
    /// <summary>The organization's display name. Throws GraphException when the Watch app is not approved there.</summary>
    public async Task<string> NameAsync(string tenantId, CancellationToken ct)
    {
        using var org = await graph.GetAsync(tenantId, "/organization?$select=displayName", ct);
        var first = org.RootElement.GetProperty("value").EnumerateArray().FirstOrDefault();
        return first.ValueKind == System.Text.Json.JsonValueKind.Object && first.TryGetProperty("displayName", out var name)
            ? name.GetString() ?? "Your organization"
            : "Your organization";
    }

    /// <summary>The object IDs of the named accounts (sign-in addresses or object IDs). Throws GraphException for one that is not found.</summary>
    public async Task<List<string>> ObjectIdsAsync(string tenantId, IEnumerable<string> accounts, CancellationToken ct)
    {
        var ids = new List<string>();
        foreach (var account in accounts.Select(a => a.Trim()).Where(a => a.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            using var user = await graph.GetAsync(tenantId, "/users/" + Uri.EscapeDataString(account) + "?$select=id", ct);
            ids.Add(user.RootElement.GetProperty("id").GetString()!);
        }
        return ids;
    }

    /// <summary>
    /// The role template IDs of the user's active directory roles, direct or through a
    /// role-assignable group. A PIM-eligible role that is not activated is not among them.
    /// </summary>
    public async Task<List<string>> ActiveRolesAsync(string tenantId, string objectId, CancellationToken ct)
    {
        using var page = await graph.GetAsync(tenantId,
            "/users/" + Uri.EscapeDataString(objectId) + "/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId", ct);
        return page.RootElement.GetProperty("value").EnumerateArray()
            .Select(r => r.TryGetProperty("roleTemplateId", out var id) ? id.GetString() : null)
            .OfType<string>()
            .ToList();
    }

    /// <summary>Where an organization's administrator approves TenantKeep Watch once.</summary>
    public static string ApprovalUrl(string tenantId, string watchClientId) =>
        $"https://login.microsoftonline.com/{tenantId}/adminconsent?client_id={watchClientId}&redirect_uri={Uri.EscapeDataString(ApprovedPage)}";

    public const string ApprovedPage = "https://kainor.com/instant-alerts/approved/";
}
