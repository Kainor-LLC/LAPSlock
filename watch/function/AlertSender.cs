using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using TenantKeep.Relay;

namespace Kainor.TenantKeep.Watch;

/// <summary>
/// Sends one alert to one phone through the relay, exactly as RELAY-API.md describes: the
/// alert sealed with HPKE in authenticated mode, from the watcher's sender key to the phone's
/// Secure Enclave key. The relay is told who is sending by this function's own identity
/// (section 15), so what it is sent names no organization.
/// </summary>
/// <summary>What the relay answered to one alert for one phone.</summary>
public readonly record struct Sent(int Status, string? Reason);

public sealed class AlertSender(WatchOptions options, TokenCredential credential, HttpClient http)
{
    const string Suite = "DHKEM-P256-HKDF-SHA256/HKDF-SHA256/AES-256-GCM";
    static readonly byte[] Info = Encoding.ASCII.GetBytes("TenantKeep relay v1");
    readonly SemaphoreSlim keyLock = new(1, 1);
    readonly ConcurrentDictionary<string, (string Token, DateTimeOffset Fetched)> entitlements = new();
    ECDiffieHellman? key;

    async Task<ECDiffieHellman> KeyAsync(CancellationToken ct)
    {
        if (key is not null) return key;
        await keyLock.WaitAsync(ct);
        try
        {
            if (key is not null) return key;
            var uri = new Uri(options.SenderKeySecretUri);
            var client = new SecretClient(new Uri(uri.GetLeftPart(UriPartial.Authority)), credential);
            var secret = await client.GetSecretAsync(uri.Segments[^1].Trim('/'), cancellationToken: ct);
            var loaded = ECDiffieHellman.Create();
            loaded.ImportPkcs8PrivateKey(Convert.FromBase64String(secret.Value.Value), out _);
            key = loaded;
            return key;
        }
        finally
        {
            keyLock.Release();
        }
    }

    /// <summary>The sender's public key, X9.63, base64url: what a phone pins for the tenant it registered for.</summary>
    public async Task<string> SenderKeyAsync(CancellationToken ct) => Base64Url.Encode(Hpke.PublicBytes(await KeyAsync(ct)));

    async Task<string> EntitlementAsync(string tenantId, CancellationToken ct)
    {
        if (entitlements.TryGetValue(tenantId, out var held) && DateTimeOffset.UtcNow - held.Fetched < TimeSpan.FromHours(12))
            return held.Token;
        using var response = await http.PostAsJsonAsync(options.EntitlementUrl, new { version = 1, tenantId = tenantId.ToLowerInvariant() }, ct);
        response.EnsureSuccessStatusCode();
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var token = body.RootElement.GetProperty("token").GetString() ?? throw new InvalidOperationException("No entitlement token.");
        entitlements[tenantId] = (token, DateTimeOffset.UtcNow);
        return token;
    }

    /// <summary>Sends the alert; returns the relay's HTTP status and, when it did not go, its word for why.</summary>
    public async Task<Sent> SendAsync(string tenantId, DeviceRecord device, string kind, string title, string body, string? link, bool timeSensitive, CancellationToken ct)
    {
        var alert = new
        {
            v = 1,
            id = Guid.NewGuid().ToString(),
            at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            tenant = tenantId.ToLowerInvariant(),
            kind,
            title = title.Length > 80 ? title[..80] : title,
            body = body.Length > 400 ? body[..400] : body,
            // A tenantkeep:// link opens the module; the phone drops any other scheme.
            link,
        };
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(alert);
        var context = Hpke.SetupAuthSender(Base64Url.Decode(device.PublicKey), await KeyAsync(ct), Info, 2, null);
        var ciphertext = context.Seal(Encoding.ASCII.GetBytes(device.DeviceToken), plaintext);
        var urgency = timeSensitive ? "time-sensitive" : "normal";
        var envelope = new { suite = Suite, mode = "auth", enc = Base64Url.Encode(context.Enc), ct = Base64Url.Encode(ciphertext) };
        if (options.RelayServiceAudience is { } audience)
        {
            var token = await credential.GetTokenAsync(new TokenRequestContext([audience + "/.default"]), ct);
            using var message = ServiceRequest(options.RelayServiceUrl, token.Token, device, urgency, envelope);
            using var answer = await http.SendAsync(message, ct);
            return new Sent((int)answer.StatusCode, await ReasonAsync(answer, ct));
        }
        // The earlier way, until RELAY_SERVICE_AUDIENCE is set: the organization's entitlement
        // token in the body. The entitlement service knows organization licences only, so an
        // organization whose administrators subscribe in the app is refused with 402 here.
        var request = new
        {
            v = 1,
            deviceToken = device.DeviceToken,
            environment = device.Environment,
            urgency,
            entitlement = await EntitlementAsync(tenantId, ct),
            envelope,
        };
        using var response = await http.PostAsJsonAsync(options.RelayUrl, request, ct);
        return new Sent((int)response.StatusCode, await ReasonAsync(response, ct));
    }

    static async Task<string?> ReasonAsync(HttpResponseMessage answer, CancellationToken ct)
    {
        if (answer.IsSuccessStatusCode) return null;
        try { return Reason(await answer.Content.ReadAsStringAsync(ct)); }
        catch (Exception e) when (e is HttpRequestException or IOException) { return null; }
    }

    /// <summary>
    /// The relay's word for an alert that did not go, from its error body (RELAY-API.md,
    /// section 7): Apple's own identifier when Apple refused, such as BadDeviceToken, and
    /// otherwise the relay's error code. One short word or nothing: the relay puts nothing
    /// from the request in either, and anything that is not a plain identifier is dropped.
    /// </summary>
    internal static string? Reason(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            string? Text(string name) =>
                doc.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            var code = Text("error");
            // "Apple refused the notification: BadDeviceToken."
            if (code == "apns_rejected" && Text("message") is { } message && message.LastIndexOf(": ", StringComparison.Ordinal) is >= 0 and var at
                && Word(message[(at + 2)..].TrimEnd('.')) is { } apple)
                return apple;
            return Word(code);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    static string? Word(string? text) =>
        text is { Length: > 0 and <= 40 } && text.All(c => char.IsAsciiLetterOrDigit(c) || c == '_') ? text : null;

    /// <summary>
    /// The request for the alert service's route: this function's token for the relay in the
    /// Authorization header, and a body of the phone's address, the urgency and the sealed
    /// alert. No organization, and no entitlement token, which the route refuses.
    /// </summary>
    internal static HttpRequestMessage ServiceRequest(string url, string token, DeviceRecord device, string urgency, object envelope)
    {
        var message = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(new { v = 1, deviceToken = device.DeviceToken, environment = device.Environment, urgency, envelope }),
        };
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return message;
    }
}
