using System.Collections.Concurrent;
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
/// Secure Enclave key, with the tenant's entitlement token beside it.
/// </summary>
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

    /// <summary>What a phone pins to trust this watcher's alerts for one tenant: tksender1.</summary>
    public async Task<string> SenderCodeAsync(string tenantId, CancellationToken ct)
    {
        var pin = new { v = 1, tenant = tenantId.ToLowerInvariant(), senderKey = Base64Url.Encode(Hpke.PublicBytes(await KeyAsync(ct))) };
        return "tksender1:" + Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(pin));
    }

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

    /// <summary>Sends the alert; returns the relay's HTTP status.</summary>
    public async Task<int> SendAsync(string tenantId, DeviceRecord device, string kind, string title, string body, bool timeSensitive, CancellationToken ct)
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
        };
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(alert);
        var context = Hpke.SetupAuthSender(Base64Url.Decode(device.PublicKey), await KeyAsync(ct), Info, 2, null);
        var ciphertext = context.Seal(Encoding.ASCII.GetBytes(device.DeviceToken), plaintext);
        var request = new
        {
            v = 1,
            deviceToken = device.DeviceToken,
            environment = device.Environment,
            urgency = timeSensitive ? "time-sensitive" : "normal",
            entitlement = await EntitlementAsync(tenantId, ct),
            envelope = new { suite = Suite, mode = "auth", enc = Base64Url.Encode(context.Enc), ct = Base64Url.Encode(ciphertext) },
        };
        using var response = await http.PostAsJsonAsync(options.RelayUrl, request, ct);
        return (int)response.StatusCode;
    }
}
