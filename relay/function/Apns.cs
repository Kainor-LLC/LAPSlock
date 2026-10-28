using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace Kainor.TenantKeep.Relay;

/// <summary>What APNs said, reduced to what the relay passes back.</summary>
public sealed record ApnsResult(int Status, string? ApnsId, string? Reason);

public interface IApnsSender
{
    Task<ApnsResult> SendAsync(string deviceToken, bool sandbox, bool timeSensitive, string enc, string ct, CancellationToken cancel);
}

/// <summary>Signs the provider token. Key Vault in the function; a local key in the tests.</summary>
public interface IApnsSigner
{
    Task<byte[]> SignAsync(byte[] data, CancellationToken cancel);
}

/// <summary>The APNs key in Key Vault, non-exportable: the signature is made there.</summary>
public sealed class KeyVaultApnsSigner(CryptographyClient client) : IApnsSigner
{
    public async Task<byte[]> SignAsync(byte[] data, CancellationToken cancel) =>
        (await client.SignDataAsync(SignatureAlgorithm.ES256, data, cancel)).Signature;
}

/// <summary>
/// The push to Apple. The payload is a neutral placeholder the phone's Notification Service
/// Extension replaces after decrypting, and the envelope under "e". The provider token is
/// signed with the APNs key held in Key Vault, non-exportable, and reused for 40 minutes as
/// Apple asks (between 20 and 60). A token Apple refuses as expired or invalid, after clock
/// skew or a key rotation, is signed again and the push sent once more, at most once every
/// 20 minutes, which is as often as Apple accepts a new one; it used to fail every push on
/// the instance until the 40 minutes ran out.
/// </summary>
public sealed class ApnsSender : IApnsSender
{
    readonly HttpClient _http;
    readonly IApnsSigner _signer;
    readonly RelayOptions _options;
    readonly TimeProvider _time;
    readonly SemaphoreSlim _lock = new(1, 1);
    string? _token;
    DateTimeOffset _tokenAt;
    DateTimeOffset? _forcedAt;

    /// <summary>Apple's two answers for a provider token it will not accept.</summary>
    public static readonly string[] RefusedTokenReasons = ["ExpiredProviderToken", "InvalidProviderToken"];
    /// <summary>How often a refused token may be replaced early.</summary>
    public static readonly TimeSpan ForcedRefreshInterval = TimeSpan.FromMinutes(20);

    public ApnsSender(HttpClient http, IApnsSigner signer, RelayOptions options, TimeProvider time)
    {
        _http = http;
        _signer = signer;
        _options = options;
        _time = time;
    }

    /// <summary>
    /// How long Apple holds an alert for a phone it cannot reach, a phone in a lift or out of
    /// signal. An expiration of 0 told Apple to try once and drop it, while the sender was
    /// told 202. Apple keeps only the latest alert per phone while it waits, so a bad night
    /// cannot pile up a backlog, and the phone shows each alert's own time.
    /// </summary>
    public static readonly TimeSpan HoldTimeSensitive = TimeSpan.FromHours(1);
    public static readonly TimeSpan HoldNormal = TimeSpan.FromMinutes(30);

    public static long Expiration(DateTimeOffset now, bool timeSensitive) =>
        (now + (timeSensitive ? HoldTimeSensitive : HoldNormal)).ToUnixTimeSeconds();

    public static string Payload(bool timeSensitive, string enc, string ct) => JsonSerializer.Serialize(new Dictionary<string, object>
    {
        ["aps"] = new Dictionary<string, object>
        {
            ["alert"] = new Dictionary<string, string> { ["title"] = "TenantKeep alert", ["body"] = "Open TenantKeep" },
            ["mutable-content"] = 1,
            ["interruption-level"] = timeSensitive ? "time-sensitive" : "active",
        }.WithSound(timeSensitive),
        ["e"] = new Dictionary<string, string> { ["enc"] = enc, ["ct"] = ct },
    });

    public async Task<ApnsResult> SendAsync(string deviceToken, bool sandbox, bool timeSensitive, string enc, string ct, CancellationToken cancel)
    {
        var result = await SendOnceAsync(deviceToken, sandbox, timeSensitive, enc, ct, cancel);
        if (result.Status == 403 && RefusedTokenReasons.Contains(result.Reason) && await TryForceRefreshAsync(cancel))
            result = await SendOnceAsync(deviceToken, sandbox, timeSensitive, enc, ct, cancel);
        return result;
    }

    /// <summary>Drops the cached token so the next push signs a new one, unless one was
    /// forced in the last 20 minutes.</summary>
    async Task<bool> TryForceRefreshAsync(CancellationToken cancel)
    {
        await _lock.WaitAsync(cancel);
        try
        {
            var now = _time.GetUtcNow();
            if (_forcedAt is { } at && now - at < ForcedRefreshInterval) return false;
            _forcedAt = now;
            _token = null;
            return true;
        }
        finally { _lock.Release(); }
    }

    async Task<ApnsResult> SendOnceAsync(string deviceToken, bool sandbox, bool timeSensitive, string enc, string ct, CancellationToken cancel)
    {
        var host = sandbox ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com";
        using var request = new HttpRequestMessage(HttpMethod.Post, host + "/3/device/" + deviceToken)
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = new StringContent(Payload(timeSensitive, enc, ct), Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("authorization", "bearer " + await ProviderTokenAsync(cancel));
        request.Headers.TryAddWithoutValidation("apns-topic", _options.Topic);
        request.Headers.TryAddWithoutValidation("apns-push-type", "alert");
        request.Headers.TryAddWithoutValidation("apns-priority", "10");
        request.Headers.TryAddWithoutValidation("apns-expiration",
            Expiration(_time.GetUtcNow(), timeSensitive).ToString(CultureInfo.InvariantCulture));
        try
        {
            using var response = await _http.SendAsync(request, cancel);
            var id = response.Headers.TryGetValues("apns-id", out var ids) ? ids.FirstOrDefault() : null;
            string? reason = null;
            if (!response.IsSuccessStatusCode)
            {
                try
                {
                    using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancel));
                    reason = doc.RootElement.TryGetProperty("reason", out var r) ? r.GetString() : null;
                }
                catch (JsonException) { }
            }
            return new ApnsResult((int)response.StatusCode, id, reason);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            return new ApnsResult(503, null, null);
        }
    }

    async Task<string> ProviderTokenAsync(CancellationToken cancel)
    {
        await _lock.WaitAsync(cancel);
        try
        {
            var now = _time.GetUtcNow();
            if (_token is not null && now - _tokenAt < TimeSpan.FromMinutes(40)) return _token;
            static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var header = B64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "ES256", kid = _options.ApnsKeyId }));
            var claims = B64(JsonSerializer.SerializeToUtf8Bytes(new { iss = _options.TeamId, iat = now.ToUnixTimeSeconds() }));
            var signed = Encoding.ASCII.GetBytes(header + "." + claims);
            var signature = await _signer.SignAsync(signed, cancel);
            _token = header + "." + claims + "." + B64(signature);
            _tokenAt = now;
            return _token;
        }
        finally { _lock.Release(); }
    }
}

static class ApsSound
{
    /// <summary>
    /// A sound for a time-sensitive alert only, as for the app's own alerts: a normal one
    /// arrives quietly (decision 4, 2026-10-27). Decided here, so it holds even when the
    /// phone cannot open the alert and shows the placeholder.
    /// </summary>
    public static Dictionary<string, object> WithSound(this Dictionary<string, object> aps, bool timeSensitive)
    {
        if (timeSensitive) aps["sound"] = "default";
        return aps;
    }
}
