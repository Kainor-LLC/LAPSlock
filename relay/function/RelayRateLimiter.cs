using System.Security.Cryptography;
using System.Text;

namespace Kainor.TenantKeep.Relay;

/// <summary>
/// docs/RELAY-API.md section 8: counters in memory only, keyed by an HMAC of the value under
/// a random key made when the process starts, so memory never holds a device token or a
/// tenant ID in the clear, and nothing survives a restart. Per instance and approximate on
/// purpose: it keeps one misconfigured run from spending the shared APNs budget.
/// </summary>
public sealed class RelayRateLimiter
{
    readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    readonly TimeProvider _time;
    readonly object _lock = new();
    readonly Dictionary<string, (long Window, int Count)> _counts = new();

    public const int PerTenant = 120, PerDevice = 30, PerAddress = 240, SandboxPerTenant = 10;

    public RelayRateLimiter(TimeProvider time) { _time = time; }

    /// <summary>True when the request may go on. Every counter counts, whatever the verdict.</summary>
    public bool TryAcquire(string tenant, string deviceToken, string? address, bool sandbox)
    {
        var a = Count("t:" + Hash(tenant), sandbox ? SandboxPerTenant : PerTenant);
        var b = Count("d:" + Hash(deviceToken), PerDevice);
        var c = Count("a:" + Hash(address ?? "unknown"), PerAddress);
        return a && b && c;
    }

    public int SecondsUntilNextWindow => 60 - (int)(_time.GetUtcNow().ToUnixTimeSeconds() % 60);

    bool Count(string key, int limit)
    {
        var window = _time.GetUtcNow().ToUnixTimeSeconds() / 60;
        lock (_lock)
        {
            if (_counts.Count > 50_000) _counts.Clear();
            var entry = _counts.TryGetValue(key, out var e) && e.Window == window ? e : (Window: window, Count: 0);
            entry.Count++;
            _counts[key] = entry;
            return entry.Count <= limit;
        }
    }

    string Hash(string value) => Convert.ToHexString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(value)));
}
