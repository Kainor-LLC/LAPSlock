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
    public const int PerService = 3000, SandboxPerService = 120;

    /// <summary>Counters kept before the ones from earlier minutes are dropped.</summary>
    const int MaxKeys = 50_000;

    public RelayRateLimiter(TimeProvider time) { _time = time; }

    /// <summary>True when the request may go on. Every counter counts, whatever the verdict.</summary>
    public bool TryAcquire(string tenant, string deviceToken, string? address, bool sandbox)
    {
        var a = Count("t:" + Hash(tenant), sandbox ? SandboxPerTenant : PerTenant);
        var b = Count("d:" + Hash(deviceToken), PerDevice);
        var c = Count("a:" + Hash(address ?? "unknown"), PerAddress);
        return a && b && c;
    }

    /// <summary>
    /// The alert service's route, section 15. No tenant is seen there, and the service's few
    /// addresses carry every organization's alerts, so neither is a key: each phone keeps
    /// its own limit, under one ceiling for the whole service.
    /// </summary>
    public bool TryAcquireService(string deviceToken, bool sandbox)
    {
        var a = Count(sandbox ? "s:sandbox" : "s:production", sandbox ? SandboxPerService : PerService);
        var b = Count("d:" + Hash(deviceToken), PerDevice);
        return a && b;
    }

    public int SecondsUntilNextWindow => 60 - (int)(_time.GetUtcNow().ToUnixTimeSeconds() % 60);

    bool Count(string key, int limit)
    {
        var window = _time.GetUtcNow().ToUnixTimeSeconds() / 60;
        lock (_lock)
        {
            if (_counts.Count > MaxKeys) Prune(window);
            var entry = _counts.TryGetValue(key, out var e) && e.Window == window ? e : (Window: window, Count: 0);
            entry.Count++;
            _counts[key] = entry;
            return entry.Count <= limit;
        }
    }

    /// <summary>
    /// Drops the counters of earlier minutes, which count nothing any more. Clearing them all,
    /// as before the second review (can wait for 2.1, 2026-11-24), let a flood of new keys in
    /// one minute reset the counters still in use, the service's ceiling among them. Should
    /// one minute alone pass four times the limit, the phones' and addresses' counters go and
    /// the service's ceilings stay.
    /// </summary>
    void Prune(long window)
    {
        foreach (var stale in _counts.Where(c => c.Value.Window != window).Select(c => c.Key).ToList()) _counts.Remove(stale);
        if (_counts.Count <= 4 * MaxKeys) return;
        foreach (var key in _counts.Keys.Where(k => !k.StartsWith("s:", StringComparison.Ordinal)).ToList()) _counts.Remove(key);
    }

    string Hash(string value) => Convert.ToHexString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(value)));
}
