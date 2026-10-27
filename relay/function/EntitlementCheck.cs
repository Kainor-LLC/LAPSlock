using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Kainor.TenantKeep.Relay;

/// <summary>
/// docs/RELAY-API.md section 4: the tenant's entitlement token, verified offline against
/// public keys compiled in here. The relay never calls the entitlement service and keeps no
/// list of tenants. Any failure is one answer, so the endpoint cannot be used to probe.
/// </summary>
public sealed class EntitlementCheck
{
    public enum Result { Valid, Invalid, Unpaid }

    readonly IReadOnlyDictionary<string, byte[]> _keyring;
    readonly TimeProvider _time;
    static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);
    static readonly HashSet<string> RelayTiers = ["pro", "msp", "enterprise"];

    /// <summary>The shipping keyring: the same key the app compiles in (LicensingKit,
    /// EntitlementKeyring.shipping), X9.63 uncompressed.</summary>
    public static readonly IReadOnlyDictionary<string, byte[]> Shipping = new Dictionary<string, byte[]>
    {
        ["lapslock-ent-2026-09"] = Convert.FromHexString(
            "04e671f32581b2e7b3901cede63171be2f26bcd38088f5bdca66c9ed6ded9b9912cce6c8897694a366489444c5be8890dc8fba6ed03f3f1f4cf82e9ea45f5fe155"),
    };

    public EntitlementCheck(IReadOnlyDictionary<string, byte[]> keyring, TimeProvider time)
    {
        _keyring = keyring;
        _time = time;
    }

    /// <summary>The verdict, and the tenant on success, which is used for the rate limit only.</summary>
    public (Result Result, string? Tenant) Verify(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return (Result.Invalid, null);
            using var header = JsonDocument.Parse(B64(parts[0]));
            if (Str(header.RootElement, "alg") != "ES256") return (Result.Invalid, null);
            var kid = Str(header.RootElement, "kid");
            if (kid is null || !_keyring.TryGetValue(kid, out var point) || point.Length != 65) return (Result.Invalid, null);
            using var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = point[1..33], Y = point[33..65] },
            });
            var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            if (!key.VerifyData(signed, B64(parts[2]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                return (Result.Invalid, null);
            using var claims = JsonDocument.Parse(B64(parts[1]));
            var c = claims.RootElement;
            if (Str(c, "iss") != "https://kainor.com/lapslock" || Str(c, "aud") != "com.kainor.lapslock") return (Result.Invalid, null);
            var now = _time.GetUtcNow();
            if (!c.TryGetProperty("nbf", out var nbf) || DateTimeOffset.FromUnixTimeSeconds(nbf.GetInt64()) > now + Skew) return (Result.Invalid, null);
            if (!c.TryGetProperty("exp", out var exp) || DateTimeOffset.FromUnixTimeSeconds(exp.GetInt64()) < now - Skew) return (Result.Invalid, null);
            var tenant = Str(c, "sub");
            if (tenant is null || !Guid.TryParse(tenant, out _)) return (Result.Invalid, null);
            return RelayTiers.Contains(Str(c, "tier") ?? "") ? (Result.Valid, tenant.ToLowerInvariant()) : (Result.Unpaid, null);
        }
        catch (Exception e) when (e is FormatException or JsonException or CryptographicException or InvalidOperationException)
        {
            return (Result.Invalid, null);
        }
    }

    static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    internal static byte[] B64(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t + new string('=', (4 - t.Length % 4) % 4));
    }
}
