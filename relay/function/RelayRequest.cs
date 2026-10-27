using System.Text.Json;
using System.Text.RegularExpressions;

namespace Kainor.TenantKeep.Relay;

/// <summary>
/// The request, docs/RELAY-API.md section 3, parsed strictly: exactly these fields, each in
/// range, nothing else. An unknown field is refused rather than ignored, so a sender never
/// believes something is carried or protected that is not.
/// </summary>
public sealed record RelayRequest(string DeviceToken, string Environment, string Urgency, string Entitlement, string Enc, string Ct)
{
    public const int BodyLimit = 6 * 1024;
    public const string Suite = "DHKEM-P256-HKDF-SHA256/HKDF-SHA256/AES-256-GCM";
    static readonly Regex Hex = new("^[0-9a-f]{64,200}$", RegexOptions.CultureInvariant);
    static readonly Regex B64Url = new("^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant);
    static readonly HashSet<string> TopLevel = ["v", "deviceToken", "environment", "urgency", "entitlement", "envelope"];
    static readonly HashSet<string> EnvelopeFields = ["suite", "mode", "enc", "ct"];

    /// <summary>Null and a reason when the body is not a valid version 1 request.</summary>
    public static (RelayRequest? Request, string? Problem) Parse(byte[] body)
    {
        if (body.Length > BodyLimit) return (null, "too_large");
        JsonDocument doc;
        try { doc = JsonDocument.Parse(body); }
        catch (JsonException) { return (null, "not JSON"); }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return (null, "not an object");
            foreach (var p in root.EnumerateObject()) if (!TopLevel.Contains(p.Name)) return (null, "unknown field");
            if (!root.TryGetProperty("v", out var v) || v.ValueKind != JsonValueKind.Number || !v.TryGetInt32(out var version) || version != 1) return (null, "v");
            var token = Str(root, "deviceToken");
            if (token is null || !Hex.IsMatch(token)) return (null, "deviceToken");
            var environment = Str(root, "environment");
            if (environment is not ("production" or "sandbox")) return (null, "environment");
            var urgency = Str(root, "urgency");
            if (urgency is not ("normal" or "time-sensitive")) return (null, "urgency");
            var entitlement = Str(root, "entitlement");
            if (entitlement is null || entitlement.Length > 2048 || entitlement.Split('.').Length != 3) return (null, "entitlement");
            if (!root.TryGetProperty("envelope", out var envelope) || envelope.ValueKind != JsonValueKind.Object) return (null, "envelope");
            foreach (var p in envelope.EnumerateObject()) if (!EnvelopeFields.Contains(p.Name)) return (null, "unknown field");
            if (Str(envelope, "suite") != Suite) return (null, "suite");
            if (Str(envelope, "mode") != "auth") return (null, "mode");
            var enc = Str(envelope, "enc");
            var ct = Str(envelope, "ct");
            if (enc is null || !B64Url.IsMatch(enc) || enc.Length != 87) return (null, "enc");
            if (ct is null || !B64Url.IsMatch(ct)) return (null, "ct");
            if (ct.Length > (2800 * 4 + 2) / 3) return (null, "too_large");
            return (new RelayRequest(token, environment, urgency, entitlement, enc, ct), null);
        }
    }

    static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
}
