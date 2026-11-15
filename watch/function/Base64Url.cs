namespace Kainor.TenantKeep.Watch;

public static class Base64Url
{
    public static string Encode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string text)
    {
        var s = text.Replace('-', '+').Replace('_', '/');
        while (s.Length % 4 != 0) s += "=";
        return Convert.FromBase64String(s);
    }
}
