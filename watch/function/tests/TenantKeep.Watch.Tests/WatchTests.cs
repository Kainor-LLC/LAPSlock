using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kainor.TenantKeep.Watch;
using TenantKeep.Relay;

namespace TenantKeep.Watch.Tests;

public class WatchTests
{
    [Fact]
    public void RegistrationNeedsOneOfTheFiveRoles()
    {
        Assert.True(new PhoneCaller("t", "o", new HashSet<string> { PhoneCaller.GlobalReader }).CanRegister);
        Assert.True(new PhoneCaller("t", "o", new HashSet<string> { PhoneCaller.SecurityOperator }).CanRegister);
        Assert.False(new PhoneCaller("t", "o", new HashSet<string>()).CanRegister);
        // Intune Administrator: not on the list.
        Assert.False(new PhoneCaller("t", "o", new HashSet<string> { "3a2c62db-5318-420d-8d74-23affee5d9d5" }).CanRegister);
    }

    [Fact]
    public void OnlyGlobalAndSecurityAdministratorsChooseTheWatchedAccounts()
    {
        Assert.True(new PhoneCaller("t", "o", new HashSet<string> { PhoneCaller.SecurityAdministrator }).CanConfigure);
        Assert.True(new PhoneCaller("t", "o", new HashSet<string> { PhoneCaller.GlobalAdministrator }).CanConfigure);
        Assert.False(new PhoneCaller("t", "o", new HashSet<string> { PhoneCaller.SecurityReader, PhoneCaller.GlobalReader }).CanConfigure);
    }

    [Fact]
    public void TheApprovalLinkIsTheTenantsAdminConsentForTheWatchApp()
    {
        var url = TenantSetup.ApprovalUrl("4470dc21-a4b7-4729-a232-56d4c0eedf73", "c6d985d1-20fd-4087-a2a7-089be1ef6b34");
        Assert.StartsWith("https://login.microsoftonline.com/4470dc21-a4b7-4729-a232-56d4c0eedf73/adminconsent?client_id=c6d985d1-20fd-4087-a2a7-089be1ef6b34", url);
        Assert.Contains("redirect_uri=https%3A%2F%2Fkainor.com%2Finstant-alerts%2Fapproved%2F", url);
    }

    [Fact]
    public void ADevicesKeyIsAHashNotItsToken()
    {
        var token = new string('a', 64);
        var key = DeviceRecord.KeyFor(token);
        Assert.Equal(64, key.Length);
        Assert.NotEqual(token, key);
        Assert.Equal(key, DeviceRecord.KeyFor(token));
    }

    [Fact]
    public void TheDerivedTenantPropertiesAreNotStored()
    {
        // Table Storage refuses arrays: BreakGlass must stay out of what is written.
        var property = typeof(TenantRecord).GetProperty(nameof(TenantRecord.BreakGlass))!;
        Assert.NotNull(property.GetCustomAttributes(typeof(System.Runtime.Serialization.IgnoreDataMemberAttribute), false).SingleOrDefault());
        Assert.Equal(["a", "b"], new TenantRecord { BreakGlassIds = "a,b" }.BreakGlass);
    }

    [Fact]
    public void TheAlertSealsForThePhoneAsTheRelayContractSays()
    {
        // The same seal AlertSender makes, opened as the phone opens it.
        using var phone = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var watcher = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var info = Encoding.ASCII.GetBytes("TenantKeep relay v1");
        var token = new string('b', 64);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(new { v = 1, kind = "breakGlassSignIn", body = "Kainor: break-glass sign-in" });
        var sealing = Hpke.SetupAuthSender(Hpke.PublicBytes(phone), watcher, info, 2, null);
        var ct = sealing.Seal(Encoding.ASCII.GetBytes(token), plaintext);
        var opening = Hpke.SetupAuthRecipient(sealing.Enc, phone, Hpke.PublicBytes(watcher), info, 2);
        Assert.Equal(plaintext, opening.Open(Encoding.ASCII.GetBytes(token), ct));
    }
}
