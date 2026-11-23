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

    [Fact]
    public void IncidentAlertsNameTheSeverityAndTheCountNeverTheTitle()
    {
        Assert.Equal("Kainor: new high severity incident", TenantWatch.IncidentBody("Kainor", ["high"]));
        Assert.Equal("Kainor: 3 incidents, 1 high severity", TenantWatch.IncidentBody("Kainor", ["high", "medium", "medium"]));
        Assert.Equal("Kainor: 2 new incidents", TenantWatch.IncidentBody("Kainor", ["medium", "medium"]));
    }

    [Fact]
    public void OnlyItemsNotSeenBeforeCountAndTheCursorMovesToTheNewest()
    {
        using var page = JsonDocument.Parse("""{"value":[{"id":"a","createdDateTime":"2026-11-15T03:00:00Z"},{"id":"b","createdDateTime":"2026-11-15T03:05:00Z"}]}""");
        var cursor = DateTimeOffset.Parse("2026-11-15T02:50:00Z");
        var (fresh, newest, seen) = TenantWatch.Fresh(page, "createdDateTime", cursor, "a");
        Assert.Equal(1, fresh);
        Assert.Equal(DateTimeOffset.Parse("2026-11-15T03:05:00Z"), newest);
        Assert.Equal(["a", "b"], seen.Split(','));
    }

    // The review of 2026-11-23: what counts as an organization having removed Watch.

    [Fact]
    public void OnlyEntrasDefiniteAnswerMeansTheAppIsNotInTheTenant()
    {
        Assert.True(GraphReader.IsNotInTenant(new Azure.Identity.AuthenticationFailedException("AADSTS700016: Application with identifier 'x' was not found in the directory 'y'.")));
        Assert.True(GraphReader.IsNotInTenant(new Azure.Identity.AuthenticationFailedException("AADSTS7000229: The client application is missing service principal in the tenant.")));
        Assert.True(GraphReader.IsNotInTenant(new Azure.Identity.AuthenticationFailedException("AADSTS90002: Tenant 'z' not found.")));
        // A token endpoint or a managed identity that is briefly unavailable is not that.
        Assert.False(GraphReader.IsNotInTenant(new Azure.Identity.AuthenticationFailedException("ManagedIdentityCredential authentication failed: Service request failed. Status: 503")));
        Assert.False(GraphReader.IsNotInTenant(new Azure.Identity.AuthenticationFailedException("AADSTS50196: The server terminated an operation because it encountered a client request loop.")));
        Assert.False(GraphReader.IsNotInTenant(new Azure.Identity.CredentialUnavailableException("AADSTS700016 named in a credential that could not be used at all")));
    }

    [Fact]
    public void ARefusedReadIsNotARemovedOrganization()
    {
        // 403: no Entra ID P1 for the sign-in log, or no Defender. Still an approval question
        // for a registration, never a reason to delete.
        var refused = new GraphException(System.Net.HttpStatusCode.Forbidden);
        Assert.True(refused.IsConsent);
        Assert.False(refused.IsNotInTenant);
        Assert.False(new GraphException(System.Net.HttpStatusCode.ServiceUnavailable).IsNotInTenant);
        Assert.True(new GraphException(System.Net.HttpStatusCode.Unauthorized).IsNotInTenant);
    }

    [Fact]
    public void AnOrganizationIsDeletedOnlyAfterADayOfEntraSayingItIsGone()
    {
        var start = new DateTimeOffset(2026, 11, 23, 3, 14, 0, TimeSpan.Zero);
        var tenant = new TenantRecord { RowKey = "t", State = "ok" };

        // 03:14, a run fails for a passing reason; 03:15, the cleanup runs. Nothing is deleted.
        TenantWatch.Settle(tenant, notInTenant: false, failed: true, start);
        Assert.Equal("error", tenant.State);
        Assert.False(Housekeeping.IsGone(tenant, start.AddMinutes(1)));

        // Entra says the app is not there. Still nothing for a day.
        TenantWatch.Settle(tenant, notInTenant: true, failed: true, start);
        Assert.Equal("noConsent", tenant.State);
        Assert.False(Housekeeping.IsGone(tenant, start.AddMinutes(1)));
        Assert.False(Housekeeping.IsGone(tenant, start.AddHours(23)));

        // The time it was first said is kept across runs, so the day is counted from then.
        TenantWatch.Settle(tenant, notInTenant: true, failed: true, start.AddHours(12));
        Assert.Equal(start, tenant.NoConsentSince);
        Assert.True(Housekeeping.IsGone(tenant, start.AddHours(24)));

        // One good run in between starts the day again.
        TenantWatch.Settle(tenant, notInTenant: false, failed: false, start.AddHours(25));
        Assert.Null(tenant.NoConsentSince);
        Assert.False(Housekeeping.IsGone(tenant, start.AddHours(26)));
    }

    [Fact]
    public void AStateOfNoConsentWithNoTimeRecordedIsNotDeleted()
    {
        // A row written before this change has the state and no time. It waits for the next run to start its day.
        var old = new TenantRecord { RowKey = "t", State = "noConsent" };
        Assert.False(Housekeeping.IsGone(old, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void APhonesKeyMustBeOnTheCurveNotOnlyTheRightLength()
    {
        using var real = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var point = real.ExportParameters(false).Q;
        var good = new byte[65];
        good[0] = 0x04;
        point.X!.CopyTo(good, 1);
        point.Y!.CopyTo(good, 33);
        Assert.True(DeviceFunctions.IsPublicKey(Base64Url.Encode(good)));

        // Right length, right first byte, not a point on P-256: once stored, and then every
        // run with an alert for that organization stopped at it.
        var bad = (byte[])good.Clone();
        bad[64] ^= 0x01;
        Assert.False(DeviceFunctions.IsPublicKey(Base64Url.Encode(bad)));
        Assert.False(DeviceFunctions.IsPublicKey(Base64Url.Encode(good[..64])));
        Assert.False(DeviceFunctions.IsPublicKey("not base64url!"));
        Assert.False(DeviceFunctions.IsPublicKey(null));
    }

    [Fact]
    public async Task AsTheAlertServiceTheRequestNamesNoOrganizationAndCarriesNoEntitlement()
    {
        // RELAY-API.md section 15. The relay refuses any other field, so this list is the contract.
        var device = new DeviceRecord { PartitionKey = "c0ffee00-1111-2222-3333-444455556666", RowKey = "key", DeviceToken = new string('b', 64), Environment = "production", PublicKey = "unused" };
        using var message = AlertSender.ServiceRequest("https://relay.example/relay/service", "the-services-token", device, "time-sensitive",
            new { suite = "DHKEM-P256-HKDF-SHA256/HKDF-SHA256/AES-256-GCM", mode = "auth", enc = "e", ct = "c" });

        Assert.Equal(HttpMethod.Post, message.Method);
        Assert.Equal("https://relay.example/relay/service", message.RequestUri!.ToString());
        Assert.Equal("Bearer", message.Headers.Authorization!.Scheme);
        Assert.Equal("the-services-token", message.Headers.Authorization.Parameter);

        var body = await message.Content!.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);
        Assert.Equal(["deviceToken", "envelope", "environment", "urgency", "v"], json.RootElement.EnumerateObject().Select(p => p.Name).Order());
        Assert.Equal(["ct", "enc", "mode", "suite"], json.RootElement.GetProperty("envelope").EnumerateObject().Select(p => p.Name).Order());
        Assert.Equal("time-sensitive", json.RootElement.GetProperty("urgency").GetString());
        Assert.DoesNotContain("c0ffee00", body);
        Assert.DoesNotContain("the-services-token", body);
    }

    [Fact]
    public void TheServiceRouteSitsBesideTheRelaysOwnAndIsOffUntilItsAudienceIsSet()
    {
        var options = new WatchOptions
        {
            StorageAccount = "s", WatchClientId = "w", SenderKeySecretUri = "u", EntitlementUrl = "e", AlertsApiAudience = "a",
            RelayUrl = "https://relay.example/relay",
        };
        Assert.Equal("https://relay.example/relay/service", options.RelayServiceUrl);
        Assert.Null(options.RelayServiceAudience);
    }

    [Fact]
    public void TheOnlyEndpointsAreTheTwoAPhoneCallsWithItsAdministratorsToken()
    {
        // The service once had four more, behind a function key, for setting an organization
        // up by hand. Whoever held that key could attach a phone to any organization that had
        // approved the service and receive its alerts. Nothing may be reachable by a key.
        var triggers = typeof(DeviceFunctions).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods())
            .SelectMany(m => m.GetParameters())
            .Select(p => p.GetCustomAttributes(typeof(Microsoft.Azure.Functions.Worker.HttpTriggerAttribute), false).FirstOrDefault())
            .OfType<Microsoft.Azure.Functions.Worker.HttpTriggerAttribute>()
            .ToList();

        Assert.Equal(["delete v1/devices", "post v1/devices"], triggers.Select(t => $"{string.Join('+', t.Methods!)} {t.Route}").Order());
        Assert.All(triggers, t => Assert.Equal(Microsoft.Azure.Functions.Worker.AuthorizationLevel.Anonymous, t.AuthLevel));
    }

    [Fact]
    public void ARunSaysWhichAnswersItsUnsentAlertsGot()
    {
        Assert.Equal("none", TenantWatch.NotSent([]));
        Assert.Equal("0x1,403x2,429x1", TenantWatch.NotSent(new() { [429] = 1, [403] = 2, [0] = 1 }));
    }
}
