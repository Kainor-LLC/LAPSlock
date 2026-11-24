using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kainor.TenantKeep.Relay;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace TenantKeep.Relay.Tests;

/// The keys Microsoft would publish, for a test: one RSA key, or a failure to fetch any.
sealed class FakeKeys(SecurityKey? key) : IServiceKeys
{
    public Task<IEnumerable<SecurityKey>> GetAsync(CancellationToken cancel) =>
        key is null ? throw new HttpRequestException("no route to Microsoft") : Task.FromResult<IEnumerable<SecurityKey>>([key]);
}

sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now = now;
    public override DateTimeOffset GetUtcNow() => Now;
}

sealed class FakeApns(ApnsResult result) : IApnsSender
{
    public int Calls;
    public Task<ApnsResult> SendAsync(string deviceToken, bool sandbox, bool timeSensitive, string enc, string ct, CancellationToken cancel)
    {
        Calls++;
        return Task.FromResult(result);
    }
}

static class Fixtures
{
    public const string Tenant = "c0ffee00-1111-2222-3333-444455556666";
    public static readonly string Token = new('a', 64);
    public static readonly string Enc = new('B', 87);
    public static readonly string Ct = new('C', 400);
    public static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
    public static readonly ECDsa Signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static IReadOnlyDictionary<string, byte[]> Keyring
    {
        get
        {
            var q = Signer.ExportParameters(false).Q;
            return new Dictionary<string, byte[]> { ["test-key"] = [0x04, .. q.X!, .. q.Y!] };
        }
    }

    static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string Jwt(string tier = "pro", string kid = "test-key", string aud = "com.kainor.lapslock", long? exp = null, ECDsa? signer = null)
    {
        var header = B64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "ES256", typ = "JWT", kid }));
        var claims = B64(JsonSerializer.SerializeToUtf8Bytes(new
        {
            iss = "https://kainor.com/lapslock", aud, sub = Tenant, tier,
            iat = Now.ToUnixTimeSeconds(), nbf = Now.ToUnixTimeSeconds() - 60, exp = exp ?? Now.ToUnixTimeSeconds() + 86400, jti = Guid.NewGuid().ToString(),
        }));
        var sig = (signer ?? Signer).SignData(Encoding.ASCII.GetBytes(header + "." + claims), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return header + "." + claims + "." + B64(sig);
    }

    public static byte[] Body(string? jwt = null, string env = "production", string urgency = "normal", string mode = "auth", string? extra = null, string? enc = null, string? token = null) =>
        Encoding.UTF8.GetBytes("{\"v\":1,\"deviceToken\":\"" + (token ?? Token) + "\",\"environment\":\"" + env + "\",\"urgency\":\"" + urgency +
            "\",\"entitlement\":\"" + (jwt ?? Jwt()) + "\",\"envelope\":{\"suite\":\"" + RelayRequest.Suite + "\",\"mode\":\"" + mode +
            "\",\"enc\":\"" + (enc ?? Enc) + "\",\"ct\":\"" + Ct + "\"}" + (extra ?? "") + "}");

    public static RelayHandler Handler(FakeApns apns, FixedTime? time = null, ServiceCaller? service = null)
    {
        var t = time ?? new FixedTime(Now);
        return new RelayHandler(new EntitlementCheck(Keyring, t), new RelayRateLimiter(t), apns, service);
    }

    // The alert service's route, RELAY-API.md section 15.
    public const string Kainor = "11111111-2222-3333-4444-555555555555";
    public const string RelayClient = "99999999-8888-7777-6666-555555555555";
    public static readonly RsaSecurityKey ServiceKey = new(RSA.Create(2048)) { KeyId = "service-test" };

    public static ServiceCaller Service(SecurityKey? key = null, bool reachable = true, string? callerId = null) =>
        new(Kainor, RelayClient, new FakeKeys(reachable ? key ?? ServiceKey : null), callerId);

    /// The alert service's managed identity, by object ID.
    public const string AlertService = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    /// A token as Microsoft Entra ID issues one to an application: by default the alert
    /// service's, from Kainor's tenant, for the relay, with the role.
    public static string ServiceToken(string tenant = Kainor, string audience = RelayClient, string[]? roles = null, string? scp = null,
        bool expired = false, RsaSecurityKey? key = null, bool olderFormat = false, string? oid = null)
    {
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object> { ["tid"] = tenant, ["oid"] = oid ?? Guid.NewGuid().ToString() };
        if ((roles ?? [ServiceCaller.Role]) is { Length: > 0 } held) claims["roles"] = held;
        if (scp is not null) claims["scp"] = scp;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = olderFormat ? $"https://sts.windows.net/{tenant}/" : $"https://login.microsoftonline.com/{tenant}/v2.0",
            Audience = olderFormat ? "api://" + audience : audience,
            Claims = claims,
            IssuedAt = expired ? now.AddHours(-3) : now,
            NotBefore = expired ? now.AddHours(-3) : now.AddMinutes(-1),
            Expires = expired ? now.AddHours(-2) : now.AddHours(1),
            SigningCredentials = new SigningCredentials(key ?? ServiceKey, SecurityAlgorithms.RsaSha256),
        });
    }

    public static byte[] ServiceBody(string env = "production", string? extra = null, string? token = null) =>
        Encoding.UTF8.GetBytes("{\"v\":1,\"deviceToken\":\"" + (token ?? Token) + "\",\"environment\":\"" + env +
            "\",\"urgency\":\"normal\",\"envelope\":{\"suite\":\"" + RelayRequest.Suite + "\",\"mode\":\"auth\",\"enc\":\"" + Enc +
            "\",\"ct\":\"" + Ct + "\"}" + (extra ?? "") + "}");
}

public class RequestTests
{
    [Fact]
    public void AValidRequestParses()
    {
        var (request, problem) = RelayRequest.Parse(Fixtures.Body());
        Assert.Null(problem);
        Assert.Equal(Fixtures.Token, request!.DeviceToken);
    }

    [Theory]
    [InlineData(",\"tenant\":\"x\"")]
    [InlineData(",\"title\":\"leak\"")]
    public void AnUnknownFieldIsRefused(string extra) => Assert.Null(RelayRequest.Parse(Fixtures.Body(extra: extra)).Request);

    /// Built by relay/sender/TenantKeepRelaySender.ps1, so the sender and the relay agree.
    [Fact]
    public void WhatTheSenderBuildsParses()
    {
        const string fromSender = """
{"v":1,"deviceToken":"abababababababababababababababababababababababababababababababab","environment":"production","urgency":"time-sensitive","entitlement":"eyJh.eyJi.c2ln","envelope":{"suite":"DHKEM-P256-HKDF-SHA256/HKDF-SHA256/AES-256-GCM","mode":"auth","enc":"BP9pBPZxS1z0-Mg29kLfolx3Sz5q3WLFVh-WyCYQ0KFyo9t1z8m2tZHNavozBOBEnCd7l1WZvi7jLwr9cwX-74A","ct":"4CchcBnlEZuzGaN3USgnMJwyYNhsj1C8iXbirGayXBjvHnxvSx3ja_N6GBg4--gPCQRW6yDqKUOAlLdCKjPuHf4ATrxVmVWwXXgvLfyor4zGfY_6JNYQejSBD-LtZNXk5U9BqNyVREvXUyzcBbn5quvSREtJ0_aOBYucjm0dM8dYa3JOTko2aNJLsMBnU6ooB-n3GEJv0VSohU65iD06N1tf7zUSVAXytzTZZl19z4KhIE34rzUQO8Ggq9R5VhIuoJAnOxUetz-j7F2rNN_CODxrr8zTMXAsVAV6Is77Ey0"}}
""";
        var (request, problem) = RelayRequest.Parse(Encoding.UTF8.GetBytes(fromSender.Trim()));
        Assert.Null(problem);
        Assert.Equal("time-sensitive", request!.Urgency);
    }

    [Fact]
    public void BaseModeIsRefused() => Assert.Null(RelayRequest.Parse(Fixtures.Body(mode: "base")).Request);

    [Fact]
    public void ATokenThatIsNotLowercaseHexIsRefused() => Assert.Null(RelayRequest.Parse(Fixtures.Body(token: new string('Z', 64))).Request);

    [Fact]
    public void AnEncOfTheWrongLengthIsRefused() => Assert.Null(RelayRequest.Parse(Fixtures.Body(enc: "short")).Request);

    [Fact]
    public void AnOversizedBodyIsTooLarge() => Assert.Equal("too_large", RelayRequest.Parse(new byte[RelayRequest.BodyLimit + 1]).Problem);
}

public class EntitlementTests
{
    readonly EntitlementCheck _check = new(Fixtures.Keyring, new FixedTime(Fixtures.Now));

    [Fact]
    public void ProVerifiesAndNamesTheTenant()
    {
        var (result, tenant) = _check.Verify(Fixtures.Jwt());
        Assert.Equal(EntitlementCheck.Result.Valid, result);
        Assert.Equal(Fixtures.Tenant, tenant);
    }

    [Fact]
    public void FreeIsUnpaid() => Assert.Equal(EntitlementCheck.Result.Unpaid, _check.Verify(Fixtures.Jwt(tier: "free")).Result);

    [Fact]
    public void AnUnknownTierIsUnpaid() => Assert.Equal(EntitlementCheck.Result.Unpaid, _check.Verify(Fixtures.Jwt(tier: "platinum")).Result);

    [Fact]
    public void ExpiredIsInvalid() => Assert.Equal(EntitlementCheck.Result.Invalid, _check.Verify(Fixtures.Jwt(exp: Fixtures.Now.ToUnixTimeSeconds() - 3600)).Result);

    [Fact]
    public void AnUnknownKidIsInvalid() => Assert.Equal(EntitlementCheck.Result.Invalid, _check.Verify(Fixtures.Jwt(kid: "other")).Result);

    [Fact]
    public void AnotherSignerIsInvalid() =>
        Assert.Equal(EntitlementCheck.Result.Invalid, _check.Verify(Fixtures.Jwt(signer: ECDsa.Create(ECCurve.NamedCurves.nistP256))).Result);

    [Fact]
    public void AnotherAudienceIsInvalid() => Assert.Equal(EntitlementCheck.Result.Invalid, _check.Verify(Fixtures.Jwt(aud: "com.example.other")).Result);

    [Fact]
    public void GarbageIsInvalid() => Assert.Equal(EntitlementCheck.Result.Invalid, _check.Verify("a.b.c").Result);

    [Fact]
    public void TheShippingKeyIsAValidPoint()
    {
        var point = EntitlementCheck.Shipping["lapslock-ent-2026-09"];
        using var key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = point[1..33], Y = point[33..65] } });
        Assert.NotNull(key);
    }
}

public class LimiterTests
{
    [Fact]
    public void ADeviceGetsThirtyAMinuteThenWaits()
    {
        var time = new FixedTime(Fixtures.Now);
        var limiter = new RelayRateLimiter(time);
        for (int i = 0; i < RelayRateLimiter.PerDevice; i++) Assert.True(limiter.TryAcquire(Fixtures.Tenant, Fixtures.Token, "1.2.3.4", false));
        Assert.False(limiter.TryAcquire(Fixtures.Tenant, Fixtures.Token, "1.2.3.4", false));
        time.Now = time.Now.AddMinutes(1);
        Assert.True(limiter.TryAcquire(Fixtures.Tenant, Fixtures.Token, "1.2.3.4", false));
    }

    [Fact]
    public void SandboxIsTighter()
    {
        var limiter = new RelayRateLimiter(new FixedTime(Fixtures.Now));
        for (int i = 0; i < RelayRateLimiter.SandboxPerTenant; i++) Assert.True(limiter.TryAcquire(Fixtures.Tenant, i.ToString("x64"), "1.2.3.4", true));
        Assert.False(limiter.TryAcquire(Fixtures.Tenant, "ff".PadLeft(64, '0'), "1.2.3.4", true));
    }
}

public class HandlerTests
{
    static async Task<RelayHandler.Answer> Run(ApnsResult apns, byte[]? body = null, bool query = false, FakeApns? fake = null)
    {
        var sender = fake ?? new FakeApns(apns);
        return await Fixtures.Handler(sender).HandleAsync(body ?? Fixtures.Body(), query, "1.2.3.4", CancellationToken.None);
    }

    [Fact]
    public async Task AcceptedByAppleIs202WithTheApnsId()
    {
        var answer = await Run(new ApnsResult(200, "1f3a2b4c-5d6e-7f80-91a2-b3c4d5e6f708", null));
        Assert.Equal(202, answer.Status);
        Assert.Contains("1f3a2b4c", answer.Body);
    }

    [Theory]
    [InlineData(410, null, 410, "device_unregistered")]
    [InlineData(400, "BadDeviceToken", 502, "apns_rejected")]
    [InlineData(503, null, 503, "apns_unavailable")]
    [InlineData(429, null, 503, "apns_unavailable")]
    public async Task ApplesAnswersMapToTheContract(int apple, string? reason, int status, string code)
    {
        var answer = await Run(new ApnsResult(apple, null, reason));
        Assert.Equal(status, answer.Status);
        Assert.Contains(code, answer.Body);
    }

    [Fact]
    public async Task AQueryStringIsRefusedBeforeAnythingElse()
    {
        var fake = new FakeApns(new ApnsResult(200, "x", null));
        Assert.Equal(400, (await Run(new ApnsResult(200, "x", null), query: true, fake: fake)).Status);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public async Task AFreeTenantIs402AndNothingIsSent()
    {
        var fake = new FakeApns(new ApnsResult(200, "x", null));
        Assert.Equal(402, (await Run(new ApnsResult(200, "x", null), body: Fixtures.Body(jwt: Fixtures.Jwt(tier: "free")), fake: fake)).Status);
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public async Task ABadEntitlementIs401()
    {
        Assert.Equal(401, (await Run(new ApnsResult(200, "x", null), body: Fixtures.Body(jwt: "a.b.c"))).Status);
    }

    [Fact]
    public async Task NoAnswerEverEchoesWhatWasSent()
    {
        var jwt = Fixtures.Jwt();
        var answers = new List<RelayHandler.Answer>();
        foreach (var apple in new[] { 200, 400, 410, 503 }) answers.Add(await Run(new ApnsResult(apple, null, "BadDeviceToken"), body: Fixtures.Body(jwt: jwt)));
        answers.Add(await Run(new ApnsResult(200, null, null), body: Fixtures.Body(jwt: "a.b.c")));
        answers.Add(await Run(new ApnsResult(200, null, null), query: true));
        foreach (var a in answers)
        {
            Assert.DoesNotContain(Fixtures.Token, a.Body);
            Assert.DoesNotContain(Fixtures.Ct, a.Body);
            Assert.DoesNotContain(Fixtures.Tenant, a.Body);
            Assert.DoesNotContain(jwt, a.Body);
        }
    }

    [Fact]
    public async Task ApplesReasonIsPassedOnOnlyWhenItIsAPlainIdentifier()
    {
        var answer = await Run(new ApnsResult(400, null, "<script>alert(1)</script>"));
        Assert.DoesNotContain("script", answer.Body);
    }

    [Fact]
    public void ThePushPayloadCarriesTheEnvelopeAndAPlaceholderOnly()
    {
        using var doc = JsonDocument.Parse(ApnsSender.Payload(true, "ENC", "CT"));
        var root = doc.RootElement;
        Assert.Equal("time-sensitive", root.GetProperty("aps").GetProperty("interruption-level").GetString());
        Assert.Equal(1, root.GetProperty("aps").GetProperty("mutable-content").GetInt32());
        Assert.Equal("ENC", root.GetProperty("e").GetProperty("enc").GetString());
        Assert.Equal(["aps", "e"], root.EnumerateObject().Select(p => p.Name).ToArray());
    }

    [Fact]
    public void OnlyATimeSensitiveAlertPlaysASound()
    {
        using var loud = JsonDocument.Parse(ApnsSender.Payload(true, "ENC", "CT"));
        using var quiet = JsonDocument.Parse(ApnsSender.Payload(false, "ENC", "CT"));
        Assert.Equal("default", loud.RootElement.GetProperty("aps").GetProperty("sound").GetString());
        Assert.False(quiet.RootElement.GetProperty("aps").TryGetProperty("sound", out _));
        Assert.Equal("active", quiet.RootElement.GetProperty("aps").GetProperty("interruption-level").GetString());
    }

    [Fact]
    public void AnAlertIsHeldForAPhoneThatIsOffline()
    {
        var now = new DateTimeOffset(2026, 10, 27, 3, 0, 0, TimeSpan.Zero);
        Assert.Equal(now.AddHours(1).ToUnixTimeSeconds(), ApnsSender.Expiration(now, timeSensitive: true));
        Assert.Equal(now.AddMinutes(30).ToUnixTimeSeconds(), ApnsSender.Expiration(now, timeSensitive: false));
        Assert.True(ApnsSender.Expiration(now, false) > now.ToUnixTimeSeconds());
    }
}

/// <summary>Counts signatures, made with a local key in place of Key Vault.</summary>
sealed class FakeSigner : IApnsSigner
{
    readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public int Calls;
    public Task<byte[]> SignAsync(byte[] data, CancellationToken cancel)
    {
        Calls++;
        return Task.FromResult(_key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
}

/// <summary>Answers each request with the next scripted status and reason, and keeps the
/// authorization header each one carried.</summary>
sealed class ScriptedApple(params (int Status, string? Reason)[] answers) : HttpMessageHandler
{
    readonly Queue<(int Status, string? Reason)> _answers = new(answers);
    public readonly List<string> Tokens = [];

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancel)
    {
        Tokens.Add(request.Headers.Authorization?.ToString() ?? request.Headers.GetValues("authorization").First());
        var (status, reason) = _answers.Count > 0 ? _answers.Dequeue() : (200, null);
        var response = new HttpResponseMessage((System.Net.HttpStatusCode)status);
        if (reason is not null) response.Content = new StringContent("{\"reason\":\"" + reason + "\"}");
        response.Headers.TryAddWithoutValidation("apns-id", "apns-" + Tokens.Count);
        return Task.FromResult(response);
    }
}

public class ApnsSenderTests
{
    static RelayOptions Options => new("KEYID12345", "TEAMID1234", "https://vault.example/keys/apns/1", "com.kainor.lapslock");

    static (ApnsSender Sender, ScriptedApple Apple, FakeSigner Signer, FixedTime Time) Make(params (int, string?)[] answers)
    {
        var apple = new ScriptedApple(answers);
        var signer = new FakeSigner();
        var time = new FixedTime(Fixtures.Now);
        return (new ApnsSender(new HttpClient(apple), signer, Options, time), apple, signer, time);
    }

    static Task<ApnsResult> Send(ApnsSender sender) => sender.SendAsync(Fixtures.Token, false, true, "ENC", "CT", CancellationToken.None);

    [Theory]
    [InlineData("ExpiredProviderToken")]
    [InlineData("InvalidProviderToken")]
    public async Task ARefusedProviderTokenIsSignedAgainAndThePushSentOnceMore(string reason)
    {
        var (sender, apple, signer, _) = Make((403, reason), (200, null));
        var result = await Send(sender);
        Assert.Equal(200, result.Status);
        Assert.Equal(2, apple.Tokens.Count);
        Assert.Equal(2, signer.Calls);
        Assert.NotEqual(apple.Tokens[0], apple.Tokens[1]);
    }

    [Fact]
    public async Task AnotherRefusalIsNotRetried()
    {
        var (sender, apple, signer, _) = Make((403, "BadCertificate"));
        var result = await Send(sender);
        Assert.Equal(403, result.Status);
        Assert.Single(apple.Tokens);
        Assert.Equal(1, signer.Calls);
    }

    [Fact]
    public async Task ATokenIsReplacedEarlyAtMostOnceEveryTwentyMinutes()
    {
        var (sender, apple, signer, time) = Make(
            (403, "ExpiredProviderToken"), (403, "ExpiredProviderToken"),
            (403, "ExpiredProviderToken"),
            (403, "ExpiredProviderToken"), (200, null));
        Assert.Equal(403, (await Send(sender)).Status);
        Assert.Equal(2, apple.Tokens.Count);
        time.Now = time.Now.AddMinutes(5);
        Assert.Equal(403, (await Send(sender)).Status);
        Assert.Equal(3, apple.Tokens.Count);
        Assert.Equal(2, signer.Calls);
        time.Now = time.Now.AddMinutes(16);
        Assert.Equal(200, (await Send(sender)).Status);
        Assert.Equal(5, apple.Tokens.Count);
        Assert.Equal(3, signer.Calls);
    }

    [Fact]
    public async Task AGoodTokenIsKeptForFortyMinutes()
    {
        var (sender, _, signer, time) = Make();
        await Send(sender);
        time.Now = time.Now.AddMinutes(39);
        await Send(sender);
        Assert.Equal(1, signer.Calls);
        time.Now = time.Now.AddMinutes(2);
        await Send(sender);
        Assert.Equal(2, signer.Calls);
    }
}

/// The alert service's route, RELAY-API.md section 15: the caller is Kainor's own service,
/// proved by a token from Kainor's tenant for the relay with the Alerts.Send role.
public class ServiceCallerTests
{
    static Task<ServiceCaller.Result> Verify(string? token, ServiceCaller? caller = null) =>
        (caller ?? Fixtures.Service()).VerifyAsync(token is null ? null : "Bearer " + token, CancellationToken.None);

    [Fact]
    public async Task TheAlertServicesOwnTokenIsAccepted() =>
        Assert.Equal(ServiceCaller.Result.Valid, await Verify(Fixtures.ServiceToken()));

    [Fact]
    public async Task TheOlderTokenFormatIsAcceptedToo() =>
        Assert.Equal(ServiceCaller.Result.Valid, await Verify(Fixtures.ServiceToken(olderFormat: true)));

    [Fact]
    public async Task AnIdentityWithoutTheRoleIsRefused()
    {
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(Fixtures.ServiceToken(roles: [])));
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(Fixtures.ServiceToken(roles: ["Something.Else"])));
    }

    [Fact]
    public async Task AnotherTenantsTokenIsRefusedEvenWithTheRole() =>
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(Fixtures.ServiceToken(tenant: Fixtures.Tenant)));

    [Fact]
    public async Task ATokenForSomethingElseIsRefused() =>
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(Fixtures.ServiceToken(audience: "00000003-0000-0000-c000-000000000000")));

    [Fact]
    public async Task AnExpiredTokenIsRefused() =>
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(Fixtures.ServiceToken(expired: true)));

    [Fact]
    public async Task ATokenSignedByAnotherKeyIsRefused() =>
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(Fixtures.ServiceToken(key: new RsaSecurityKey(RSA.Create(2048)) { KeyId = "service-test" })));

    [Fact]
    public async Task APersonsTokenIsRefused() =>
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(Fixtures.ServiceToken(scp: "Alerts.Send")));

    [Fact]
    public async Task AnUnsignedTokenIsRefused()
    {
        var parts = Fixtures.ServiceToken().Split('.');
        var none = Convert.ToBase64String(Encoding.ASCII.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}")).TrimEnd('=');
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(none + "." + parts[1] + "."));
    }

    [Fact]
    public async Task NoTokenAtAllIsRefused()
    {
        Assert.Equal(ServiceCaller.Result.Invalid, await Fixtures.Service().VerifyAsync(null, CancellationToken.None));
        Assert.Equal(ServiceCaller.Result.Invalid, await Fixtures.Service().VerifyAsync("Basic abc", CancellationToken.None));
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify("not-a-token"));
    }

    [Fact]
    public async Task KeysThatCannotBeFetchedAreNotTheCallersFault() =>
        Assert.Equal(ServiceCaller.Result.Unavailable, await Verify(Fixtures.ServiceToken(), Fixtures.Service(reachable: false)));

    // Second review, R2-11: once the relay knows the alert service's identity, another
    // identity in Kainor's tenant that was given the role is refused.
    [Fact]
    public async Task OnceTheAlertServiceIsNamedNoOtherIdentityWithTheRolePasses()
    {
        var pinned = Fixtures.Service(callerId: Fixtures.AlertService);
        Assert.Equal(ServiceCaller.Result.Valid, await Verify(Fixtures.ServiceToken(oid: Fixtures.AlertService), pinned));
        Assert.Equal(ServiceCaller.Result.Valid, await Verify(Fixtures.ServiceToken(oid: Fixtures.AlertService.ToUpperInvariant()), pinned));
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(Fixtures.ServiceToken(), pinned));
        // The role is still needed.
        Assert.Equal(ServiceCaller.Result.Invalid, await Verify(Fixtures.ServiceToken(oid: Fixtures.AlertService, roles: []), pinned));
        // Not named: as before, the role decides.
        Assert.Equal(ServiceCaller.Result.Valid, await Verify(Fixtures.ServiceToken()));
    }
}

public class ServiceRouteTests
{
    static readonly ApnsResult Accepted = new(200, "1f3a2b4c-5d6e-7f80-91a2-b3c4d5e6f708", null);

    static async Task<RelayHandler.Answer> Run(FakeApns apns, string? token, byte[]? body = null, bool query = false, ServiceCaller? service = null, bool configured = true) =>
        await Fixtures.Handler(apns, service: configured ? service ?? Fixtures.Service() : null)
            .HandleServiceAsync(body ?? Fixtures.ServiceBody(), query, token is null ? null : "Bearer " + token, CancellationToken.None);

    [Fact]
    public async Task TheAlertServiceSendsWithNoEntitlementToken()
    {
        var apns = new FakeApns(Accepted);
        var answer = await Run(apns, Fixtures.ServiceToken());
        Assert.Equal(202, answer.Status);
        Assert.Contains("1f3a2b4c", answer.Body);
        Assert.Equal(1, apns.Calls);
    }

    [Fact]
    public void TheBodyIsTheSameRequestWithoutTheEntitlement()
    {
        Assert.NotNull(RelayRequest.Parse(Fixtures.ServiceBody(), service: true).Request);
        // Each route refuses the other's body: nothing is carried that the route does not check.
        Assert.Null(RelayRequest.Parse(Fixtures.Body(), service: true).Request);
        Assert.Null(RelayRequest.Parse(Fixtures.ServiceBody()).Request);
        Assert.Null(RelayRequest.Parse(Fixtures.ServiceBody(extra: ",\"tenant\":\"" + Fixtures.Tenant + "\""), service: true).Request);
    }

    [Fact]
    public async Task AnyoneElseIs401AndNothingIsSent()
    {
        foreach (var token in new[] { null, "a.b.c", Fixtures.ServiceToken(roles: []), Fixtures.ServiceToken(tenant: Fixtures.Tenant), Fixtures.Jwt() })
        {
            var apns = new FakeApns(Accepted);
            var answer = await Run(apns, token);
            Assert.Equal(401, answer.Status);
            Assert.Contains("service_token_invalid", answer.Body);
            Assert.Equal(0, apns.Calls);
        }
    }

    [Fact]
    public async Task ARelayNotSetUpForTheServiceRefusesEveryone()
    {
        var apns = new FakeApns(Accepted);
        Assert.Equal(401, (await Run(apns, Fixtures.ServiceToken(), configured: false)).Status);
        Assert.Equal(0, apns.Calls);
    }

    [Fact]
    public async Task TheCallerIsCheckedBeforeTheBodyIsRead()
    {
        // A stranger learns nothing about what a well-formed body looks like.
        var answer = await Run(new FakeApns(Accepted), null, body: Encoding.UTF8.GetBytes("not json"));
        Assert.Equal(401, answer.Status);
    }

    [Fact]
    public async Task AMalformedBodyFromTheServiceIs400()
    {
        var apns = new FakeApns(Accepted);
        Assert.Equal(400, (await Run(apns, Fixtures.ServiceToken(), body: Fixtures.Body())).Status);
        Assert.Equal(400, (await Run(apns, Fixtures.ServiceToken(), query: true)).Status);
        Assert.Equal(0, apns.Calls);
    }

    [Fact]
    public async Task KeysThatCannotBeFetchedAre503SoTheServiceTriesAgain()
    {
        var apns = new FakeApns(Accepted);
        var answer = await Run(apns, Fixtures.ServiceToken(), service: Fixtures.Service(reachable: false));
        Assert.Equal(503, answer.Status);
        Assert.Contains("keys_unavailable", answer.Body);
        Assert.Equal(0, apns.Calls);
    }

    [Fact]
    public async Task TheEntitlementRouteDoesNotTakeTheServicesToken()
    {
        // The token in the Authorization header means nothing to POST /relay, which reads its body only.
        var apns = new FakeApns(Accepted);
        var answer = await Fixtures.Handler(apns, service: Fixtures.Service()).HandleAsync(Fixtures.ServiceBody(), false, "1.2.3.4", CancellationToken.None);
        Assert.Equal(400, answer.Status);
        Assert.Equal(0, apns.Calls);
    }

    [Fact]
    public async Task EachPhoneKeepsItsLimitAndTheServicesOneAddressIsNotOne()
    {
        var handler = Fixtures.Handler(new FakeApns(Accepted), service: Fixtures.Service());
        var bearer = "Bearer " + Fixtures.ServiceToken();
        // More phones in a minute than one address may send on the other route.
        for (int i = 0; i < RelayRateLimiter.PerAddress + 60; i++)
            Assert.Equal(202, (await handler.HandleServiceAsync(Fixtures.ServiceBody(token: i.ToString("x64")), false, bearer, CancellationToken.None)).Status);
        // One phone still gets thirty.
        for (int i = 0; i < RelayRateLimiter.PerDevice; i++)
            Assert.Equal(202, (await handler.HandleServiceAsync(Fixtures.ServiceBody(), false, bearer, CancellationToken.None)).Status);
        var limited = await handler.HandleServiceAsync(Fixtures.ServiceBody(), false, bearer, CancellationToken.None);
        Assert.Equal(429, limited.Status);
        Assert.NotNull(limited.RetryAfter);
    }

    [Fact]
    public void TheServiceHasOneCeilingAndSandboxALowerOne()
    {
        var limiter = new RelayRateLimiter(new FixedTime(Fixtures.Now));
        for (int i = 0; i < RelayRateLimiter.SandboxPerService; i++) Assert.True(limiter.TryAcquireService(i.ToString("x64"), true));
        Assert.False(limiter.TryAcquireService("ff".PadLeft(64, '0'), true));
        // Sandbox spending its ceiling does not take production's.
        Assert.True(limiter.TryAcquireService("ee".PadLeft(64, '0'), false));
    }

    [Fact]
    public async Task NoAnswerEchoesTheTokenOrThePhone()
    {
        var token = Fixtures.ServiceToken();
        var answers = new List<RelayHandler.Answer>();
        foreach (var apple in new[] { 200, 400, 410, 503 }) answers.Add(await Run(new FakeApns(new ApnsResult(apple, null, "BadDeviceToken")), token));
        answers.Add(await Run(new FakeApns(Accepted), "a.b.c"));
        answers.Add(await Run(new FakeApns(Accepted), token, query: true));
        foreach (var a in answers)
        {
            Assert.DoesNotContain(Fixtures.Token, a.Body);
            Assert.DoesNotContain(Fixtures.Ct, a.Body);
            Assert.DoesNotContain(token, a.Body);
            Assert.DoesNotContain(Fixtures.Kainor, a.Body);
        }
    }
}
