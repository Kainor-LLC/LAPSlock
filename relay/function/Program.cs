using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;
using Kainor.TenantKeep.Relay;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// TenantKeep alert relay, docs/RELAY-API.md. Stateless: no storage account binding beyond
// what the Functions host needs for itself, no table, no queue, no custom telemetry.
var builder = FunctionsApplication.CreateBuilder(args);
builder.ConfigureFunctionsWebApplication();

// Warning and above only, and the code logs nothing about a request in the first place.
builder.Logging.SetMinimumLevel(LogLevel.Warning);

var options = RelayOptions.FromEnvironment();
builder.Services.AddSingleton(options);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(_ => new EntitlementCheck(EntitlementCheck.Shipping, TimeProvider.System));
builder.Services.AddSingleton<RelayRateLimiter>();
// The function's own system-assigned identity, asked directly: the default chain tried
// several other credentials first on the cold start that carries the night's first alert.
builder.Services.AddSingleton<IApnsSigner>(_ => new KeyVaultApnsSigner(
    new CryptographyClient(new Uri(options.KeyVaultKeyId), new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned))));
// One HTTP/2 connection to Apple, kept open with a ping every minute while the instance
// lives, so sparse alerts do not each open a new TLS connection. The ping stays inside
// Azure's idle timeout for outbound connections, about four minutes.
builder.Services.AddSingleton(_ => new HttpClient(new SocketsHttpHandler
{
    EnableMultipleHttp2Connections = true,
    KeepAlivePingDelay = TimeSpan.FromSeconds(60),
    KeepAlivePingTimeout = TimeSpan.FromSeconds(10),
    KeepAlivePingPolicy = HttpKeepAlivePingPolicy.Always,
    PooledConnectionIdleTimeout = TimeSpan.FromMinutes(5),
}) { Timeout = TimeSpan.FromSeconds(10) });
builder.Services.AddSingleton<IApnsSender, ApnsSender>();
builder.Services.AddSingleton<RelayHandler>();

builder.Build().Run();
