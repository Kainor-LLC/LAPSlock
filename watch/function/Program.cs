using Azure.Core;
using Azure.Identity;
using Kainor.TenantKeep.Watch;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = FunctionsApplication.CreateBuilder(args);
builder.ConfigureFunctionsWebApplication();

var options = WatchOptions.FromEnvironment();
TokenCredential identity = new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned);
var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };

builder.Services.AddSingleton(options);
builder.Services.AddSingleton(new WatchStore(options, identity));
builder.Services.AddSingleton(new GraphReader(options, identity, http));
builder.Services.AddSingleton(new AlertSender(options, identity, http));

builder.Build().Run();
