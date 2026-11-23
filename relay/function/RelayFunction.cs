using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Kainor.TenantKeep.Relay;

/// <summary>POST /relay and POST /relay/service. Each reads the body, hands it to
/// RelayHandler, writes the answer. No logger is injected on purpose: there is nothing about
/// a request worth writing down.</summary>
public sealed class RelayFunction
{
    readonly RelayHandler _handler;

    public RelayFunction(RelayHandler handler) { _handler = handler; }

    [Function("Relay")]
    public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "relay")] HttpRequest request, CancellationToken cancel)
    {
        var body = await ReadAsync(request, cancel);
        return Write(request, await _handler.HandleAsync(body, request.QueryString.HasValue, request.HttpContext.Connection.RemoteIpAddress?.ToString(), cancel));
    }

    /// <summary>docs/RELAY-API.md section 15: Kainor's alert service, by its own identity.</summary>
    [Function("RelayService")]
    public async Task<IActionResult> RunService([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "relay/service")] HttpRequest request, CancellationToken cancel)
    {
        var body = await ReadAsync(request, cancel);
        return Write(request, await _handler.HandleServiceAsync(body, request.QueryString.HasValue, request.Headers.Authorization, cancel));
    }

    /// One byte past the limit at most, so an oversized body is refused without being held.
    static async Task<byte[]> ReadAsync(HttpRequest request, CancellationToken cancel)
    {
        using var buffer = new MemoryStream();
        var limit = RelayRequest.BodyLimit + 1;
        var chunk = new byte[4096];
        int read;
        while ((read = await request.Body.ReadAsync(chunk, cancel)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > limit) break;
        }
        return buffer.ToArray();
    }

    static ContentResult Write(HttpRequest request, RelayHandler.Answer answer)
    {
        if (answer.RetryAfter is int seconds) request.HttpContext.Response.Headers.RetryAfter = seconds.ToString();
        return new ContentResult { StatusCode = answer.Status, Content = answer.Body, ContentType = "application/json; charset=utf-8" };
    }
}
