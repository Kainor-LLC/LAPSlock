using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Kainor.TenantKeep.Relay;

/// <summary>POST /relay. Reads the body, hands it to RelayHandler, writes the answer.
/// No logger is injected on purpose: there is nothing about a request worth writing down.</summary>
public sealed class RelayFunction
{
    readonly RelayHandler _handler;

    public RelayFunction(RelayHandler handler) { _handler = handler; }

    [Function("Relay")]
    public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "relay")] HttpRequest request, CancellationToken cancel)
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
        var answer = await _handler.HandleAsync(buffer.ToArray(), request.QueryString.HasValue, request.HttpContext.Connection.RemoteIpAddress?.ToString(), cancel);
        if (answer.RetryAfter is int seconds) request.HttpContext.Response.Headers.RetryAfter = seconds.ToString();
        return new ContentResult { StatusCode = answer.Status, Content = answer.Body, ContentType = "application/json; charset=utf-8" };
    }
}
