using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using MiraFunction.Models;
using MiraFunction.Services;

namespace MiraFunction.Functions;

public class NsgFunctions(NsgService nsgService, ILogger<NsgFunctions> logger)
{
    // -------------------------------------------------------------------------
    // GET /api/nsg/rules/next-free-id?nsgResourceId=...
    //
    // Returns the lowest unused priority in [2000, 4000].
    // -------------------------------------------------------------------------

    [Function("GetNextFreeId")]
    public async Task<IActionResult> GetNextFreeId(
        [HttpTrigger(AuthorizationLevel.Function, "get",
            Route = "nsg/rules/next-free-id")] HttpRequest req,
        CancellationToken ct)
    {
        var nsgResourceId = req.Query["nsgResourceId"].ToString();
        if (string.IsNullOrWhiteSpace(nsgResourceId))
            return new BadRequestObjectResult(
                new { error = "Query parameter 'nsgResourceId' is required." });

        logger.LogInformation("GetNextFreeId for NSG {NsgResourceId}", nsgResourceId);

        var nextId = await nsgService.GetNextFreeIdAsync(nsgResourceId, ct);
        return new OkObjectResult(new { nextFreeId = nextId });
    }

    // -------------------------------------------------------------------------
    // POST /api/nsg/rules/tcp
    //
    // Body: CreateTcpRuleRequest (JSON)
    // Creates an inbound TCP Allow rule for a list of source IPs on a single port.
    // Priority is auto-assigned as the next free ID.
    // -------------------------------------------------------------------------

    [Function("CreateTcpRule")]
    public async Task<IActionResult> CreateTcpRule(
        [HttpTrigger(AuthorizationLevel.Function, "post",
            Route = "nsg/rules/tcp")] HttpRequest req,
        CancellationToken ct)
    {
        CreateTcpRuleRequest? request;
        try
        {
            request = await req.ReadFromJsonAsync<CreateTcpRuleRequest>(ct);
        }
        catch (Exception ex)
        {
            return new BadRequestObjectResult(new { error = "Invalid JSON body.", detail = ex.Message });
        }

        if (request is null)
            return new BadRequestObjectResult(new { error = "Request body is required." });

        var validationError = ValidateTcpRequest(request);
        if (validationError is not null)
            return new BadRequestObjectResult(new { error = validationError });

        logger.LogInformation(
            "CreateTcpRule '{RuleName}' on NSG {NsgResourceId} port {Port}",
            request.RuleName, request.NsgResourceId, request.DestinationPort);

        var rule = await nsgService.CreateTcpRuleAsync(request, ct);
        return new OkObjectResult(rule);
    }

    // -------------------------------------------------------------------------
    // POST /api/nsg/rules/udp
    //
    // Body: CreateUdpRuleRequest (JSON)
    // Creates an inbound UDP Allow rule for a list of source IPs on a port range.
    // Priority is auto-assigned as the next free ID.
    // -------------------------------------------------------------------------

    [Function("CreateUdpRule")]
    public async Task<IActionResult> CreateUdpRule(
        [HttpTrigger(AuthorizationLevel.Function, "post",
            Route = "nsg/rules/udp")] HttpRequest req,
        CancellationToken ct)
    {
        CreateUdpRuleRequest? request;
        try
        {
            request = await req.ReadFromJsonAsync<CreateUdpRuleRequest>(ct);
        }
        catch (Exception ex)
        {
            return new BadRequestObjectResult(new { error = "Invalid JSON body.", detail = ex.Message });
        }

        if (request is null)
            return new BadRequestObjectResult(new { error = "Request body is required." });

        var validationError = ValidateUdpRequest(request);
        if (validationError is not null)
            return new BadRequestObjectResult(new { error = validationError });

        logger.LogInformation(
            "CreateUdpRule '{RuleName}' on NSG {NsgResourceId} ports {Start}-{End}",
            request.RuleName, request.NsgResourceId, request.PortRangeStart, request.PortRangeEnd);

        var rule = await nsgService.CreateUdpRuleAsync(request, ct);
        return new OkObjectResult(rule);
    }

    // -------------------------------------------------------------------------
    // DELETE /api/nsg/rules/{priority}?nsgResourceId=...
    //
    // Deletes the rule whose priority equals {priority}.
    // Returns 204 No Content on success, 404 if not found.
    // -------------------------------------------------------------------------

    [Function("DeleteRuleByPriority")]
    public async Task<IActionResult> DeleteRuleByPriority(
        [HttpTrigger(AuthorizationLevel.Function, "delete",
            Route = "nsg/rules/{priority:int}")] HttpRequest req,
        int priority,
        CancellationToken ct)
    {
        var nsgResourceId = req.Query["nsgResourceId"].ToString();
        if (string.IsNullOrWhiteSpace(nsgResourceId))
            return new BadRequestObjectResult(
                new { error = "Query parameter 'nsgResourceId' is required." });

        logger.LogInformation(
            "DeleteRuleByPriority {Priority} on NSG {NsgResourceId}", priority, nsgResourceId);

        var deleted = await nsgService.DeleteRuleByPriorityAsync(nsgResourceId, priority, ct);
        if (!deleted)
            return new NotFoundObjectResult(
                new { error = $"No rule with priority {priority} found on the specified NSG." });

        return new NoContentResult();
    }

    // -------------------------------------------------------------------------
    // GET /api/nsg/rules?nsgResourceId=...&namePrefix=...
    //
    // Lists all rules whose name starts with namePrefix (case-insensitive).
    // Example namePrefix: "0001.11.00"
    // -------------------------------------------------------------------------

    [Function("ListRulesByNamePrefix")]
    public async Task<IActionResult> ListRulesByNamePrefix(
        [HttpTrigger(AuthorizationLevel.Function, "get",
            Route = "nsg/rules")] HttpRequest req,
        CancellationToken ct)
    {
        var nsgResourceId = req.Query["nsgResourceId"].ToString();
        var namePrefix = req.Query["namePrefix"].ToString();

        if (string.IsNullOrWhiteSpace(nsgResourceId))
            return new BadRequestObjectResult(
                new { error = "Query parameter 'nsgResourceId' is required." });

        if (string.IsNullOrWhiteSpace(namePrefix))
            return new BadRequestObjectResult(
                new { error = "Query parameter 'namePrefix' is required." });

        logger.LogInformation(
            "ListRulesByNamePrefix '{Prefix}' on NSG {NsgResourceId}", namePrefix, nsgResourceId);

        var rules = await nsgService.ListRulesByNamePrefixAsync(nsgResourceId, namePrefix, ct);
        return new OkObjectResult(rules);
    }

    // -------------------------------------------------------------------------
    // Validation helpers
    // -------------------------------------------------------------------------

    private static string? ValidateTcpRequest(CreateTcpRuleRequest r)
    {
        if (string.IsNullOrWhiteSpace(r.NsgResourceId))
            return "'nsgResourceId' is required.";
        if (string.IsNullOrWhiteSpace(r.RuleName))
            return "'ruleName' is required.";
        if (r.SourceAddresses is null || r.SourceAddresses.Length == 0)
            return "'sourceAddresses' must contain at least one entry.";
        if (r.DestinationPort is < 1 or > 65535)
            return "'destinationPort' must be between 1 and 65535.";
        return null;
    }

    private static string? ValidateUdpRequest(CreateUdpRuleRequest r)
    {
        if (string.IsNullOrWhiteSpace(r.NsgResourceId))
            return "'nsgResourceId' is required.";
        if (string.IsNullOrWhiteSpace(r.RuleName))
            return "'ruleName' is required.";
        if (r.SourceAddresses is null || r.SourceAddresses.Length == 0)
            return "'sourceAddresses' must contain at least one entry.";
        if (r.PortRangeStart < 1 || r.PortRangeEnd > 65535 || r.PortRangeStart > r.PortRangeEnd)
            return "'portRangeStart'/'portRangeEnd' must be valid (1–65535, start ≤ end).";
        return null;
    }
}
