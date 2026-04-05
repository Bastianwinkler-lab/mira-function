using Azure;
using Azure.ResourceManager;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models;
using MiraFunction.Models;

namespace MiraFunction.Services;

public class NsgService(ArmClient armClient)
{
    private const int PriorityRangeStart = 2000;
    private const int PriorityRangeEnd = 4000;

    // -------------------------------------------------------------------------
    // Get next free priority ID in [2000, 4000]
    // -------------------------------------------------------------------------

    public async Task<int> GetNextFreeIdAsync(string nsgResourceId, CancellationToken ct = default)
    {
        var rules = await GetAllCustomRulesAsync(nsgResourceId, ct);
        var used = rules
            .Where(r => r.Priority is >= PriorityRangeStart and <= PriorityRangeEnd)
            .Select(r => r.Priority!.Value)
            .ToHashSet();

        for (int p = PriorityRangeStart; p <= PriorityRangeEnd; p++)
            if (!used.Contains(p))
                return p;

        throw new InvalidOperationException(
            $"No free priority available in range {PriorityRangeStart}–{PriorityRangeEnd}.");
    }

    // -------------------------------------------------------------------------
    // Create TCP rule
    // -------------------------------------------------------------------------

    public async Task<NsgRuleInfo> CreateTcpRuleAsync(
        CreateTcpRuleRequest request, CancellationToken ct = default)
    {
        var nsg = GetNsgResource(request.NsgResourceId);
        var priority = await GetNextFreeIdAsync(request.NsgResourceId, ct);

        var data = new SecurityRuleData
        {
            Protocol = SecurityRuleProtocol.Tcp,
            SourcePortRange = "*",
            DestinationAddressPrefix = "*",
            DestinationPortRange = request.DestinationPort.ToString(),
            Access = new SecurityRuleAccess(request.Access),
            Direction = new SecurityRuleDirection(request.Direction),
            Priority = priority,
            Description = request.Description
        };

        ApplySourceAddresses(data, request.SourceAddresses);

        var op = await nsg.GetSecurityRules()
            .CreateOrUpdateAsync(WaitUntil.Completed, request.RuleName, data, ct);

        return MapToInfo(op.Value.Data);
    }

    // -------------------------------------------------------------------------
    // Create UDP rule with port range
    // -------------------------------------------------------------------------

    public async Task<NsgRuleInfo> CreateUdpRuleAsync(
        CreateUdpRuleRequest request, CancellationToken ct = default)
    {
        var nsg = GetNsgResource(request.NsgResourceId);
        var priority = await GetNextFreeIdAsync(request.NsgResourceId, ct);

        var data = new SecurityRuleData
        {
            Protocol = SecurityRuleProtocol.Udp,
            SourcePortRange = "*",
            DestinationAddressPrefix = "*",
            DestinationPortRange = $"{request.PortRangeStart}-{request.PortRangeEnd}",
            Access = new SecurityRuleAccess(request.Access),
            Direction = new SecurityRuleDirection(request.Direction),
            Priority = priority,
            Description = request.Description
        };

        ApplySourceAddresses(data, request.SourceAddresses);

        var op = await nsg.GetSecurityRules()
            .CreateOrUpdateAsync(WaitUntil.Completed, request.RuleName, data, ct);

        return MapToInfo(op.Value.Data);
    }

    // -------------------------------------------------------------------------
    // Delete rule by priority (the "ID" in the 2000–4000 range)
    // -------------------------------------------------------------------------

    public async Task<bool> DeleteRuleByPriorityAsync(
        string nsgResourceId, int priority, CancellationToken ct = default)
    {
        var nsg = GetNsgResource(nsgResourceId);

        await foreach (var rule in nsg.GetSecurityRules().GetAllAsync(ct))
        {
            if (rule.Data.Priority == priority)
            {
                await rule.DeleteAsync(WaitUntil.Completed, ct);
                return true;
            }
        }

        return false; // not found
    }

    // -------------------------------------------------------------------------
    // List rules whose name starts with a given prefix
    // -------------------------------------------------------------------------

    public async Task<List<NsgRuleInfo>> ListRulesByNamePrefixAsync(
        string nsgResourceId, string namePrefix, CancellationToken ct = default)
    {
        var nsg = GetNsgResource(nsgResourceId);
        var result = new List<NsgRuleInfo>();

        await foreach (var rule in nsg.GetSecurityRules().GetAllAsync(ct))
        {
            if (rule.Data.Name?.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase) == true)
                result.Add(MapToInfo(rule.Data));
        }

        return result;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private NetworkSecurityGroupResource GetNsgResource(string nsgResourceId) =>
        armClient.GetNetworkSecurityGroupResource(new Azure.Core.ResourceIdentifier(nsgResourceId));

    private async Task<List<SecurityRuleData>> GetAllCustomRulesAsync(
        string nsgResourceId, CancellationToken ct)
    {
        var nsg = GetNsgResource(nsgResourceId);
        var rules = new List<SecurityRuleData>();
        await foreach (var rule in nsg.GetSecurityRules().GetAllAsync(ct))
            rules.Add(rule.Data);
        return rules;
    }

    /// <summary>
    /// Sets SourceAddressPrefix (single) or SourceAddressPrefixes (multiple).
    /// Azure requires exactly one of the two to be populated.
    /// </summary>
    private static void ApplySourceAddresses(SecurityRuleData data, string[] addresses)
    {
        if (addresses.Length == 1)
        {
            data.SourceAddressPrefix = addresses[0];
        }
        else
        {
            foreach (var addr in addresses)
                data.SourceAddressPrefixes.Add(addr);
        }
    }

    private static NsgRuleInfo MapToInfo(SecurityRuleData d)
    {
        var sourceAddresses = d.SourceAddressPrefixes.Count > 0
            ? [.. d.SourceAddressPrefixes]
            : d.SourceAddressPrefix is not null
                ? [d.SourceAddressPrefix]
                : Array.Empty<string>();

        var destAddresses = d.DestinationAddressPrefixes.Count > 0
            ? [.. d.DestinationAddressPrefixes]
            : d.DestinationAddressPrefix is not null
                ? [d.DestinationAddressPrefix]
                : Array.Empty<string>();

        var destPorts = d.DestinationPortRanges.Count > 0
            ? [.. d.DestinationPortRanges]
            : d.DestinationPortRange is not null
                ? [d.DestinationPortRange]
                : Array.Empty<string>();

        var srcPort = d.SourcePortRanges.Count > 0
            ? string.Join(",", d.SourcePortRanges)
            : d.SourcePortRange ?? string.Empty;

        return new NsgRuleInfo
        {
            Name = d.Name ?? string.Empty,
            Priority = d.Priority ?? 0,
            Protocol = d.Protocol?.ToString() ?? string.Empty,
            Direction = d.Direction?.ToString() ?? string.Empty,
            Access = d.Access?.ToString() ?? string.Empty,
            SourceAddresses = sourceAddresses,
            SourcePortRange = srcPort,
            DestinationAddresses = destAddresses,
            DestinationPortRanges = destPorts,
            Description = d.Description,
            ProvisioningState = d.ProvisioningState?.ToString() ?? string.Empty
        };
    }
}
