namespace MiraFunction.Models;

public class CreateUdpRuleRequest
{
    /// <summary>
    /// Full NSG resource ID, e.g.
    /// /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/{name}
    /// </summary>
    public string NsgResourceId { get; set; } = string.Empty;

    /// <summary>One or more source IP addresses / CIDR ranges.</summary>
    public string[] SourceAddresses { get; set; } = [];

    /// <summary>Start of the destination UDP port range (inclusive).</summary>
    public int PortRangeStart { get; set; }

    /// <summary>End of the destination UDP port range (inclusive).</summary>
    public int PortRangeEnd { get; set; }

    /// <summary>Name for the new security rule.</summary>
    public string RuleName { get; set; } = string.Empty;

    /// <summary>Inbound or Outbound. Default: Inbound.</summary>
    public string Direction { get; set; } = "Inbound";

    /// <summary>Allow or Deny. Default: Allow.</summary>
    public string Access { get; set; } = "Allow";

    public string? Description { get; set; }
}
