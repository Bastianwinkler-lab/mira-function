namespace MiraFunction.Models;

public class NsgRuleInfo
{
    public string Name { get; set; } = string.Empty;
    public int Priority { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string Direction { get; set; } = string.Empty;
    public string Access { get; set; } = string.Empty;
    public string[] SourceAddresses { get; set; } = [];
    public string SourcePortRange { get; set; } = string.Empty;
    public string[] DestinationAddresses { get; set; } = [];
    public string[] DestinationPortRanges { get; set; } = [];
    public string? Description { get; set; }
    public string ProvisioningState { get; set; } = string.Empty;
}
