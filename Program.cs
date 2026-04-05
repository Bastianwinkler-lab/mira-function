using Azure.Identity;
using Azure.ResourceManager;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MiraFunction.Services;

var host = new HostBuilder()
    .ConfigureFunctionsWebApplication()
    .ConfigureServices(services =>
    {
        services.AddApplicationInsightsTelemetryWorkerService();
        services.ConfigureFunctionsApplicationInsights();

        // ArmClient with Managed Identity (DefaultAzureCredential picks up the
        // system-assigned or user-assigned identity when running in Azure)
        services.AddSingleton(_ => new ArmClient(new DefaultAzureCredential()));
        services.AddSingleton<NsgService>();
    })
    .Build();

host.Run();
