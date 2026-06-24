using CyberSOC.Domain.Detection;
using CyberSOC.Domain.Detection.Rules;
using Microsoft.Extensions.DependencyInjection;

namespace CyberSOC.Infrastructure
{
    public static class InfrastructureServiceCollectionExtensions
    {
        /// <summary>
        /// Registers every active detection rule as IDetectionRule. This is the
        /// single place that decides which rules run — adding a new rule (e.g. a
        /// SIEM correlation rule in Phase 2) means adding one line here, nothing
        /// in the Application handler changes.
        /// </summary>
        public static IServiceCollection AddCyberSocInfrastructure(this IServiceCollection services)
        {
            services.AddSingleton<IDetectionRule>(
                new ApiRateThresholdRule(failureThreshold: 10, window: TimeSpan.FromMinutes(1)));

            return services;
        }
    }
}
