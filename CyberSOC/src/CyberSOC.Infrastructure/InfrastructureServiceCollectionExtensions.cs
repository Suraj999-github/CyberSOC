using CyberSOC.Domain.Detection;
using CyberSOC.Domain.Detection.Rules;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CyberSOC.Infrastructure
{
    public static class InfrastructureServiceCollectionExtensions
    {
        /// <summary>
        /// Registers every active detection rule as IDetectionRule. This is the
        /// single place that decides which rules run — adding a new rule means
        /// adding one line here, nothing in the Application handler changes.
        /// Threshold/window are read from configuration (DetectionRules:ApiRateThreshold)
        /// so they can be tuned per environment without a code change — a 1-minute
        /// window is realistic for production brute-force traffic, but too tight
        /// if you're manually clicking through Swagger to test.
        /// </summary>
        public static IServiceCollection AddCyberSocInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            var failureThreshold = configuration.GetValue<int?>("DetectionRules:ApiRateThreshold:FailureThreshold") ?? 10;
            var windowSeconds = configuration.GetValue<int?>("DetectionRules:ApiRateThreshold:WindowSeconds") ?? 60;

            services.AddSingleton<IDetectionRule>(
                new ApiRateThresholdRule(failureThreshold, TimeSpan.FromSeconds(windowSeconds)));

            return services;
        }
    }
    //public static class InfrastructureServiceCollectionExtensions
    //{
    //    /// <summary>
    //    /// Registers every active detection rule as IDetectionRule. This is the
    //    /// single place that decides which rules run — adding a new rule (e.g. a
    //    /// SIEM correlation rule in Phase 2) means adding one line here, nothing
    //    /// in the Application handler changes.
    //    /// </summary>
    //    public static IServiceCollection AddCyberSocInfrastructure(this IServiceCollection services)
    //    {
    //        services.AddSingleton<IDetectionRule>(
    //            new ApiRateThresholdRule(failureThreshold: 10, window: TimeSpan.FromMinutes(1)));

    //        return services;
    //    }
    //}

}
