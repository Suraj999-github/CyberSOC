using CyberSOC.Application.Common.Interfaces;
using CyberSOC.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CyberSOC.Persistence
{
    public static class PersistenceServiceCollectionExtensions
    {
        public static IServiceCollection AddCyberSocPersistence(
            this IServiceCollection services, IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("CyberSocDb")
                ?? throw new InvalidOperationException(
                    "Connection string 'CyberSocDb' not found. Set it in appsettings.json or env var ConnectionStrings__CyberSocDb.");

            services.AddDbContext<CyberSocDbContext>(options =>
                options.UseSqlServer(connectionString, sqlServer =>
                    sqlServer.EnableRetryOnFailure(maxRetryCount: 3))); // built-in resilience, same role Polly plays elsewhere

            services.AddScoped<ISecurityEventRepository, SecurityEventRepository>();
            services.AddScoped<IAlertRepository, AlertRepository>();

            return services;
        }
    }

}
