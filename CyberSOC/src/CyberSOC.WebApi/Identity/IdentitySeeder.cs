using CyberSOC.Domain.IdentityAccess;
using CyberSOC.Persistence.Identity;
using Microsoft.AspNetCore.Identity;
using System.Data;

namespace CyberSOC.WebApi.Identity
{

    /// <summary>
    /// Creates the five SOC roles and one bootstrap Administrator account if none
    /// exists yet — solves the chicken-and-egg problem where /api/auth/register
    /// requires an Administrator to call it, but no Administrator exists on a
    /// fresh database. Bootstrap credentials come from configuration
    /// (Bootstrap:AdminUserName/Bootstrap:AdminPassword) — set a real value via
    /// user-secrets/environment variables, never commit a real password.
    /// </summary>
    public static class IdentitySeeder
    {
        public static async Task SeedAsync(IServiceProvider services)
        {
            using var scope = services.CreateScope();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();
            var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("IdentitySeeder");

            foreach (var roleName in Roles.All)
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                    logger.LogInformation("Created role {RoleName}", roleName);
                }
            }

            var adminUserName = configuration["Bootstrap:AdminUserName"] ?? "admin";
            var existingAdmin = await userManager.FindByNameAsync(adminUserName);
            if (existingAdmin is not null) return;

            var adminPassword = configuration["Bootstrap:AdminPassword"];
            if (string.IsNullOrWhiteSpace(adminPassword))
            {
                logger.LogWarning(
                    "No bootstrap Administrator created: set Bootstrap:AdminPassword " +
                    "(via user-secrets or env var) to create the first login.");
                return;
            }

            var adminUser = new ApplicationUser
            {
                UserName = adminUserName,
                Email = configuration["Bootstrap:AdminEmail"] ?? "admin@cybersoc.local",
                DisplayName = "Bootstrap Administrator",
                IsActive = true
            };

            var result = await userManager.CreateAsync(adminUser, adminPassword);
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(adminUser, Roles.Administrator);
                logger.LogInformation("Bootstrap Administrator account '{UserName}' created.", adminUserName);
            }
            else
            {
                logger.LogError(
                    "Failed to create bootstrap Administrator: {Errors}",
                    string.Join("; ", result.Errors.Select(e => e.Description)));
            }
        }
    }

}
