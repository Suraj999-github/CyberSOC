using CyberSOC.Domain.IdentityAccess;
using CyberSOC.Persistence.Identity;
using CyberSOC.WebApi.Identity;
using Microsoft.AspNetCore.Identity;
using System.Data;

namespace CyberSOC.WebApi.Endpoints
{
    public static class AuthEndpoints
    {
        public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app.MapGroup("/api/auth").WithTags("Auth");

            group.MapPost("/login", async (
                LoginRequest request,
                UserManager<ApplicationUser> userManager,
                IJwtTokenGenerator tokenGenerator) =>
            {
                var user = await userManager.FindByNameAsync(request.UserName);
                if (user is null || !user.IsActive || !await userManager.CheckPasswordAsync(user, request.Password))
                {
                    // Deliberately generic message — never reveal whether the
                    // username or the password was wrong (avoids username enumeration).
                    return Results.Unauthorized();
                }

                var token = await tokenGenerator.GenerateTokenAsync(user);
                var roles = await userManager.GetRolesAsync(user);

                return Results.Ok(new LoginResponse(token, user.UserName!, user.DisplayName, roles));
            })
            .WithName("Login")
            .AllowAnonymous()
            .Produces<LoginResponse>(200)
            .Produces(401);

            // Only Administrators can create new SOC accounts — no public self-registration
            // for a security operations platform.
            group.MapPost("/register", async (
                RegisterUserRequest request,
                UserManager<ApplicationUser> userManager) =>
            {
                if (!Roles.All.Contains(request.Role))
                {
                    return Results.BadRequest(new { error = $"Role must be one of: {string.Join(", ", Roles.All)}" });
                }

                var user = new ApplicationUser
                {
                    UserName = request.UserName,
                    Email = request.Email,
                    DisplayName = request.DisplayName,
                    IsActive = true
                };

                var createResult = await userManager.CreateAsync(user, request.Password);
                if (!createResult.Succeeded)
                {
                    return Results.BadRequest(new { errors = createResult.Errors.Select(e => e.Description) });
                }

                await userManager.AddToRoleAsync(user, request.Role);

                return Results.Created($"/api/auth/users/{user.Id}", new { userId = user.Id });
            })
            .WithName("RegisterUser")
            .RequireAuthorization(policy => policy.RequireRole(Roles.Administrator))
            .Produces(201)
            .Produces(400)
            .Produces(401)
            .Produces(403);

            return app;
        }
    }

    public sealed record LoginRequest(string UserName, string Password);
    public sealed record LoginResponse(string Token, string UserName, string DisplayName, IList<string> Roles);
    public sealed record RegisterUserRequest(string UserName, string Email, string Password, string DisplayName, string Role);


}
