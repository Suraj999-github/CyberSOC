using CyberSOC.Domain.IdentityAccess;
using CyberSOC.Persistence.Identity;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace CyberSOC.WebApi.Endpoints
{
    /// <summary>
    /// Lockout management and authenticated-user self-service profile endpoints.
    ///
    /// Lockout (Administrator only):
    ///  • POST   /api/users/{id}/lockout         — manually lock an account until a given UTC time
    ///  • DELETE /api/users/{id}/lockout         — unlock a currently locked account
    ///  • GET    /api/users/{id}/lockout         — inspect current lockout state
    ///
    /// Self-service (any authenticated user):
    ///  • GET  /api/me   — current user's profile + roles
    ///  • PUT  /api/me   — update own display name / email
    /// </summary>
    public static class AccountEndpoints
    {
        public static IEndpointRouteBuilder MapAccountEndpoints(this IEndpointRouteBuilder app)
        {
            // ================================================================== //
            //  LOCKOUT MANAGEMENT
            // ================================================================== //

            var lockoutGroup = app.MapGroup("/api/users/{id}/lockout")
                                  .WithTags("Lockout")
                                  .RequireAuthorization(p => p.RequireRole(Roles.Administrator));

            // GET /api/users/{id}/lockout
            lockoutGroup.MapGet("/", async (
                string id,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                var lockoutEnd = await userManager.GetLockoutEndDateAsync(user);
                var isLockedOut = await userManager.IsLockedOutAsync(user);
                var accessFailedCount = await userManager.GetAccessFailedCountAsync(user);

                return Results.Ok(new LockoutStatusResponse(
                    isLockedOut,
                    lockoutEnd?.UtcDateTime,
                    accessFailedCount));
            })
            .WithName("GetLockoutStatus")
            .Produces<LockoutStatusResponse>(200)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            // POST /api/users/{id}/lockout  — lock account
            lockoutGroup.MapPost("/", async (
                string id,
                LockUserRequest request,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                // LockoutEnabled must be true for SetLockoutEndDateAsync to take effect.
                await userManager.SetLockoutEnabledAsync(user, true);

                var lockoutEnd = request.LockUntilUtc
                    ?? DateTimeOffset.UtcNow.AddYears(100); // "permanent" lock

                var result = await userManager.SetLockoutEndDateAsync(user, lockoutEnd);
                if (!result.Succeeded)
                    return Results.BadRequest(new { errors = result.Errors.Select(e => e.Description) });

                return Results.Ok(new { lockedUntilUtc = lockoutEnd });
            })
            .WithName("LockUser")
            .Produces(200)
            .Produces(400)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            // DELETE /api/users/{id}/lockout  — unlock account
            lockoutGroup.MapDelete("/", async (
                string id,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                // Setting lockout end to the past immediately unlocks the account.
                var result = await userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddSeconds(-1));
                if (!result.Succeeded)
                    return Results.BadRequest(new { errors = result.Errors.Select(e => e.Description) });

                await userManager.ResetAccessFailedCountAsync(user);

                return Results.NoContent();
            })
            .WithName("UnlockUser")
            .Produces(204)
            .Produces(400)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            // ================================================================== //
            //  SELF-SERVICE — current authenticated user
            // ================================================================== //

            var meGroup = app.MapGroup("/api/me")
                             .WithTags("Profile")
                             .RequireAuthorization();

            // GET /api/me
            meGroup.MapGet("/", async (
                ClaimsPrincipal principal,
                UserManager<ApplicationUser> userManager) =>
            {
                var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
                if (userId is null) return Results.Unauthorized();

                var user = await userManager.FindByIdAsync(userId);
                if (user is null) return Results.Unauthorized();

                var roles = await userManager.GetRolesAsync(user);
                return Results.Ok(new UserDetailResponse(
                    user.Id,
                    user.UserName!,
                    user.Email!,
                    user.DisplayName,
                    user.IsActive,
                    roles));
            })
            .WithName("GetMyProfile")
            .Produces<UserDetailResponse>(200)
            .Produces(401);

            // PUT /api/me  — update own display name / email (no role change)
            meGroup.MapPut("/", async (
                UpdateUserRequest request,
                ClaimsPrincipal principal,
                UserManager<ApplicationUser> userManager) =>
            {
                var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
                if (userId is null) return Results.Unauthorized();

                var user = await userManager.FindByIdAsync(userId);
                if (user is null) return Results.Unauthorized();

                user.DisplayName = request.DisplayName ?? user.DisplayName;

                if (!string.IsNullOrWhiteSpace(request.Email))
                {
                    var setEmailResult = await userManager.SetEmailAsync(user, request.Email);
                    if (!setEmailResult.Succeeded)
                        return Results.BadRequest(new { errors = setEmailResult.Errors.Select(e => e.Description) });
                }

                var updateResult = await userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                    return Results.BadRequest(new { errors = updateResult.Errors.Select(e => e.Description) });

                return Results.NoContent();
            })
            .WithName("UpdateMyProfile")
            .Produces(204)
            .Produces(400)
            .Produces(401);

            return app;
        }
    }

    // ── Request / Response records ─────────────────────────────────────────── //

    /// <param name="LockUntilUtc">
    ///   Leave null for an indefinite (100-year) lock.
    ///   Pass a future UTC datetime for a time-bounded suspension.
    /// </param>
    public sealed record LockUserRequest(DateTimeOffset? LockUntilUtc);

    public sealed record LockoutStatusResponse(
        bool IsLockedOut,
        DateTime? LockoutEndsUtc,
        int AccessFailedCount);
}