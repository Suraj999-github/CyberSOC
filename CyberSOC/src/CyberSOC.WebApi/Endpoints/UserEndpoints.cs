using CyberSOC.Domain.IdentityAccess;
using CyberSOC.Persistence.Identity;
using Microsoft.AspNetCore.Identity;

namespace CyberSOC.WebApi.Endpoints
{
    /// <summary>
    /// User management endpoints — list, get, update profile, activate/deactivate, and role assignment.
    /// All routes require the Administrator role unless noted otherwise.
    /// </summary>
    public static class UserEndpoints
    {
        public static IEndpointRouteBuilder MapUserEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app.MapGroup("/api/users")
                           .WithTags("Users")
                           .RequireAuthorization(p => p.RequireRole(Roles.Administrator));

            // ------------------------------------------------------------------ //
            // GET /api/users
            // ------------------------------------------------------------------ //
            group.MapGet("/", async (UserManager<ApplicationUser> userManager) =>
            {
                var users = userManager.Users
                    .Select(u => new UserSummaryResponse(
                        u.Id,
                        u.UserName!,
                        u.Email!,
                        u.DisplayName,
                        u.IsActive))
                    .ToList();

                return Results.Ok(users);
            })
            .WithName("GetAllUsers")
            .Produces<IList<UserSummaryResponse>>(200)
            .Produces(401)
            .Produces(403);

            // ------------------------------------------------------------------ //
            // GET /api/users/{id}
            // ------------------------------------------------------------------ //
            group.MapGet("/{id}", async (
                string id,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                var roles = await userManager.GetRolesAsync(user);
                return Results.Ok(new UserDetailResponse(
                    user.Id,
                    user.UserName!,
                    user.Email!,
                    user.DisplayName,
                    user.IsActive,
                    roles));
            })
            .WithName("GetUserById")
            .Produces<UserDetailResponse>(200)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            // ------------------------------------------------------------------ //
            // PUT /api/users/{id}
            // Update display name and / or email. Password changes use a dedicated
            // endpoint so audit logging and token invalidation can be handled there.
            // ------------------------------------------------------------------ //
            group.MapPut("/{id}", async (
                string id,
                UpdateUserRequest request,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

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
            .WithName("UpdateUser")
            .Produces(204)
            .Produces(400)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            // ------------------------------------------------------------------ //
            // DELETE /api/users/{id}
            // Hard-delete — consider soft-delete (deactivate) for SOC audit trails.
            // ------------------------------------------------------------------ //
            group.MapDelete("/{id}", async (
                string id,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                var deleteResult = await userManager.DeleteAsync(user);
                if (!deleteResult.Succeeded)
                    return Results.BadRequest(new { errors = deleteResult.Errors.Select(e => e.Description) });

                return Results.NoContent();
            })
            .WithName("DeleteUser")
            .Produces(204)
            .Produces(400)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            // ------------------------------------------------------------------ //
            // POST /api/users/{id}/activate
            // POST /api/users/{id}/deactivate
            // Preferred over hard-delete in security contexts — preserves audit data.
            // ------------------------------------------------------------------ //
            group.MapPost("/{id}/activate", async (
                string id,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                user.IsActive = true;
                var result = await userManager.UpdateAsync(user);
                if (!result.Succeeded)
                    return Results.BadRequest(new { errors = result.Errors.Select(e => e.Description) });

                return Results.NoContent();
            })
            .WithName("ActivateUser")
            .Produces(204)
            .Produces(400)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            group.MapPost("/{id}/deactivate", async (
                string id,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                user.IsActive = false;
                var result = await userManager.UpdateAsync(user);
                if (!result.Succeeded)
                    return Results.BadRequest(new { errors = result.Errors.Select(e => e.Description) });

                return Results.NoContent();
            })
            .WithName("DeactivateUser")
            .Produces(204)
            .Produces(400)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            // ------------------------------------------------------------------ //
            // POST /api/users/{id}/roles         — add a role
            // DELETE /api/users/{id}/roles/{role} — remove a role
            // ------------------------------------------------------------------ //
            group.MapPost("/{id}/roles", async (
                string id,
                AssignRoleRequest request,
                UserManager<ApplicationUser> userManager) =>
            {
                if (!Roles.All.Contains(request.Role))
                    return Results.BadRequest(new { error = $"Role must be one of: {string.Join(", ", Roles.All)}" });

                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                if (await userManager.IsInRoleAsync(user, request.Role))
                    return Results.Conflict(new { error = $"User already has role '{request.Role}'." });

                var result = await userManager.AddToRoleAsync(user, request.Role);
                if (!result.Succeeded)
                    return Results.BadRequest(new { errors = result.Errors.Select(e => e.Description) });

                return Results.NoContent();
            })
            .WithName("AddUserRole")
            .Produces(204)
            .Produces(400)
            .Produces(401)
            .Produces(403)
            .Produces(404)
            .Produces(409);

            group.MapDelete("/{id}/roles/{role}", async (
                string id,
                string role,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                if (!await userManager.IsInRoleAsync(user, role))
                    return Results.NotFound(new { error = $"User does not have role '{role}'." });

                var result = await userManager.RemoveFromRoleAsync(user, role);
                if (!result.Succeeded)
                    return Results.BadRequest(new { errors = result.Errors.Select(e => e.Description) });

                return Results.NoContent();
            })
            .WithName("RemoveUserRole")
            .Produces(204)
            .Produces(400)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            return app;
        }
    }

    // ── Request / Response records ─────────────────────────────────────────── //

    public sealed record UserSummaryResponse(
        string Id,
        string UserName,
        string Email,
        string DisplayName,
        bool IsActive);

    public sealed record UserDetailResponse(
        string Id,
        string UserName,
        string Email,
        string DisplayName,
        bool IsActive,
        IList<string> Roles);

    public sealed record UpdateUserRequest(string? DisplayName, string? Email);

    public sealed record AssignRoleRequest(string Role);
}