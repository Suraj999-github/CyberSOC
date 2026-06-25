using CyberSOC.Domain.IdentityAccess;
using CyberSOC.Persistence.Identity;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace CyberSOC.WebApi.Endpoints
{
    /// <summary>
    /// Password lifecycle endpoints.
    ///
    ///  • POST /api/password/change          — authenticated user changes their own password
    ///  • POST /api/users/{id}/password/reset — Administrator resets another user's password
    ///  • POST /api/users/{id}/password/force-reset — flag account so user must reset on next login
    /// </summary>
    public static class PasswordEndpoints
    {
        public static IEndpointRouteBuilder MapPasswordEndpoints(this IEndpointRouteBuilder app)
        {
            // ------------------------------------------------------------------ //
            // POST /api/password/change
            // Any authenticated user can change their own password.
            // Requires the current password — prevents session-hijack escalation.
            // ------------------------------------------------------------------ //
            app.MapPost("/api/password/change", async (
                ChangePasswordRequest request,
                ClaimsPrincipal principal,
                UserManager<ApplicationUser> userManager) =>
            {
                var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
                if (userId is null)
                    return Results.Unauthorized();

                var user = await userManager.FindByIdAsync(userId);
                if (user is null)
                    return Results.Unauthorized();

                var result = await userManager.ChangePasswordAsync(
                    user,
                    request.CurrentPassword,
                    request.NewPassword);

                if (!result.Succeeded)
                    return Results.BadRequest(new { errors = result.Errors.Select(e => e.Description) });

                // Security stamp is automatically updated by ChangePasswordAsync,
                // which invalidates all existing JWT tokens for this user (if your
                // JwtTokenGenerator validates the stamp in the token claims).
                return Results.NoContent();
            })
            .WithTags("Password")
            .WithName("ChangePassword")
            .RequireAuthorization()
            .Produces(204)
            .Produces(400)
            .Produces(401);

            // ------------------------------------------------------------------ //
            // POST /api/users/{id}/password/reset
            // Administrator sets a new password directly — no current password needed.
            // Use when a user is locked out or account is being handed over.
            // ------------------------------------------------------------------ //
            app.MapPost("/api/users/{id}/password/reset", async (
                string id,
                AdminResetPasswordRequest request,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                // Generate a reset token then immediately consume it — this is the
                // correct Identity pattern for admin-initiated password replacement.
                var token = await userManager.GeneratePasswordResetTokenAsync(user);
                var result = await userManager.ResetPasswordAsync(user, token, request.NewPassword);

                if (!result.Succeeded)
                    return Results.BadRequest(new { errors = result.Errors.Select(e => e.Description) });

                return Results.NoContent();
            })
            .WithTags("Password")
            .WithName("AdminResetPassword")
            .RequireAuthorization(p => p.RequireRole(Roles.Administrator))
            .Produces(204)
            .Produces(400)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            // ------------------------------------------------------------------ //
            // POST /api/users/{id}/password/force-reset
            // Stamps the account so the next login is blocked until the user
            // resets their password (via an out-of-band flow, e.g. email token).
            // Useful after a suspected credential leak.
            // ------------------------------------------------------------------ //
            app.MapPost("/api/users/{id}/password/force-reset", async (
                string id,
                UserManager<ApplicationUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(id);
                if (user is null)
                    return Results.NotFound(new { error = $"User '{id}' not found." });

                // Updating the security stamp invalidates all current JWT tokens
                // (assuming your token generator embeds / validates the stamp).
                await userManager.UpdateSecurityStampAsync(user);

                // Store a flag so the login endpoint can enforce the reset requirement.
                // Requires a custom boolean property on ApplicationUser, e.g. MustResetPassword.
                user.MustResetPassword = true;
                await userManager.UpdateAsync(user);

                return Results.NoContent();
            })
            .WithTags("Password")
            .WithName("ForcePasswordReset")
            .RequireAuthorization(p => p.RequireRole(Roles.Administrator))
            .Produces(204)
            .Produces(401)
            .Produces(403)
            .Produces(404);

            return app;
        }
    }

    // ── Request records ────────────────────────────────────────────────────── //

    public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
    public sealed record AdminResetPasswordRequest(string NewPassword);
}