using CyberSOC.Persistence.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
namespace CyberSOC.WebApi.Identity
{
    public interface IJwtTokenGenerator
    {
        Task<string> GenerateTokenAsync(ApplicationUser user);
    }

    /// <summary>
    /// Free, built into the BCL/ASP.NET Core (System.IdentityModel.Tokens.Jwt is
    /// MIT-licensed, maintained by Microsoft) — no third-party identity-as-a-
    /// service dependency. Tokens carry the user's roles as claims so
    /// [Authorize(Roles = "...")] works on both REST endpoints and the SignalR hub.
    /// </summary>
    public sealed class JwtTokenGenerator : IJwtTokenGenerator
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;

        public JwtTokenGenerator(UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        public async Task<string> GenerateTokenAsync(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name, user.UserName ?? user.Email ?? user.Id),
            new(ClaimTypes.Email, user.Email ?? string.Empty),
            new("displayName", user.DisplayName)
        };
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var jwtSection = _configuration.GetSection("Jwt");
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["SigningKey"]!));
            var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
            var expiryMinutes = jwtSection.GetValue<int?>("ExpiryMinutes") ?? 60;

            var token = new JwtSecurityToken(
                issuer: jwtSection["Issuer"],
                audience: jwtSection["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiryMinutes),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

}
