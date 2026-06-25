using Microsoft.AspNetCore.Identity;


namespace CyberSOC.Persistence.Identity
{
    /// <summary>
    /// Identity lives in Persistence (not Domain) because ASP.NET Core Identity's
    /// IdentityUser is itself a framework/infrastructure concern — the same reason
    /// SecurityEvent/Alert never reference it. If a richer "SOC analyst profile"
    /// domain concept emerges later (shift schedule, specialization, etc.), that
    /// would become its own Domain entity linked by UserId string, not a subclass
    /// of this one.
    /// </summary>
    public sealed class ApplicationUser : IdentityUser
    {
        public string DisplayName { get; set; } = string.Empty;
        public bool IsActive { get; set; } = true;
        public bool MustResetPassword { get; set; }
    }

}
