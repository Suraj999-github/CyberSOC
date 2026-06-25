using CyberSOC.Domain.Entities;
using CyberSOC.Domain.ThreatIntel;
using CyberSOC.Persistence.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CyberSOC.Persistence
{
    public sealed class CyberSocDbContext : IdentityDbContext<ApplicationUser>
    {
        public CyberSocDbContext(DbContextOptions<CyberSocDbContext> options) : base(options) { }

        public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
        public DbSet<Alert> Alerts => Set<Alert>();
        public DbSet<IndicatorOfCompromise> Indicators => Set<IndicatorOfCompromise>();
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(CyberSocDbContext).Assembly);
            base.OnModelCreating(modelBuilder);
        }
    }
}
