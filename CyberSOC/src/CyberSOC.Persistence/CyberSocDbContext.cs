using CyberSOC.Domain.Entities;
using Microsoft.EntityFrameworkCore;


namespace CyberSOC.Persistence
{
    public sealed class CyberSocDbContext : DbContext
    {
        public CyberSocDbContext(DbContextOptions<CyberSocDbContext> options) : base(options) { }

        public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
        public DbSet<Alert> Alerts => Set<Alert>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(CyberSocDbContext).Assembly);
            base.OnModelCreating(modelBuilder);
        }
    }
}
