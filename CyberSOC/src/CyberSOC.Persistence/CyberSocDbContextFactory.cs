using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore;
namespace CyberSOC.Persistence
{
    public class CyberSocDbContextFactory
      : IDesignTimeDbContextFactory<CyberSocDbContext>
    {
        public CyberSocDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder =
                new DbContextOptionsBuilder<CyberSocDbContext>();

            optionsBuilder.UseSqlServer(
                "Data Source=STPL-SURAJG;Initial Catalog=cybersoc;Integrated Security=True;Encrypt=True;Trust Server Certificate=True");

            return new CyberSocDbContext(optionsBuilder.Options);
        }
    }
}
