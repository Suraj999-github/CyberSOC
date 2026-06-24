using CyberSOC.Application.Common.Interfaces;
using CyberSOC.Domain.Entities;

namespace CyberSOC.Persistence.Repositories
{
    public sealed class AlertRepository : IAlertRepository
    {
        private readonly CyberSocDbContext _dbContext;

        public AlertRepository(CyberSocDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task AddAsync(Alert alert, CancellationToken cancellationToken)
        {
            await _dbContext.Alerts.AddAsync(alert, cancellationToken);
        }

        public Task SaveChangesAsync(CancellationToken cancellationToken)
            => _dbContext.SaveChangesAsync(cancellationToken);
    }
}
