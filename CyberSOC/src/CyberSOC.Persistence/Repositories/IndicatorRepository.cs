using CyberSOC.Application.Common.Interfaces;
using CyberSOC.Domain.ThreatIntel;
using Microsoft.EntityFrameworkCore;

namespace CyberSOC.Persistence.Repositories
{
    public sealed class IndicatorRepository : IIndicatorRepository
    {
        private readonly CyberSocDbContext _dbContext;

        public IndicatorRepository(CyberSocDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public Task<IndicatorOfCompromise?> FindByValueAsync(
            IndicatorType type, string normalizedValue, CancellationToken cancellationToken)
        {
            return _dbContext.Indicators
                .FirstOrDefaultAsync(i => i.Type == type && i.Value == normalizedValue, cancellationToken);
        }

        public async Task AddAsync(IndicatorOfCompromise indicator, CancellationToken cancellationToken)
        {
            await _dbContext.Indicators.AddAsync(indicator, cancellationToken);
        }

        public Task SaveChangesAsync(CancellationToken cancellationToken)
            => _dbContext.SaveChangesAsync(cancellationToken);
    }
}
