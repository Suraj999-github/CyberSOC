using CyberSOC.Application.Common.Interfaces;
using CyberSOC.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace CyberSOC.Persistence.Repositories
{
    public sealed class SecurityEventRepository : ISecurityEventRepository
    {
        private readonly CyberSocDbContext _dbContext;

        public SecurityEventRepository(CyberSocDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task AddAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
        {
            await _dbContext.SecurityEvents.AddAsync(securityEvent, cancellationToken);
        }

        public async Task<IReadOnlyCollection<SecurityEvent>> GetRecentByIpAsync(
            string ipAddress, TimeSpan lookback, CancellationToken cancellationToken)
        {
            var since = DateTimeOffset.UtcNow - lookback;

            return await _dbContext.SecurityEvents
                .Where(e => e.Actor.IpAddress == ipAddress && e.Timestamp >= since)
                .OrderBy(e => e.Timestamp)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        public Task SaveChangesAsync(CancellationToken cancellationToken)
            => _dbContext.SaveChangesAsync(cancellationToken);
    }
}
