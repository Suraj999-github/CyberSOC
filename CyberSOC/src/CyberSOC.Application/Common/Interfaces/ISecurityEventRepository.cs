using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberSOC.Application.Common.Interfaces
{
    /// <summary>
    /// Defined here (Application) and implemented in Infrastructure with EF Core —
    /// the Application layer never knows about Postgres, TimescaleDB, or EF Core types.
    /// </summary>
    public interface ISecurityEventRepository
    {
        Task AddAsync(SecurityEvent securityEvent, CancellationToken cancellationToken);

        /// <summary>Fetch recent events for a given actor IP within a lookback window — used by detection rules.</summary>
        Task<IReadOnlyCollection<SecurityEvent>> GetRecentByIpAsync(
            string ipAddress, TimeSpan lookback, CancellationToken cancellationToken);

        Task SaveChangesAsync(CancellationToken cancellationToken);
    }

    public interface IAlertRepository
    {
        Task AddAsync(Alert alert, CancellationToken cancellationToken);
        Task SaveChangesAsync(CancellationToken cancellationToken);
    }

}
