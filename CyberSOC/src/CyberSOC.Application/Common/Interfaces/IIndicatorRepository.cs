using CyberSOC.Domain.ThreatIntel;

namespace CyberSOC.Application.Common.Interfaces
{
    public interface IIndicatorRepository
    {
        Task<IndicatorOfCompromise?> FindByValueAsync(
            IndicatorType type, string normalizedValue, CancellationToken cancellationToken);

        Task AddAsync(IndicatorOfCompromise indicator, CancellationToken cancellationToken);

        Task SaveChangesAsync(CancellationToken cancellationToken);
    }

}
