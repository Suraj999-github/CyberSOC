using CyberSOC.Domain.ThreatIntel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
