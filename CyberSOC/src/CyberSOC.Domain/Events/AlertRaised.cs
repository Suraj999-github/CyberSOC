using CyberSOC.Domain.Common;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Events
{
    /// <summary>
    /// Raised whenever a new Alert is created. Handlers in the Application layer
    /// react to this to: push a SignalR notification to the live dashboard, and
    /// optionally enqueue the alert for IOC enrichment / incident auto-creation.
    /// </summary>
    public sealed record AlertRaised(Guid AlertId, AlertType AlertType, Severity Severity) : IDomainEvent
    {
        public DateTimeOffset OccurredOn { get; } = DateTimeOffset.UtcNow;
    }

}
