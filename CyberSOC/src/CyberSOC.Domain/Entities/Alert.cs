using CyberSOC.Domain.Common;
using CyberSOC.Domain.Enums;
using CyberSOC.Domain.Events;

namespace CyberSOC.Domain.Entities
{
    /// <summary>
    /// Raised by a detection rule when it matches. Carries enough evidence (source
    /// SecurityEvent IDs + a human-readable reason) for an analyst — or the AI
    /// Investigation module — to understand why it fired without re-querying raw logs.
    /// </summary>
    public sealed class Alert : Entity<Guid>
    {
        public AlertType AlertType { get; private set; }
        public Severity Severity { get; private set; }
        public AlertStatus Status { get; private set; }
        public string Title { get; private set; } = string.Empty;
        public string Reason { get; private set; } = string.Empty;
        public DateTimeOffset RaisedAt { get; private set; }
        public string SourceIp { get; private set; } = string.Empty;
        public string? UserId { get; private set; }

        private readonly List<Guid> _evidenceEventIds = new();
        public IReadOnlyCollection<Guid> EvidenceEventIds => _evidenceEventIds.AsReadOnly();

        private Alert() { } // EF Core

        public static Alert Raise(
            AlertType alertType,
            Severity severity,
            string title,
            string reason,
            string sourceIp,
            IEnumerable<Guid> evidenceEventIds,
            string? userId = null)
        {
            if (string.IsNullOrWhiteSpace(title))
                throw new ArgumentException("Title is required.", nameof(title));

            var alert = new Alert
            {
                Id = Guid.NewGuid(),
                AlertType = alertType,
                Severity = severity,
                Status = AlertStatus.New,
                Title = title,
                Reason = reason,
                RaisedAt = DateTimeOffset.UtcNow,
                SourceIp = sourceIp,
                UserId = userId
            };

            alert._evidenceEventIds.AddRange(evidenceEventIds);
            alert.RaiseDomainEvent(new AlertRaised(alert.Id, alertType, severity));

            return alert;
        }

        public void Acknowledge()
        {
            if (Status != AlertStatus.New)
                throw new InvalidOperationException($"Cannot acknowledge an alert in status {Status}.");
            Status = AlertStatus.Acknowledged;
        }

        public void MarkFalsePositive(string analystNote)
        {
            Status = AlertStatus.FalsePositive;
            Reason += $" | Analyst note: {analystNote}";
        }

        public void Escalate() => Status = AlertStatus.Escalated;
        public void Resolve() => Status = AlertStatus.Resolved;

        /// <summary>Appends threat-intel reputation context once a match is found (UC-02).
        /// Idempotent-ish by design: called once per alert right after creation, before save.</summary>
        public void EnrichWithThreatIntelContext(string context)
        {
            if (string.IsNullOrWhiteSpace(context)) return;
            Reason += $" | Threat intel: {context}";
            if (Severity < Severity.High) Severity = Severity.High; // a known-bad IOC match escalates severity
        }
    }

}
