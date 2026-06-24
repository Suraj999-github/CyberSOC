using CyberSOC.Domain.Common;
using CyberSOC.Domain.Enums;
using CyberSOC.Domain.ValueObjects;

namespace CyberSOC.Domain.Entities
{
    /// <summary>
    /// The canonical, normalized representation of any ingested signal — an API call,
    /// a login attempt, a firewall log line, etc. Every detector (API attack rules,
    /// SIEM correlation rules, anomaly scoring) reads from this single shape, which
    /// is what makes the "SIEM simulation" possible without a real SIEM product.
    /// </summary>
    public sealed class SecurityEvent : Entity<Guid>
    {
        public SecurityEventType EventType { get; private set; }
        public DateTimeOffset Timestamp { get; private set; }
        public string Source { get; private set; } = string.Empty;          // e.g. "api-gateway", "auth-service"
        public NetworkActor Actor { get; private set; } = default!;          // who/what triggered it
        public string TargetResource { get; private set; } = string.Empty;   // endpoint path, asset name, etc.
        public EventOutcome Outcome { get; private set; }
        public string RawPayload { get; private set; } = string.Empty;       // original log line/JSON, for forensics
        public IReadOnlyDictionary<string, string> Attributes { get; private set; }
            = new Dictionary<string, string>();

        private SecurityEvent() { } // EF Core

        public static SecurityEvent Create(
            SecurityEventType eventType,
            string source,
            NetworkActor actor,
            string targetResource,
            EventOutcome outcome,
            string rawPayload,
            IDictionary<string, string>? attributes = null,
            DateTimeOffset? timestamp = null)
        {
            if (string.IsNullOrWhiteSpace(source))
                throw new ArgumentException("Source is required.", nameof(source));
            if (string.IsNullOrWhiteSpace(targetResource))
                throw new ArgumentException("TargetResource is required.", nameof(targetResource));

            return new SecurityEvent
            {
                Id = Guid.NewGuid(),
                EventType = eventType,
                Timestamp = timestamp ?? DateTimeOffset.UtcNow,
                Source = source,
                Actor = actor,
                TargetResource = targetResource,
                Outcome = outcome,
                RawPayload = rawPayload,
                Attributes = attributes is null
                    ? new Dictionary<string, string>()
                    : new Dictionary<string, string>(attributes)
            };
        }
    }

}
