using CyberSOC.Domain.Common;

namespace CyberSOC.Domain.ThreatIntel
{
    public enum IndicatorType
    {
        IpAddress = 0,
        Domain = 1,
        FileHash = 2,
        Url = 3
    }

    /// <summary>
    /// A single threat indicator (IOC) pulled from a free feed (AbuseIPDB, AlienVault
    /// OTX, abuse.ch) or entered manually by a Security Engineer. Alerts are matched
    /// against this table to enrich them with reputation context (UC-02).
    /// </summary>
    public sealed class IndicatorOfCompromise : Entity<Guid>
    {
        public IndicatorType Type { get; private set; }
        public string Value { get; private set; } = string.Empty;   // the IP/domain/hash/url itself
        public string Source { get; private set; } = string.Empty;  // e.g. "AbuseIPDB", "AlienVault OTX", "manual"
        public int Confidence { get; private set; }                  // 0-100, as reported by the source
        public DateTimeOffset FirstSeen { get; private set; }
        public DateTimeOffset LastSeen { get; private set; }
        public string? Tags { get; private set; }                    // comma-separated, e.g. "botnet,scanner"

        private IndicatorOfCompromise() { } // EF Core

        public static IndicatorOfCompromise Create(
            IndicatorType type, string value, string source, int confidence, string? tags = null)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Value is required.", nameof(value));
            if (confidence is < 0 or > 100)
                throw new ArgumentOutOfRangeException(nameof(confidence), "Confidence must be 0-100.");

            var now = DateTimeOffset.UtcNow;
            return new IndicatorOfCompromise
            {
                Id = Guid.NewGuid(),
                Type = type,
                Value = NormalizeValue(type, value),
                Source = source,
                Confidence = confidence,
                FirstSeen = now,
                LastSeen = now,
                Tags = tags
            };
        }

        /// <summary>Called when the same IOC reappears in a fresh feed sync — keeps it current
        /// rather than creating duplicate rows.</summary>
        public void Refresh(int confidence, string? tags)
        {
            Confidence = confidence;
            Tags = tags ?? Tags;
            LastSeen = DateTimeOffset.UtcNow;
        }

        public static string NormalizeValue(IndicatorType type, string value) => type switch
        {
            IndicatorType.IpAddress => value.Trim(),
            IndicatorType.Domain or IndicatorType.Url => value.Trim().ToLowerInvariant(),
            IndicatorType.FileHash => value.Trim().ToLowerInvariant(),
            _ => value.Trim()
        };
    }


}
