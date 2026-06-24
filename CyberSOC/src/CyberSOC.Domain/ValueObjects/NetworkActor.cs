namespace CyberSOC.Domain.ValueObjects
{
    /// <summary>
    /// Value object describing the actor behind a SecurityEvent. Immutable by design —
    /// two NetworkActors with identical field values are interchangeable, which matters
    /// for grouping/aggregation in the Detection and Login-Anomaly engines.
    /// </summary>
    public sealed record NetworkActor
    {
        public string IpAddress { get; }
        public string? UserId { get; }
        public string? CountryCode { get; }
        public string? DeviceFingerprint { get; }
        public string? UserAgent { get; }

        public NetworkActor(
            string ipAddress,
            string? userId = null,
            string? countryCode = null,
            string? deviceFingerprint = null,
            string? userAgent = null)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                throw new ArgumentException("IpAddress is required.", nameof(ipAddress));

            IpAddress = ipAddress;
            UserId = userId;
            CountryCode = countryCode;
            DeviceFingerprint = deviceFingerprint;
            UserAgent = userAgent;
        }

        public static NetworkActor Anonymous(string ipAddress) => new(ipAddress);
    }

}
