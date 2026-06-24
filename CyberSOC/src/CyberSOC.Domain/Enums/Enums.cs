namespace CyberSOC.Domain.Enums
{
    internal class Enums
    {
    }
    public enum Severity
    {
        Informational = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    public enum SecurityEventType
    {
        ApiRequest = 0,
        LoginAttempt = 1,
        FirewallLog = 2,
        SystemAudit = 3
    }

    public enum EventOutcome
    {
        Success = 0,
        Failure = 1,
        Unknown = 2
    }

    public enum AlertType
    {
        ApiAttack = 0,
        ThreatIntelMatch = 1,
        SiemCorrelation = 2,
        LoginAnomaly = 3
    }

    public enum AlertStatus
    {
        New = 0,
        Acknowledged = 1,
        Escalated = 2,
        FalsePositive = 3,
        Resolved = 4
    }

}
