namespace CyberSOC.Domain.IdentityAccess
{
    /// <summary>
    /// Role names matching the actors defined in the Business Analyst section of
    /// the architecture doc (UC-01..UC-08). Plain string constants rather than an
    /// enum because ASP.NET Core Identity roles are string-based (IdentityRole.Name).
    /// </summary>
    public static class Roles
    {
        public const string Analyst = "Analyst";                 // SOC Analyst L1/L2 — triage, investigate
        public const string SecurityEngineer = "SecurityEngineer"; // configures rules, IOC feeds, ingestion sources
        public const string Manager = "Manager";                 // SOC Manager/CISO — risk heatmaps, trends
        public const string Administrator = "Administrator";     // user/role management, full access
        public const string Auditor = "Auditor";                 // read-only compliance access

        public static readonly string[] All = { Analyst, SecurityEngineer, Manager, Administrator, Auditor };

        /// <summary>Roles allowed to ingest events / manage detection & threat-intel config.</summary>
        public const string IngestionAndConfigPolicy = $"{SecurityEngineer},{Administrator}";

        /// <summary>Roles allowed to read alerts/dashboards (everyone except nobody — Auditor included, read-only).</summary>
        public const string ReadAlertsPolicy = $"{Analyst},{SecurityEngineer},{Manager},{Administrator},{Auditor}";
    }

}
