using CyberSOC.Domain.Detection;
using CyberSOC.Domain.Detection.Rules;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CyberSOC.Infrastructure
{
    public static class InfrastructureServiceCollectionExtensions
    {
        /// <summary>
        /// Registers every active detection rule as IDetectionRule. This is the
        /// single place that decides which rules run — adding a new rule means
        /// adding one line here, nothing in the Application handler changes.
        /// All thresholds and windows are read from configuration so they can be
        /// tuned per environment without a code change.
        /// </summary>
        // CyberSOC.Infrastructure — full AddCyberSocInfrastructure
        public static IServiceCollection AddCyberSocInfrastructure(
            this IServiceCollection services,
            IConfiguration configuration)
        {
            T Cfg<T>(string key, T fallback) =>
                configuration.GetValue<T?>(key) is T v ? v : fallback;

            // ── Original four ─────────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new ApiRateThresholdRule(
                Cfg("DetectionRules:ApiRateThreshold:FailureThreshold", 10),
                TimeSpan.FromSeconds(Cfg("DetectionRules:ApiRateThreshold:WindowSeconds", 60))));

            services.AddSingleton<IDetectionRule>(_ => new LoginBruteForceRule(
                Cfg("DetectionRules:LoginBruteForce:FailureThreshold", 5),
                TimeSpan.FromSeconds(Cfg("DetectionRules:LoginBruteForce:WindowSeconds", 300))));

            services.AddSingleton<IDetectionRule>(_ => new FirewallPortScanRule(
                Cfg("DetectionRules:FirewallPortScan:DenyThreshold", 15),
                TimeSpan.FromSeconds(Cfg("DetectionRules:FirewallPortScan:WindowSeconds", 120))));

            services.AddSingleton<IDetectionRule>(_ => new AuditTamperingRule(
                Cfg("DetectionRules:AuditTampering:ChangeThreshold", 8),
                TimeSpan.FromSeconds(Cfg("DetectionRules:AuditTampering:WindowSeconds", 600))));

            // ── Session & identity ────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new SessionAnomalyRule(
                Cfg("DetectionRules:SessionAnomaly:Threshold", 5),
                TimeSpan.FromSeconds(Cfg("DetectionRules:SessionAnomaly:WindowSeconds", 300))));

            services.AddSingleton<IDetectionRule>(_ => new PrivilegeEscalationRule(
                Cfg("DetectionRules:PrivilegeEscalation:Threshold", 3),
                TimeSpan.FromSeconds(Cfg("DetectionRules:PrivilegeEscalation:WindowSeconds", 600))));

            services.AddSingleton<IDetectionRule>(_ => new AccountManipulationRule(
                Cfg("DetectionRules:AccountManipulation:Threshold", 5),
                TimeSpan.FromSeconds(Cfg("DetectionRules:AccountManipulation:WindowSeconds", 300))));

            services.AddSingleton<IDetectionRule>(_ => new MfaAnomalyRule(
                Cfg("DetectionRules:MfaAnomaly:BypassThreshold", 3),
                TimeSpan.FromSeconds(Cfg("DetectionRules:MfaAnomaly:WindowSeconds", 120))));

            // ── Endpoint & process ────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new MaliciousProcessRule(
                Cfg("DetectionRules:MaliciousProcess:Threshold", 10),
                TimeSpan.FromSeconds(Cfg("DetectionRules:MaliciousProcess:WindowSeconds", 60))));

            services.AddSingleton<IDetectionRule>(_ => new RansomwareIndicatorRule(
                Cfg("DetectionRules:Ransomware:FileWriteThreshold", 100),
                TimeSpan.FromSeconds(Cfg("DetectionRules:Ransomware:WindowSeconds", 30))));

            services.AddSingleton<IDetectionRule>(_ => new PersistenceMechanismRule(
                Cfg("DetectionRules:Persistence:Threshold", 2),
                TimeSpan.FromSeconds(Cfg("DetectionRules:Persistence:WindowSeconds", 300))));

            // ── Network & protocol ────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new DnsAnomalyRule(
                Cfg("DetectionRules:DnsAnomaly:QueryThreshold", 200),
                TimeSpan.FromSeconds(Cfg("DetectionRules:DnsAnomaly:WindowSeconds", 60))));

            services.AddSingleton<IDetectionRule>(_ => new LateralMovementRule(
                Cfg("DetectionRules:LateralMovement:HopThreshold", 5),
                TimeSpan.FromSeconds(Cfg("DetectionRules:LateralMovement:WindowSeconds", 300))));

            services.AddSingleton<IDetectionRule>(_ => new VpnGeoAnomalyRule(
                Cfg("DetectionRules:VpnGeoAnomaly:ImpossibleTravelKmh", 900)));

            // ── Email & collaboration ─────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new EmailPhishingRule(
                Cfg("DetectionRules:EmailPhishing:ForwardThreshold", 3),
                TimeSpan.FromSeconds(Cfg("DetectionRules:EmailPhishing:WindowSeconds", 300))));

            // ── Cloud & IdP ───────────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new CloudMisconfigRule(
                Cfg("DetectionRules:CloudMisconfig:Threshold", 3),
                TimeSpan.FromSeconds(Cfg("DetectionRules:CloudMisconfig:WindowSeconds", 600))));

            services.AddSingleton<IDetectionRule>(_ => new IdentityProviderAnomalyRule(
                Cfg("DetectionRules:IdpAnomaly:Threshold", 5),
                TimeSpan.FromSeconds(Cfg("DetectionRules:IdpAnomaly:WindowSeconds", 300))));

            // ── Data & storage ────────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new DataExfiltrationRule(
                Cfg("DetectionRules:DataExfiltration:ReadThreshold", 50),
                TimeSpan.FromSeconds(Cfg("DetectionRules:DataExfiltration:WindowSeconds", 600))));

            services.AddSingleton<IDetectionRule>(_ => new TransactionVelocityRule(
                Cfg("DetectionRules:TransactionVelocity:TxThreshold", 20),
                TimeSpan.FromSeconds(Cfg("DetectionRules:TransactionVelocity:WindowSeconds", 900))));

            services.AddSingleton<IDetectionRule>(_ => new DatabaseAnomalyRule(
                Cfg("DetectionRules:DatabaseAnomaly:QueryThreshold", 500),
                TimeSpan.FromSeconds(Cfg("DetectionRules:DatabaseAnomaly:WindowSeconds", 60))));

            // ── Physical & OT (banking) ───────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new AtmTamperingRule(
                Cfg("DetectionRules:AtmTampering:EventThreshold", 3),
                TimeSpan.FromSeconds(Cfg("DetectionRules:AtmTampering:WindowSeconds", 60))));

            // ── Certificate & PKI ─────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new CertificateAnomalyRule(
                Cfg("DetectionRules:CertificateAnomaly:Threshold", 2),
                TimeSpan.FromSeconds(Cfg("DetectionRules:CertificateAnomaly:WindowSeconds", 3600))));

            // ── DLP & compliance ──────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new DlpViolationRule(
                Cfg("DetectionRules:DlpViolation:Threshold", 1),
                TimeSpan.FromSeconds(Cfg("DetectionRules:DlpViolation:WindowSeconds", 300))));

            // ── Container & CI/CD ─────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new ContainerEscapeRule(
                Cfg("DetectionRules:ContainerEscape:Threshold", 1),
                TimeSpan.FromSeconds(Cfg("DetectionRules:ContainerEscape:WindowSeconds", 60))));

            services.AddSingleton<IDetectionRule>(_ => new CiCdPoisoningRule(
                Cfg("DetectionRules:CiCdPoisoning:Threshold", 2),
                TimeSpan.FromSeconds(Cfg("DetectionRules:CiCdPoisoning:WindowSeconds", 300))));

            // ── UEBA ──────────────────────────────────────────────────────────────
            services.AddSingleton<IDetectionRule>(_ => new UebaAnomalyRule(
                Cfg("DetectionRules:UebaAnomaly:DeviationSigma", 3.0)));

            return services;
        }
    }
}