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
        // ── ORIGINAL FOUR (keep as-is, values preserved) ──────────────────────
        ApiRequest = 0,   // inbound/outbound REST/gRPC calls; rate abuse, stuffing
        LoginAttempt = 1,   // auth flows; brute-force, MFA bypass, ATO
        FirewallLog = 2,   // perimeter allow/deny; port scans, C2, lateral movement
        SystemAudit = 3,   // privilege changes, config mutation, log tampering

        // ── SESSION & IDENTITY ─────────────────────────────────────────────────
        SessionEvent = 4,   // token issue/revoke/hijack, session fixation, OAuth abuse
        PrivilegeChange = 5,   // sudo, role escalation, group membership mutation
        AccountChange = 6,   // create/disable/delete/unlock accounts; shadow account creation
        MfaEvent = 7,   // MFA enroll/bypass/prompt-bomb; OTP interception

        // ── ENDPOINT & PROCESS ─────────────────────────────────────────────────
        ProcessCreation = 8,   // new process spawn; maps to MITRE T1059 (script execution)
        FileSystemEvent = 9,   // read/write/delete/rename; ransomware staging, exfil prep
        RegistryEvent = 10,  // Windows registry R/W/D; persistence, boot hijack (T1547)
        DriverLoad = 11,  // kernel driver/module load; rootkit installation (T1215)
        ServiceEvent = 12,  // service install/start/stop; malicious service persistence

        // ── NETWORK & PROTOCOL ────────────────────────────────────────────────
        DnsQuery = 13,  // DNS lookup telemetry; DGA, DNS tunnelling, C2 beaconing
        NetworkConnection = 14,  // raw TCP/UDP flows beyond firewall; lateral movement, exfil
        ProxyLog = 15,  // web proxy / CASB; shadow IT, malware download, data staging
        VpnEvent = 16,  // VPN connect/disconnect/geo-anomaly; impossible travel
        WirelessEvent = 17,  // 802.11 auth, rogue AP, deauth flood; relevant to branches/ATMs

        // ── EMAIL & COLLABORATION ─────────────────────────────────────────────
        EmailEvent = 18,  // send/receive/forward/delete; phishing, BEC, data leak via mail
        CollaborationEvent = 19,  // Teams/Slack/SharePoint actions; insider data sharing, exfil

        // ── CLOUD & IDENTITY PROVIDER ─────────────────────────────────────────
        CloudApiCall = 20,  // AWS CloudTrail, Azure Activity, GCP Audit; IAM abuse, bucket exposure
        CloudConfigChange = 21,  // security group, policy, role change in IaaS/PaaS; misconfiguration
        SaasAuditEvent = 22,  // O365/Salesforce/Workday audit; admin-console abuse, mass download
        IdentityProviderEvent = 23, // IdP (Entra/Okta/Ping) federation change, token policy, SSO bypass

        // ── DATA & STORAGE ────────────────────────────────────────────────────
        DataAccessEvent = 24,  // DB queries, file reads, PII access; bulk exfil, insider threat
        TransactionEvent = 25,  // monetary/payment flows; velocity, structuring, mule detection
        DatabaseEvent = 26,  // DDL/DML anomalies, schema change, stored-proc abuse, SQLi trace
        StorageEvent = 27,  // blob/S3/NAS access, share mount/unmount; staging for exfil

        // ── VULNERABILITY & THREAT INTEL ──────────────────────────────────────
        ThreatIntelHit = 28,  // IOC match (IP/domain/hash); known-bad infrastructure contact
        VulnerabilityEvent = 29,  // scanner findings, CVE hits, patch-status changes; risk scoring
        IntrusionDetection = 30,  // IDS/IPS signature hits; exploit attempts, payload delivery

        // ── PHYSICAL & OT/IOT (banking-specific) ──────────────────────────────
        PhysicalAccessEvent = 31, // badge swipe, door/safe/vault open; tailgating, forced entry
        AtmKioskEvent = 32,  // ATM/kiosk integrity; jackpotting, card-skimmer detection, XFS events
        OtIcsEvent = 33,  // OT/ICS/SCADA telemetry; relevant for data-centre and vault infra

        // ── CERTIFICATE & PKI ─────────────────────────────────────────────────
        CertificateEvent = 34,  // cert issue/revoke/expire/mismatch; MitM, expired TLS, rogue CA

        // ── SUPPLY CHAIN & THIRD PARTY ────────────────────────────────────────
        ThirdPartyApiEvent = 35,  // partner/vendor API calls; supply-chain compromise, BaaS risk
        SoftwareInventoryEvent = 36, // install/update/remove; unauthorised software, shadow IT

        // ── COMPLIANCE & DLP ──────────────────────────────────────────────────
        DlpEvent = 37,  // data-loss-prevention policy hit; PII/PCI/SWIFT data leaving boundary
        ComplianceEvent = 38,  // regulatory rule evaluation; AML/KYC/PCI-DSS/SOX control gap

        // ── CONTAINER & CI/CD ─────────────────────────────────────────────────
        ContainerEvent = 39,  // pod/container start-stop, image pull, privilege escalation in K8s
        CiCdPipelineEvent = 40,  // build/deploy pipeline actions; secrets exposure, supply-chain inject

        // ── BEHAVIOURAL / UEBA ────────────────────────────────────────────────
        UserBehaviorAnomaly = 41, // UEBA-derived: impossible travel, off-hours, peer-group deviation
        EntityBehaviorAnomaly = 42, // service/machine-identity anomaly; NHI abuse, lateral movement
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
        LoginAnomaly = 3,
        TransactionAnomaly = 4,
        DataExfiltration = 5,
        FirewallAnomaly = 6,
        AuditTampering = 7,
        SessionHijack = 8,
        PrivilegeEscalation = 9,
        AccountManipulation = 10,
        MfaAnomaly = 11,
        MaliciousProcess = 12,
        RansomwareIndicator = 13,
        PersistenceMechanism = 14,
        DnsAnomaly = 15,
        LateralMovement = 16,
        PhishingOrBec = 17,
        CloudMisconfiguration = 18,
        InsiderThreat = 19,
        PhysicalSecurityBreach = 20,
        AtmTampering = 21,
        CertificateAnomaly = 22,
        SupplyChainRisk = 23,
        DlpViolation = 24,
        ComplianceViolation = 25,
        ContainerEscape = 26,
        CiCdPoisoning = 27,
        UebaAnomaly = 28,
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
