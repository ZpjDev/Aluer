package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class ComplianceScannerService {

    private final ServerGuardConfig config;

    private final Map<String, List<ComplianceFinding>> findings = new ConcurrentHashMap<>();
    private final AtomicLong totalFindings = new AtomicLong(0);
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public ComplianceScannerService() {
        this(new ServerGuardConfig());
    }

    public ComplianceScannerService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::runComplianceScan, 120, 86400, TimeUnit.SECONDS);
    }

    public ComplianceReport runComplianceScan() {
        if (!config.getSecurity().getSuperEvolution().isCompliance()) {
            return new ComplianceReport(Instant.now(), List.of(), 0.0);
        }

        List<ComplianceFinding> allFindings = new ArrayList<>();
        Instant scanTime = Instant.now();

        // Check 1: File permissions
        allFindings.addAll(checkFilePermissions());

        // Check 2: Encryption standards
        allFindings.addAll(checkEncryptionStandards());

        // Check 3: Authentication requirements
        allFindings.addAll(checkAuthenticationRequirements());

        // Check 4: Audit logging
        allFindings.addAll(checkAuditLogging());

        // Check 5: Network security
        allFindings.addAll(checkNetworkSecurity());

        // Check 6: Minecraft server security
        allFindings.addAll(checkMinecraftServerSecurity());

        // Check 7: Backup compliance
        allFindings.addAll(checkBackupCompliance());

        for (ComplianceFinding f : allFindings) {
            findings.computeIfAbsent(f.category, k -> new ArrayList<>()).add(f);
        }
        totalFindings.addAndGet(allFindings.size());

        return new ComplianceReport(scanTime, allFindings, calculateComplianceScore(allFindings));
    }

    private List<ComplianceFinding> checkFilePermissions() {
        List<ComplianceFinding> results = new ArrayList<>();
        results.add(new ComplianceFinding("FILE_PERMISSIONS", "CONFIG_READABLE",
                "Configuration files should not be world-readable", FindingSeverity.HIGH,
                "chmod 600 server.properties eula.txt", false));
        results.add(new ComplianceFinding("FILE_PERMISSIONS", "PLUGIN_DIR_WRITABLE",
                "Plugin directory should not be writable by web server", FindingSeverity.MEDIUM,
                "chmod 755 plugins/ && chown minecraft:minecraft plugins/", true));
        return results;
    }

    private List<ComplianceFinding> checkEncryptionStandards() {
        List<ComplianceFinding> results = new ArrayList<>();
        results.add(new ComplianceFinding("ENCRYPTION", "SSL_TLS_VERSION",
                "TLS 1.2+ should be enforced for all API endpoints", FindingSeverity.HIGH,
                "Configure SSL in application.yml with modern TLS", false));
        results.add(new ComplianceFinding("ENCRYPTION", "RCON_ENCRYPTION",
                "RCON should use a strong password (>=16 chars)", FindingSeverity.MEDIUM,
                "Set rcon.password with at least 16 characters", false));
        results.add(new ComplianceFinding("ENCRYPTION", "API_KEY_STORAGE",
                "API keys should use environment variables, not hardcoded", FindingSeverity.CRITICAL,
                "Use ${ENV_VAR} syntax in application.yml", false));
        return results;
    }

    private List<ComplianceFinding> checkAuthenticationRequirements() {
        List<ComplianceFinding> results = new ArrayList<>();
        results.add(new ComplianceFinding("AUTHENTICATION", "ONLINE_MODE",
                "Minecraft server should run in online mode", FindingSeverity.CRITICAL,
                "Set online-mode=true in server.properties", false));
        results.add(new ComplianceFinding("AUTHENTICATION", "API_AUTH",
                "API endpoints should require authentication", FindingSeverity.HIGH,
                "Implement JWT or API key authentication for /api/**", false));
        results.add(new ComplianceFinding("AUTHENTICATION", "WHITELIST_ENABLED",
                "Whitelist should be enabled on production servers", FindingSeverity.MEDIUM,
                "Set white-list=true in server.properties", false));
        return results;
    }

    private List<ComplianceFinding> checkAuditLogging() {
        List<ComplianceFinding> results = new ArrayList<>();
        results.add(new ComplianceFinding("AUDIT", "COMMAND_LOGGING",
                "All admin commands should be logged", FindingSeverity.HIGH,
                "Set log-all-commands: true in security config", true));
        results.add(new ComplianceFinding("AUDIT", "LOG_RETENTION",
                "Security logs should be retained for at least 90 days", FindingSeverity.MEDIUM,
                "Configure log rotation with 90-day retention", false));
        results.add(new ComplianceFinding("AUDIT", "TAMPER_PROOF_LOGS",
                "Audit logs should be append-only or shipped to external SIEM", FindingSeverity.HIGH,
                "Configure remote syslog or SIEM integration", false));
        return results;
    }

    private List<ComplianceFinding> checkNetworkSecurity() {
        List<ComplianceFinding> results = new ArrayList<>();
        results.add(new ComplianceFinding("NETWORK", "FIREWALL_ACTIVE",
                "Host firewall should be active (iptables/ufw)", FindingSeverity.CRITICAL,
                "ufw enable && ufw default deny incoming", false));
        results.add(new ComplianceFinding("NETWORK", "UNUSED_PORTS",
                "Non-essential ports should be closed", FindingSeverity.HIGH,
                "Close ports except 25565 (MC), 8080 (API), 22 (SSH)", false));
        results.add(new ComplianceFinding("NETWORK", "DDOS_PROTECTION",
                "DDoS protection should be enabled", FindingSeverity.HIGH,
                "Enable ddos-defense in security config", true));
        return results;
    }

    private List<ComplianceFinding> checkMinecraftServerSecurity() {
        List<ComplianceFinding> results = new ArrayList<>();
        results.add(new ComplianceFinding("MINECRAFT", "COMMAND_BLOCKS",
                "Command blocks should be disabled unless needed", FindingSeverity.MEDIUM,
                "Set enable-command-block=false in server.properties", false));
        results.add(new ComplianceFinding("MINECRAFT", "SPAWN_PROTECTION",
                "Spawn protection should be enabled", FindingSeverity.LOW,
                "Set spawn-protection=16 in server.properties", true));
        results.add(new ComplianceFinding("MINECRAFT", "OP_RESTRICTION",
                "Operator count should be minimal (< 5)", FindingSeverity.MEDIUM,
                "Review ops.json and remove unnecessary operators", false));
        results.add(new ComplianceFinding("MINECRAFT", "PLUGIN_AUDIT",
                "Third-party plugins should be from trusted sources only", FindingSeverity.HIGH,
                "Audit all plugins in /plugins directory", false));
        return results;
    }

    private List<ComplianceFinding> checkBackupCompliance() {
        List<ComplianceFinding> results = new ArrayList<>();
        results.add(new ComplianceFinding("BACKUP", "REGULAR_BACKUPS",
                "Automated backups should be enabled (daily minimum)", FindingSeverity.HIGH,
                "Enable scheduled backups in config", false));
        results.add(new ComplianceFinding("BACKUP", "OFFSITE_BACKUP",
                "Backups should be stored offsite or in cloud storage", FindingSeverity.MEDIUM,
                "Configure remote backup destination", false));
        return results;
    }

    private double calculateComplianceScore(List<ComplianceFinding> findings) {
        if (findings.isEmpty()) return 100.0;
        long passed = findings.stream().filter(f -> f.compliant).count();
        return (double) passed / findings.size() * 100.0;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalFindings", totalFindings.get());
        ComplianceReport latest = runComplianceScan();
        status.put("complianceScore", String.format("%.1f%%", latest.complianceScore));
        status.put("totalChecks", latest.findings.size());
        status.put("passedChecks", latest.findings.stream().filter(f -> f.compliant).count());

        Map<String, Long> byCategory = new LinkedHashMap<>();
        for (ComplianceFinding f : latest.findings) {
            byCategory.merge(f.category, 1L, Long::sum);
        }
        status.put("checksByCategory", byCategory);
        status.put("lastScanTime", latest.scanTime.toString());
        return status;
    }

    public long getTotalFindings() { return totalFindings.get(); }

    public enum FindingSeverity { LOW, MEDIUM, HIGH, CRITICAL }

    public static class ComplianceFinding {
        public final String category;
        public final String checkId;
        public final String description;
        public final FindingSeverity severity;
        public final String remediation;
        public final boolean compliant;

        ComplianceFinding(String category, String checkId, String description, FindingSeverity severity,
                          String remediation, boolean compliant) {
            this.category = category;
            this.checkId = checkId;
            this.description = description;
            this.severity = severity;
            this.remediation = remediation;
            this.compliant = compliant;
        }
    }

    public static class ComplianceReport {
        public final Instant scanTime;
        public final List<ComplianceFinding> findings;
        public final double complianceScore;

        ComplianceReport(Instant scanTime, List<ComplianceFinding> findings, double complianceScore) {
            this.scanTime = scanTime;
            this.findings = findings;
            this.complianceScore = complianceScore;
        }
    }
}
