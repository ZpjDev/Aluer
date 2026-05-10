package com.aluer.console;

import com.aluer.ai.AluerSovereignEngine;
import com.aluer.audit.SecurityAuditService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.kernel.AluerKernelEngine;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

@Service
public class AluerEngineHandshakeService {
    private final ServerGuardConfig config;
    private final AluerSovereignEngine aluerSovereignEngine;
    private final AluerKernelEngine aluerKernelEngine;
    private final AluerMirageShieldService aluerMirageShieldService;
    private final SecurityAuditService securityAuditService;

    private final Map<String, HandshakeGrant> grants = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<HandshakeRecord> history = new ConcurrentLinkedDeque<>();

    public AluerEngineHandshakeService(ServerGuardConfig config,
                                       AluerSovereignEngine aluerSovereignEngine,
                                       AluerKernelEngine aluerKernelEngine,
                                       AluerMirageShieldService aluerMirageShieldService,
                                       SecurityAuditService securityAuditService) {
        this.config = config;
        this.aluerSovereignEngine = aluerSovereignEngine;
        this.aluerKernelEngine = aluerKernelEngine;
        this.aluerMirageShieldService = aluerMirageShieldService;
        this.securityAuditService = securityAuditService;
    }

    public HandshakeResult requestSshHandshake(HandshakeIntent intent) {
        String host = requireText(intent.host(), "host");
        String username = requireText(intent.username(), "username");
        int port = intent.port() > 0 ? intent.port() : 22;
        String purpose = intent.purpose() == null || intent.purpose().isBlank() ? "ssh-connect" : intent.purpose().trim();

        cleanupExpiredGrants();

        Map<String, Object> engineStatus = aluerSovereignEngine.getEngineStatus();
        AluerKernelEngine.KernelPulse pulse = aluerKernelEngine.runKernelPulse("ssh-handshake:" + host + ":" + username);
        Map<String, Object> shieldStatus = aluerMirageShieldService.getShieldStatus();

        int kernelHeat = (int) Math.round(pulse.getHeat());
        int resonance = (int) Math.round(pulse.getResonance());
        int riskScore = toInt(shieldStatus.get("riskScore"));
        String shieldMode = String.valueOf(shieldStatus.getOrDefault("currentMode", "OBSERVE"));
        String workflow = pulse.getDirective().getWorkflow();
        boolean handshakeRequired = config.getDashboard().getSshGateway().isRequireEngineHandshake();
        boolean approved = !handshakeRequired || (kernelHeat < 96 && riskScore < 97);
        String token = approved ? UUID.randomUUID().toString() : "";
        long ttlSeconds = Math.max(10, config.getDashboard().getSshGateway().getHandshakeTtlSeconds());
        long expiresAt = System.currentTimeMillis() + ttlSeconds * 1000L;
        String message = approved
            ? "Sovereign handshake approved. Session may proceed."
            : "Main engine declined SSH session while the node is under critical defensive pressure.";

        if (approved && handshakeRequired) {
            grants.put(token, new HandshakeGrant(token, host, port, username, expiresAt, purpose, shieldMode, kernelHeat, riskScore));
        }

        HandshakeRecord record = new HandshakeRecord(host, port, username, purpose, approved, shieldMode, kernelHeat, riskScore, workflow, expiresAt);
        rememberRecord(record);
        securityAuditService.logEvent("ALUER_HANDSHAKE", username + "@" + host, approved ? "APPROVED" : "DENIED", purpose);

        return new HandshakeResult(
            approved,
            token,
            message,
            shieldMode,
            workflow,
            kernelHeat,
            resonance,
            riskScore,
            expiresAt,
            engineStatus.getOrDefault("engine", "ALUER_SOVEREIGN_LOOP").toString()
        );
    }

    public HandshakeGrant consumeSshGrant(String token, String host, int port, String username) {
        cleanupExpiredGrants();
        if (!config.getDashboard().getSshGateway().isRequireEngineHandshake()) {
            return new HandshakeGrant("", host, port, username, 0, "ssh-connect", "BYPASS", 0, 0);
        }
        String normalizedToken = requireText(token, "handshakeToken");
        HandshakeGrant grant = grants.remove(normalizedToken);
        if (grant == null) {
            throw new IllegalArgumentException("主引擎握手令牌不存在或已过期");
        }
        if (grant.expiresAt < System.currentTimeMillis()) {
            throw new IllegalArgumentException("主引擎握手令牌已过期");
        }
        if (!grant.host.equals(host) || grant.port != port || !grant.username.equals(username)) {
            throw new IllegalArgumentException("主引擎握手令牌与目标节点不匹配");
        }
        return grant;
    }

    public Map<String, Object> getStatus() {
        cleanupExpiredGrants();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("required", config.getDashboard().getSshGateway().isRequireEngineHandshake());
        result.put("ttlSeconds", config.getDashboard().getSshGateway().getHandshakeTtlSeconds());
        result.put("activeGrants", grants.size());
        if (!history.isEmpty()) {
            result.put("lastHandshake", history.peekFirst().toMap());
        }
        return result;
    }

    private void cleanupExpiredGrants() {
        long now = System.currentTimeMillis();
        grants.entrySet().removeIf(entry -> entry.getValue().expiresAt < now);
    }

    private void rememberRecord(HandshakeRecord record) {
        history.offerFirst(record);
        while (history.size() > 120) {
            history.pollLast();
        }
    }

    private int toInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return value == null ? 0 : Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " 不能为空");
        }
        return value.trim();
    }

    public record HandshakeIntent(
        String host,
        int port,
        String username,
        String purpose
    ) {
    }

    public static class HandshakeResult {
        private final boolean approved;
        private final String token;
        private final String message;
        private final String shieldMode;
        private final String workflow;
        private final int kernelHeat;
        private final int resonance;
        private final int riskScore;
        private final long expiresAt;
        private final String engine;

        public HandshakeResult(boolean approved,
                               String token,
                               String message,
                               String shieldMode,
                               String workflow,
                               int kernelHeat,
                               int resonance,
                               int riskScore,
                               long expiresAt,
                               String engine) {
            this.approved = approved;
            this.token = token;
            this.message = message;
            this.shieldMode = shieldMode;
            this.workflow = workflow;
            this.kernelHeat = kernelHeat;
            this.resonance = resonance;
            this.riskScore = riskScore;
            this.expiresAt = expiresAt;
            this.engine = engine;
        }

        public boolean isApproved() { return approved; }
        public String getToken() { return token; }
        public String getMessage() { return message; }
        public String getShieldMode() { return shieldMode; }
        public String getWorkflow() { return workflow; }
        public int getKernelHeat() { return kernelHeat; }
        public int getResonance() { return resonance; }
        public int getRiskScore() { return riskScore; }
        public long getExpiresAt() { return expiresAt; }
        public String getEngine() { return engine; }
    }

    public static class HandshakeGrant {
        private final String token;
        private final String host;
        private final int port;
        private final String username;
        private final long expiresAt;
        private final String purpose;
        private final String shieldMode;
        private final int kernelHeat;
        private final int riskScore;

        public HandshakeGrant(String token,
                              String host,
                              int port,
                              String username,
                              long expiresAt,
                              String purpose,
                              String shieldMode,
                              int kernelHeat,
                              int riskScore) {
            this.token = token;
            this.host = host;
            this.port = port;
            this.username = username;
            this.expiresAt = expiresAt;
            this.purpose = purpose;
            this.shieldMode = shieldMode;
            this.kernelHeat = kernelHeat;
            this.riskScore = riskScore;
        }

        public String getToken() { return token; }
        public String getHost() { return host; }
        public int getPort() { return port; }
        public String getUsername() { return username; }
        public long getExpiresAt() { return expiresAt; }
        public String getPurpose() { return purpose; }
        public String getShieldMode() { return shieldMode; }
        public int getKernelHeat() { return kernelHeat; }
        public int getRiskScore() { return riskScore; }
    }

    public static class HandshakeRecord {
        private final String host;
        private final int port;
        private final String username;
        private final String purpose;
        private final boolean approved;
        private final String shieldMode;
        private final int kernelHeat;
        private final int riskScore;
        private final String workflow;
        private final long expiresAt;
        private final long timestamp = Instant.now().toEpochMilli();

        public HandshakeRecord(String host,
                               int port,
                               String username,
                               String purpose,
                               boolean approved,
                               String shieldMode,
                               int kernelHeat,
                               int riskScore,
                               String workflow,
                               long expiresAt) {
            this.host = host;
            this.port = port;
            this.username = username;
            this.purpose = purpose;
            this.approved = approved;
            this.shieldMode = shieldMode;
            this.kernelHeat = kernelHeat;
            this.riskScore = riskScore;
            this.workflow = workflow;
            this.expiresAt = expiresAt;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("host", host);
            result.put("port", port);
            result.put("username", username);
            result.put("purpose", purpose);
            result.put("approved", approved);
            result.put("shieldMode", shieldMode);
            result.put("kernelHeat", kernelHeat);
            result.put("riskScore", riskScore);
            result.put("workflow", workflow);
            result.put("expiresAt", expiresAt);
            result.put("timestamp", timestamp);
            return result;
        }
    }
}
