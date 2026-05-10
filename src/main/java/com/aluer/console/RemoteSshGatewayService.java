package com.aluer.console;

import com.aluer.audit.SecurityAuditService;
import com.aluer.config.ServerGuardConfig;
import com.aluer.security.CommandExecutionGuardService;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
public class RemoteSshGatewayService {
    private static final int CONNECT_TIMEOUT_MS = 12_000;
    private static final int MAX_OUTPUT_CHARS = 16_000;

    private final ServerGuardConfig config;
    private final CommandExecutionGuardService commandExecutionGuardService;
    private final SecurityAuditService securityAuditService;
    private final AluerEngineHandshakeService aluerEngineHandshakeService;
    private final Map<String, ActiveSession> sessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "aluer-ssh-gateway");
        thread.setDaemon(true);
        return thread;
    });

    @Autowired
    public RemoteSshGatewayService(ServerGuardConfig config,
                                   CommandExecutionGuardService commandExecutionGuardService,
                                   SecurityAuditService securityAuditService,
                                   AluerEngineHandshakeService aluerEngineHandshakeService) {
        this.config = config;
        this.commandExecutionGuardService = commandExecutionGuardService;
        this.securityAuditService = securityAuditService;
        this.aluerEngineHandshakeService = aluerEngineHandshakeService;
        startCleanupLoop();
    }

    public RemoteSshGatewayService(ServerGuardConfig config,
                                   CommandExecutionGuardService commandExecutionGuardService,
                                   SecurityAuditService securityAuditService) {
        this(config, commandExecutionGuardService, securityAuditService, null);
    }

    public AluerEngineHandshakeService.HandshakeResult requestHandshake(HandshakeRequest request) {
        ensureEnabled();
        if (aluerEngineHandshakeService == null) {
            throw new IllegalStateException("主引擎握手服务不可用");
        }
        return aluerEngineHandshakeService.requestSshHandshake(
            new AluerEngineHandshakeService.HandshakeIntent(
                request.host(),
                request.port(),
                request.username(),
                request.purpose()
            )
        );
    }

    public SessionView connect(ConnectRequest request) {
        ensureEnabled();
        cleanupExpiredSessions();
        if (sessions.size() >= Math.max(1, config.getDashboard().getSshGateway().getMaxSessions())) {
            throw new IllegalStateException("SSH 会话已达到上限");
        }

        String host = requireText(request.host(), "host");
        String username = requireText(request.username(), "username");
        int port = request.port() > 0 ? request.port() : 22;
        boolean hasPassword = request.password() != null && !request.password().isBlank();
        boolean hasInlineKey = request.privateKey() != null && !request.privateKey().isBlank();
        boolean hasKeyPath = request.privateKeyPath() != null && !request.privateKeyPath().isBlank();
        if (!hasPassword && !hasInlineKey && !hasKeyPath) {
            throw new IllegalArgumentException("请提供 SSH 密码或私钥");
        }
        if (hasInlineKey && !config.getDashboard().getSshGateway().isAllowPrivateKeyPaste()) {
            throw new IllegalArgumentException("当前配置不允许粘贴私钥");
        }

        String alias = request.alias() == null || request.alias().isBlank()
            ? username + "@" + host
            : request.alias().trim();

        validateHandshake(request, host, port, username);

        try {
            JSch jsch = new JSch();
            if (hasInlineKey) {
                byte[] passphrase = toBytes(request.passphrase());
                jsch.addIdentity(alias, request.privateKey().getBytes(StandardCharsets.UTF_8), null, passphrase);
            } else if (hasKeyPath) {
                if (request.passphrase() != null && !request.passphrase().isBlank()) {
                    jsch.addIdentity(request.privateKeyPath(), request.passphrase());
                } else {
                    jsch.addIdentity(request.privateKeyPath());
                }
            }

            Session session = jsch.getSession(username, host, port);
            if (hasPassword) {
                session.setPassword(request.password());
            }
            session.setConfig("StrictHostKeyChecking",
                config.getDashboard().getSshGateway().isStrictHostKeyChecking() ? "yes" : "no");
            session.connect(CONNECT_TIMEOUT_MS);

            String sessionId = UUID.randomUUID().toString();
            HostKey hostKey = session.getHostKey();
            ActiveSession activeSession = new ActiveSession(
                sessionId,
                alias,
                host,
                port,
                username,
                hostKey == null ? "" : hostKey.getFingerPrint(jsch),
                session
            );
            sessions.put(sessionId, activeSession);
            securityAuditService.logEvent("SSH_GATEWAY", alias, "CONNECT", host + ":" + port);
            return activeSession.toView();
        } catch (JSchException e) {
            throw new IllegalStateException("SSH 连接失败: " + e.getMessage(), e);
        }
    }

    public SshCommandResult execute(String sessionId, String command) {
        ensureEnabled();
        ActiveSession activeSession = requireSession(sessionId);
        String normalizedCommand = requireText(command, "command");
        activeSession.touch();

        CommandExecutionGuardService.AntiIntrusionIncident guardIncident =
            commandExecutionGuardService.analyzeCommand("ssh:" + activeSession.username, normalizedCommand, activeSession.host);

        ChannelExec channel = null;
        long started = System.currentTimeMillis();
        try {
            channel = (ChannelExec) activeSession.session.openChannel("exec");
            channel.setCommand(normalizedCommand);
            channel.setInputStream(null);
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            channel.setOutputStream(stdout);
            channel.setErrStream(stderr);
            channel.connect(CONNECT_TIMEOUT_MS);

            long timeoutAt = started + Math.max(5, config.getDashboard().getSshGateway().getCommandTimeoutSeconds()) * 1000L;
            while (!channel.isClosed() && System.currentTimeMillis() < timeoutAt) {
                Thread.sleep(120);
            }

            boolean timedOut = !channel.isClosed();
            if (timedOut) {
                channel.disconnect();
            }

            int exitStatus = timedOut ? -1 : channel.getExitStatus();
            long durationMs = System.currentTimeMillis() - started;
            String stdoutText = trimOutput(stdout.toString(StandardCharsets.UTF_8));
            String stderrText = trimOutput(stderr.toString(StandardCharsets.UTF_8));
            securityAuditService.logEvent(
                "SSH_GATEWAY",
                activeSession.alias,
                "EXECUTE",
                normalizedCommand + " [" + exitStatus + "]"
            );

            return new SshCommandResult(
                sessionId,
                normalizedCommand,
                stdoutText,
                stderrText,
                exitStatus,
                durationMs,
                timedOut,
                guardIncident != null,
                guardIncident == null ? "" : guardIncident.getType(),
                guardIncident == null ? 0 : guardIncident.getSeverity(),
                Instant.now().toEpochMilli()
            );
        } catch (Exception e) {
            throw new IllegalStateException("SSH 命令执行失败: " + e.getMessage(), e);
        } finally {
            if (channel != null && channel.isConnected()) {
                channel.disconnect();
            }
        }
    }

    public SessionView disconnect(String sessionId) {
        ActiveSession activeSession = requireSession(sessionId);
        activeSession.session.disconnect();
        sessions.remove(sessionId);
        securityAuditService.logEvent("SSH_GATEWAY", activeSession.alias, "DISCONNECT", activeSession.host);
        return activeSession.toView();
    }

    public Map<String, Object> getGatewayStatus() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("enabled", config.getDashboard().getSshGateway().isEnabled());
        result.put("activeSessions", sessions.size());
        result.put("sessionTimeoutMinutes", config.getDashboard().getSshGateway().getSessionTimeoutMinutes());
        result.put("maxSessions", config.getDashboard().getSshGateway().getMaxSessions());
        result.put("strictHostKeyChecking", config.getDashboard().getSshGateway().isStrictHostKeyChecking());
        result.put("handshakeRequired", config.getDashboard().getSshGateway().isRequireEngineHandshake());
        if (aluerEngineHandshakeService != null) {
            result.put("engineHandshake", aluerEngineHandshakeService.getStatus());
        }
        result.put("sessions", listSessions());
        return result;
    }

    public List<SessionView> listSessions() {
        cleanupExpiredSessions();
        return sessions.values().stream()
            .sorted(Comparator.comparingLong(ActiveSession::getLastUsedAt).reversed())
            .map(ActiveSession::toView)
            .toList();
    }

    private void startCleanupLoop() {
        scheduler.scheduleAtFixedRate(this::cleanupExpiredSessions, 60, 60, TimeUnit.SECONDS);
    }

    private void cleanupExpiredSessions() {
        long cutoff = System.currentTimeMillis()
            - Math.max(5, config.getDashboard().getSshGateway().getSessionTimeoutMinutes()) * 60_000L;
        List<String> expired = new ArrayList<>();
        for (ActiveSession activeSession : sessions.values()) {
            if (activeSession.lastUsedAt < cutoff || !activeSession.session.isConnected()) {
                expired.add(activeSession.sessionId);
            }
        }
        for (String sessionId : expired) {
            ActiveSession activeSession = sessions.remove(sessionId);
            if (activeSession != null && activeSession.session.isConnected()) {
                activeSession.session.disconnect();
            }
        }
    }

    private void ensureEnabled() {
        if (!config.getDashboard().getSshGateway().isEnabled()) {
            throw new IllegalStateException("SSH Gateway 已禁用");
        }
    }

    private ActiveSession requireSession(String sessionId) {
        String key = requireText(sessionId, "sessionId");
        ActiveSession activeSession = sessions.get(key);
        if (activeSession == null || !activeSession.session.isConnected()) {
            sessions.remove(key);
            throw new IllegalArgumentException("SSH 会话不存在或已断开");
        }
        return activeSession;
    }

    private String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " 不能为空");
        }
        return value.trim();
    }

    private void validateHandshake(ConnectRequest request, String host, int port, String username) {
        if (!config.getDashboard().getSshGateway().isRequireEngineHandshake()) {
            return;
        }
        if (aluerEngineHandshakeService == null) {
            throw new IllegalStateException("主引擎握手服务不可用");
        }
        aluerEngineHandshakeService.consumeSshGrant(request.handshakeToken(), host, port, username);
    }

    private byte[] toBytes(String value) {
        return value == null || value.isBlank() ? null : value.getBytes(StandardCharsets.UTF_8);
    }

    private String trimOutput(String value) {
        if (value == null) {
            return "";
        }
        String normalized = value.trim();
        if (normalized.length() <= MAX_OUTPUT_CHARS) {
            return normalized;
        }
        return normalized.substring(0, MAX_OUTPUT_CHARS) + "\n...[output truncated by Aluer]";
    }

    public record ConnectRequest(
        String alias,
        String host,
        int port,
        String username,
        String password,
        String privateKey,
        String privateKeyPath,
        String passphrase,
        String handshakeToken
    ) {
    }

    public record HandshakeRequest(
        String host,
        int port,
        String username,
        String purpose
    ) {
    }

    public static class SessionView {
        private final String sessionId;
        private final String alias;
        private final String host;
        private final int port;
        private final String username;
        private final String fingerprint;
        private final long connectedAt;
        private final long lastUsedAt;

        public SessionView(String sessionId,
                           String alias,
                           String host,
                           int port,
                           String username,
                           String fingerprint,
                           long connectedAt,
                           long lastUsedAt) {
            this.sessionId = sessionId;
            this.alias = alias;
            this.host = host;
            this.port = port;
            this.username = username;
            this.fingerprint = fingerprint;
            this.connectedAt = connectedAt;
            this.lastUsedAt = lastUsedAt;
        }

        public String getSessionId() { return sessionId; }
        public String getAlias() { return alias; }
        public String getHost() { return host; }
        public int getPort() { return port; }
        public String getUsername() { return username; }
        public String getFingerprint() { return fingerprint; }
        public long getConnectedAt() { return connectedAt; }
        public long getLastUsedAt() { return lastUsedAt; }
    }

    public static class SshCommandResult {
        private final String sessionId;
        private final String command;
        private final String stdout;
        private final String stderr;
        private final int exitStatus;
        private final long durationMs;
        private final boolean timedOut;
        private final boolean flagged;
        private final String guardType;
        private final int guardSeverity;
        private final long timestamp;

        public SshCommandResult(String sessionId,
                                String command,
                                String stdout,
                                String stderr,
                                int exitStatus,
                                long durationMs,
                                boolean timedOut,
                                boolean flagged,
                                String guardType,
                                int guardSeverity,
                                long timestamp) {
            this.sessionId = sessionId;
            this.command = command;
            this.stdout = stdout;
            this.stderr = stderr;
            this.exitStatus = exitStatus;
            this.durationMs = durationMs;
            this.timedOut = timedOut;
            this.flagged = flagged;
            this.guardType = guardType;
            this.guardSeverity = guardSeverity;
            this.timestamp = timestamp;
        }

        public String getSessionId() { return sessionId; }
        public String getCommand() { return command; }
        public String getStdout() { return stdout; }
        public String getStderr() { return stderr; }
        public int getExitStatus() { return exitStatus; }
        public long getDurationMs() { return durationMs; }
        public boolean isTimedOut() { return timedOut; }
        public boolean isFlagged() { return flagged; }
        public String getGuardType() { return guardType; }
        public int getGuardSeverity() { return guardSeverity; }
        public long getTimestamp() { return timestamp; }
    }

    private static final class ActiveSession {
        private final String sessionId;
        private final String alias;
        private final String host;
        private final int port;
        private final String username;
        private final String fingerprint;
        private final Session session;
        private final long connectedAt;
        private volatile long lastUsedAt;

        private ActiveSession(String sessionId,
                              String alias,
                              String host,
                              int port,
                              String username,
                              String fingerprint,
                              Session session) {
            this.sessionId = sessionId;
            this.alias = alias;
            this.host = host;
            this.port = port;
            this.username = username;
            this.fingerprint = fingerprint;
            this.session = session;
            this.connectedAt = System.currentTimeMillis();
            this.lastUsedAt = this.connectedAt;
        }

        private long getLastUsedAt() {
            return lastUsedAt;
        }

        private void touch() {
            this.lastUsedAt = System.currentTimeMillis();
        }

        private SessionView toView() {
            return new SessionView(sessionId, alias, host, port, username, fingerprint, connectedAt, lastUsedAt);
        }
    }
}
