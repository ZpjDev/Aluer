package com.aluer.security;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class SSLMonitorService {

    private final Map<String, SSLSession> sslSessions = new ConcurrentHashMap<>();
    private final Queue<SSLAlert> alerts = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final long SESSION_TIMEOUT = 60000;
    private static final int MAX_CERTIFICATES = 1000;

    private final AtomicLong totalHandshakes = new AtomicLong(0);
    private final AtomicLong failedHandshakes = new AtomicLong(0);

    public SSLMonitorService() {
        startMonitoringTask();
    }

    public boolean recordHandshake(String ip, boolean success, String details) {
        totalHandshakes.incrementAndGet();

        if (!success) {
            failedHandshakes.incrementAndGet();
            addAlert(ip, "HANDSHAKE_FAILED", details);
            return false;
        }

        SSLSession session = sslSessions.computeIfAbsent(ip, k -> new SSLSession(ip));
        session.recordHandshake(success);
        return true;
    }

    public void recordCertificate(String ip, String certInfo) {
        SSLSession session = sslSessions.get(ip);
        if (session != null) {
            session.addCertificate(certInfo);
        }
    }

    public void recordCipherSuite(String ip, String cipher) {
        SSLSession session = sslSessions.get(ip);
        if (session != null) {
            session.setCipherSuite(cipher);
        }
    }

    public void recordProtocolVersion(String ip, String version) {
        SSLSession session = sslSessions.get(ip);
        if (session != null) {
            session.setProtocolVersion(version);
        }
    }

    public boolean isWeakCipher(String ip) {
        SSLSession session = sslSessions.get(ip);
        if (session == null || session.cipherSuite == null) {
            return false;
        }
        return isWeakCipherSuite(session.cipherSuite);
    }

    private boolean isWeakCipherSuite(String cipher) {
        String[] weakCiphers = {"SSL", "TLSv1.0", "TLSv1.1", "3DES", "RC4", "MD5"};
        for (String weak : weakCiphers) {
            if (cipher.toUpperCase().contains(weak)) {
                return true;
            }
        }
        return false;
    }

    public boolean isOutdatedProtocol(String ip) {
        SSLSession session = sslSessions.get(ip);
        if (session == null || session.protocolVersion == null) {
            return false;
        }
        return session.protocolVersion.contains("1.0") || session.protocolVersion.contains("1.1");
    }

    public SSLSession getSession(String ip) {
        return sslSessions.get(ip);
    }

    public Collection<SSLSession> getAllSessions() {
        return sslSessions.values();
    }

    public void addAlert(String ip, String type, String details) {
        SSLAlert alert = new SSLAlert(ip, type, details, System.currentTimeMillis());
        alerts.offer(alert);

        while (alerts.size() > 500) {
            alerts.poll();
        }
    }

    public List<SSLAlert> getAlerts(int limit) {
        List<SSLAlert> result = new ArrayList<>();
        int count = 0;
        for (SSLAlert alert : alerts) {
            if (count++ >= limit) break;
            result.add(alert);
        }
        return result;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("activeSessions", sslSessions.size());
        stats.put("totalHandshakes", totalHandshakes.get());
        stats.put("failedHandshakes", failedHandshakes.get());
        return stats;
    }

    private void startMonitoringTask() {
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();

            sslSessions.entrySet().removeIf(entry ->
                now - entry.getValue().lastActivity > SESSION_TIMEOUT);

        }, 30, 30, TimeUnit.SECONDS);
    }

    public static class SSLSession {
        private final String ip;
        private final List<String> certificates = new ArrayList<>();
        private volatile String cipherSuite;
        private volatile String protocolVersion;
        private volatile long handshakeCount = 0;
        private volatile long failedCount = 0;
        private volatile long lastActivity;

        public SSLSession(String ip) {
            this.ip = ip;
            this.lastActivity = System.currentTimeMillis();
        }

        public void recordHandshake(boolean success) {
            handshakeCount++;
            if (!success) {
                failedCount++;
            }
            lastActivity = System.currentTimeMillis();
        }

        public void addCertificate(String certInfo) {
            certificates.add(certInfo);
            if (certificates.size() > MAX_CERTIFICATES) {
                certificates.remove(0);
            }
        }

        public String getIp() { return ip; }
        public String getCipherSuite() { return cipherSuite; }
        public void setCipherSuite(String cipherSuite) { this.cipherSuite = cipherSuite; }
        public String getProtocolVersion() { return protocolVersion; }
        public void setProtocolVersion(String protocolVersion) { this.protocolVersion = protocolVersion; }
        public long getHandshakeCount() { return handshakeCount; }
        public long getFailedCount() { return failedCount; }
    }

    public static class SSLAlert {
        private final String ip;
        private final String type;
        private final String details;
        private final long timestamp;

        public SSLAlert(String ip, String type, String details, long timestamp) {
            this.ip = ip;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getIp() { return ip; }
        public String getType() { return type; }
        public String getDetails() { return details; }
        public long getTimestamp() { return timestamp; }
    }
}
