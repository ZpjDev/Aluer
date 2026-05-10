package com.aluer.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class SSLTLSCertificateService {
    private static final Logger logger = LoggerFactory.getLogger(SSLTLSCertificateService.class);

    private final Map<String, CertificateInfo> certificates = new ConcurrentHashMap<>();
    private final Map<String, CertificateChain> certificateChains = new ConcurrentHashMap<>();
    private final Queue<CertificateAlert> alertQueue = new ConcurrentLinkedQueue<>();
    private final Map<String, SSLConnectionStats> connectionStats = new ConcurrentHashMap<>();
    private final AtomicLong totalConnections = new AtomicLong(0);
    private final AtomicLong totalHandshakes = new AtomicLong(0);
    private final AtomicLong failedHandshakes = new AtomicLong(0);

    private static final int CERTIFICATE_VALIDITY_DAYS = 365;
    private static final int RENEWAL_WARNING_DAYS = 30;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public SSLTLSCertificateService() {
        initializeDefaultCertificates();
        logger.info("SSL/TLS Certificate Service initialized");
    }

    private void initializeDefaultCertificates() {
        addCertificate("minecraft-server", "CN=mc.example.com, O=Example Server, C=US",
            generateExpiryDate(365), "RSA", 2048, "SHA256withRSA");

        addCertificate("rcon-server", "CN=rcon.example.com, O=Example Server, C=US",
            generateExpiryDate(180), "RSA", 2048, "SHA256withRSA");

        logger.info("Initialized {} default certificates", certificates.size());
    }

    private LocalDateTime generateExpiryDate(int days) {
        return LocalDateTime.now().plusDays(days);
    }

    public void addCertificate(String name, String subject, LocalDateTime expiry, 
                              String keyAlgorithm, int keySize, String signatureAlgorithm) {
        CertificateInfo cert = new CertificateInfo(name, subject, expiry, keyAlgorithm, keySize, signatureAlgorithm);
        certificates.put(name, cert);

        CertificateChain chain = new CertificateChain(name);
        chain.addCertificate(cert);
        certificateChains.put(name, chain);

        logger.info("Added certificate: {} (expires: {})", name, expiry);
    }

    public CertificateInfo getCertificate(String name) {
        return certificates.get(name);
    }

    public List<CertificateInfo> getExpiringCertificates(int daysThreshold) {
        List<CertificateInfo> expiring = new ArrayList<>();
        LocalDateTime threshold = LocalDateTime.now().plusDays(daysThreshold);

        for (CertificateInfo cert : certificates.values()) {
            if (cert.getExpiryDate().isBefore(threshold)) {
                expiring.add(cert);
            }
        }

        return expiring;
    }

    public Map<String, Object> analyzeCertificate(String name) {
        Map<String, Object> analysis = new HashMap<>();
        CertificateInfo cert = certificates.get(name);

        if (cert == null) {
            analysis.put("error", "Certificate not found");
            return analysis;
        }

        analysis.put("name", cert.getName());
        analysis.put("subject", cert.getSubject());
        analysis.put("expiryDate", cert.getExpiryDate());
        analysis.put("daysUntilExpiry", cert.getDaysUntilExpiry());

        boolean needsRenewal = cert.getDaysUntilExpiry() < RENEWAL_WARNING_DAYS;
        analysis.put("needsRenewal", needsRenewal);

        boolean isWeakAlgorithm = "MD5".equals(cert.getSignatureAlgorithm()) || "SHA1".equals(cert.getSignatureAlgorithm());
        analysis.put("isWeakAlgorithm", isWeakAlgorithm);

        boolean isWeakKey = cert.getKeySize() < 2048;
        analysis.put("isWeakKey", isWeakKey);

        if (isWeakAlgorithm || isWeakKey || needsRenewal) {
            analysis.put("securityConcerns", new ArrayList<String>());
        }

        CertificateChain chain = certificateChains.get(name);
        if (chain != null) {
            analysis.put("chainLength", chain.getChainLength());
            analysis.put("chainValid", chain.isChainValid());
        }

        return analysis;
    }

    public void recordHandshake(String serverName, boolean success, String error) {
        totalHandshakes.incrementAndGet();

        if (!success) {
            failedHandshakes.incrementAndGet();
        }

        SSLConnectionStats stats = connectionStats.computeIfAbsent(serverName, k -> new SSLConnectionStats(serverName));
        if (success) {
            stats.incrementSuccessfulHandshakes();
        } else {
            stats.incrementFailedHandshakes();
        }

        logger.debug("SSL handshake for {}: {}", serverName, success ? "success" : "failed");
    }

    public void recordConnection(String sourceIP, String destIP, String protocol, boolean encrypted) {
        totalConnections.incrementAndGet();

        SSLConnectionStats stats = connectionStats.computeIfAbsent(destIP, k -> new SSLConnectionStats(destIP));
        stats.incrementConnectionCount();
        if (encrypted) {
            stats.incrementEncryptedConnections();
        }
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalConnections", totalConnections.get());
        stats.put("totalHandshakes", totalHandshakes.get());
        stats.put("failedHandshakes", failedHandshakes.get());
        stats.put("certificatesLoaded", certificates.size());
        stats.put("connectionStats", connectionStats.size());

        long successRate = totalHandshakes.get() > 0 ? 
            (totalHandshakes.get() - failedHandshakes.get()) * 100 / totalHandshakes.get() : 0;
        stats.put("handshakeSuccessRate", successRate + "%");

        return stats;
    }

    public List<CertificateAlert> getAlerts(int limit) {
        List<CertificateAlert> alerts = new ArrayList<>();
        int count = 0;
        for (CertificateAlert alert : alertQueue) {
            if (count++ >= limit) break;
            alerts.add(alert);
        }
        return alerts;
    }

    public void checkCertificateExpiration() {
        for (CertificateInfo cert : certificates.values()) {
            int daysUntilExpiry = cert.getDaysUntilExpiry();

            if (daysUntilExpiry <= 0) {
                triggerAlert(cert.getName(), "EXPIRED", "Certificate has expired");
            } else if (daysUntilExpiry <= 7) {
                triggerAlert(cert.getName(), "CRITICAL", "Certificate expires in " + daysUntilExpiry + " days");
            } else if (daysUntilExpiry <= 30) {
                triggerAlert(cert.getName(), "WARNING", "Certificate expires in " + daysUntilExpiry + " days");
            }
        }
    }

    private void triggerAlert(String certName, String severity, String message) {
        CertificateAlert alert = new CertificateAlert(certName, severity, message, LocalDateTime.now());
        alertQueue.offer(alert);

        if (alertQueue.size() > 100) {
            alertQueue.poll();
        }

        logger.warn("Certificate Alert [{}]: {} - {}", severity, certName, message);
    }

    public Map<String, CertificateInfo> getAllCertificates() {
        return new HashMap<>(certificates);
    }

    public static class CertificateInfo {
        private final String name;
        private final String subject;
        private final LocalDateTime expiryDate;
        private final String keyAlgorithm;
        private final int keySize;
        private final String signatureAlgorithm;

        public CertificateInfo(String name, String subject, LocalDateTime expiryDate,
                            String keyAlgorithm, int keySize, String signatureAlgorithm) {
            this.name = name;
            this.subject = subject;
            this.expiryDate = expiryDate;
            this.keyAlgorithm = keyAlgorithm;
            this.keySize = keySize;
            this.signatureAlgorithm = signatureAlgorithm;
        }

        public int getDaysUntilExpiry() {
            return (int) java.time.Duration.between(LocalDateTime.now(), expiryDate).toDays();
        }

        public String getName() { return name; }
        public String getSubject() { return subject; }
        public LocalDateTime getExpiryDate() { return expiryDate; }
        public String getKeyAlgorithm() { return keyAlgorithm; }
        public int getKeySize() { return keySize; }
        public String getSignatureAlgorithm() { return signatureAlgorithm; }
    }

    public static class CertificateChain {
        private final String serverName;
        private final List<CertificateInfo> certificates = new ArrayList<>();
        private volatile boolean chainValid = true;

        public CertificateChain(String serverName) {
            this.serverName = serverName;
        }

        public void addCertificate(CertificateInfo cert) {
            certificates.add(cert);
        }

        public boolean isChainValid() {
            return chainValid;
        }

        public void setChainValid(boolean valid) {
            this.chainValid = valid;
        }

        public int getChainLength() {
            return certificates.size();
        }

        public String getServerName() { return serverName; }
        public List<CertificateInfo> getCertificates() { return certificates; }
    }

    public static class SSLConnectionStats {
        private final String serverName;
        private final AtomicLong connectionCount = new AtomicLong(0);
        private final AtomicLong encryptedConnections = new AtomicLong(0);
        private final AtomicLong successfulHandshakes = new AtomicLong(0);
        private final AtomicLong failedHandshakes = new AtomicLong(0);

        public SSLConnectionStats(String serverName) {
            this.serverName = serverName;
        }

        public void incrementConnectionCount() { connectionCount.incrementAndGet(); }
        public void incrementEncryptedConnections() { encryptedConnections.incrementAndGet(); }
        public void incrementSuccessfulHandshakes() { successfulHandshakes.incrementAndGet(); }
        public void incrementFailedHandshakes() { failedHandshakes.incrementAndGet(); }

        public String getServerName() { return serverName; }
        public long getConnectionCount() { return connectionCount.get(); }
        public long getEncryptedConnections() { return encryptedConnections.get(); }
        public long getSuccessfulHandshakes() { return successfulHandshakes.get(); }
        public long getFailedHandshakes() { return failedHandshakes.get(); }
    }

    public static class CertificateAlert {
        private final String certificateName;
        private final String severity;
        private final String message;
        private final LocalDateTime timestamp;

        public CertificateAlert(String certificateName, String severity, String message, LocalDateTime timestamp) {
            this.certificateName = certificateName;
            this.severity = severity;
            this.message = message;
            this.timestamp = timestamp;
        }

        public String getCertificateName() { return certificateName; }
        public String getSeverity() { return severity; }
        public String getMessage() { return message; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
