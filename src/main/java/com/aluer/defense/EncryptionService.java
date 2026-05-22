package com.aluer.defense;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.security.MessageDigest;
import java.util.Base64;

@Component
public class EncryptionService {
    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);

    private final Map<String, String> encryptionKeys = new ConcurrentHashMap<>();
    private final Map<String, EncryptionStats> stats = new ConcurrentHashMap<>();
    private final Queue<EncryptionEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final AtomicLong totalEncryptions = new AtomicLong(0);
    private final AtomicLong totalDecryptions = new AtomicLong(0);
    private final AtomicLong totalFailures = new AtomicLong(0);

    private static final String DEFAULT_KEY = "AluerDefaultKey2024Secure!";
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public EncryptionService() {
        encryptionKeys.put("default", DEFAULT_KEY);
        logger.info("Encryption Service initialized");
    }

    public String encrypt(String plaintext, String keyName) {
        try {
            String key = encryptionKeys.getOrDefault(keyName, DEFAULT_KEY);
            String encrypted = xorEncrypt(plaintext, key);
            totalEncryptions.incrementAndGet();

            EncryptionStats stat = stats.computeIfAbsent(keyName, k -> new EncryptionStats(keyName));
            stat.incrementEncryptions();

            logEvent("ENCRYPT", keyName, "SUCCESS", null);
            return encrypted;
        } catch (Exception e) {
            totalFailures.incrementAndGet();
            logEvent("ENCRYPT", keyName, "FAILED", e.getMessage());
            logger.error("Encryption failed: {}", e.getMessage());
            return null;
        }
    }

    public String decrypt(String ciphertext, String keyName) {
        try {
            String key = encryptionKeys.getOrDefault(keyName, DEFAULT_KEY);
            String decrypted = xorDecrypt(ciphertext, key);
            totalDecryptions.incrementAndGet();

            EncryptionStats stat = stats.computeIfAbsent(keyName, k -> new EncryptionStats(keyName));
            stat.incrementDecryptions();

            logEvent("DECRYPT", keyName, "SUCCESS", null);
            return decrypted;
        } catch (Exception e) {
            totalFailures.incrementAndGet();
            logEvent("DECRYPT", keyName, "FAILED", e.getMessage());
            logger.error("Decryption failed: {}", e.getMessage());
            return null;
        }
    }

    private String xorEncrypt(String plaintext, String key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < plaintext.length(); i++) {
            result.append((char) (plaintext.charAt(i) ^ key.charAt(i % key.length())));
        }
        return Base64.getEncoder().encodeToString(result.toString().getBytes());
    }

    private String xorDecrypt(String ciphertext, String key) {
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        String decodedStr = new String(decoded);
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < decodedStr.length(); i++) {
            result.append((char) (decodedStr.charAt(i) ^ key.charAt(i % key.length())));
        }
        return result.toString();
    }

    public String hashData(String data, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hash = md.digest(data.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            logger.error("Hashing failed: {}", e.getMessage());
            return null;
        }
    }

    public String generateKey(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        Random random = new Random();
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < length; i++) {
            key.append(chars.charAt(random.nextInt(chars.length())));
        }
        return key.toString();
    }

    public void addKey(String name, String key) {
        encryptionKeys.put(name, key);
        logger.info("Added encryption key: {}", name);
    }

    public boolean removeKey(String name) {
        if ("default".equals(name)) {
            logger.warn("Cannot remove default key");
            return false;
        }
        return encryptionKeys.remove(name) != null;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> statsMap = new HashMap<>();
        statsMap.put("totalEncryptions", totalEncryptions.get());
        statsMap.put("totalDecryptions", totalDecryptions.get());
        statsMap.put("totalFailures", totalFailures.get());
        statsMap.put("activeKeys", encryptionKeys.size());
        return statsMap;
    }

    public List<EncryptionEvent> getRecentEvents(int limit) {
        List<EncryptionEvent> events = new ArrayList<>();
        int count = 0;
        for (EncryptionEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    private void logEvent(String operation, String keyName, String status, String error) {
        EncryptionEvent event = new EncryptionEvent(operation, keyName, status, error, LocalDateTime.now());
        eventLog.offer(event);
        if (eventLog.size() > 1000) {
            eventLog.poll();
        }
    }

    public static class EncryptionStats {
        private final String keyName;
        private final AtomicLong encryptions = new AtomicLong(0);
        private final AtomicLong decryptions = new AtomicLong(0);

        public EncryptionStats(String keyName) {
            this.keyName = keyName;
        }

        public void incrementEncryptions() { encryptions.incrementAndGet(); }
        public void incrementDecryptions() { decryptions.incrementAndGet(); }

        public String getKeyName() { return keyName; }
        public long getEncryptions() { return encryptions.get(); }
        public long getDecryptions() { return decryptions.get(); }
    }

    public static class EncryptionEvent {
        private final String operation;
        private final String keyName;
        private final String status;
        private final String error;
        private final LocalDateTime timestamp;

        public EncryptionEvent(String operation, String keyName, String status, String error, LocalDateTime timestamp) {
            this.operation = operation;
            this.keyName = keyName;
            this.status = status;
            this.error = error;
            this.timestamp = timestamp;
        }

        public String getOperation() { return operation; }
        public String getKeyName() { return keyName; }
        public String getStatus() { return status; }
        public String getError() { return error; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
