package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class BackupIntegrityService {

    private final ServerGuardConfig config;

    private final Map<String, BackupRecord> records = new ConcurrentHashMap<>();
    private final Map<String, List<IntegrityResult>> history = new ConcurrentHashMap<>();

    private final AtomicLong totalVerified = new AtomicLong(0);
    private final AtomicLong failedCount = new AtomicLong(0);
    private final AtomicLong corruptedCount = new AtomicLong(0);

    private volatile long lastScanTime = 0L;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private static final long SIX_HOURS_MS = 6L * 60 * 60 * 1000;
    private static final long SIZE_TOLERANCE_BYTES = 1024L;

    public BackupIntegrityService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public BackupIntegrityService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::scanAll, 1, 6, TimeUnit.HOURS);
    }

    public void registerBackup(String name, String filePath, long size, String expectedHash) {
        BackupRecord record = new BackupRecord(name, filePath, size, expectedHash, System.currentTimeMillis());
        records.put(name, record);
        history.computeIfAbsent(name, k -> new CopyOnWriteArrayList<>());
    }

    public IntegrityResult verifyBackup(String name) {
        if (!config.getSecurity().getSuperEvolution().isBackupIntegrity()) {
            return IntegrityResult.passed();
        }

        BackupRecord record = records.get(name);
        if (record == null) {
            failedCount.incrementAndGet();
            return IntegrityResult.missing();
        }

        Path path = Paths.get(record.filePath);
        if (!Files.exists(path)) {
            failedCount.incrementAndGet();
            List<String> reasons = new ArrayList<>();
            reasons.add("File not found: " + record.filePath);
            IntegrityResult result = IntegrityResult.failed(reasons);
            appendHistory(name, result);
            return result;
        }

        List<String> reasons = new ArrayList<>();
        boolean ok = true;

        // File size check
        try {
            long actualSize = Files.size(path);
            long diff = Math.abs(actualSize - record.expectedSize);
            if (diff > SIZE_TOLERANCE_BYTES) {
                ok = false;
                reasons.add("Size mismatch: expected " + record.expectedSize + ", actual " + actualSize + " (diff " + diff + ")");
            }
        } catch (IOException e) {
            ok = false;
            reasons.add("Cannot read file size: " + e.getMessage());
        }

        // SHA-256 checksum
        try {
            String actualHash = computeSha256(path);
            if (!actualHash.equals(record.expectedHash)) {
                ok = false;
                reasons.add("Hash mismatch: expected " + record.expectedHash + ", actual " + actualHash);
                corruptedCount.incrementAndGet();
            }
        } catch (Exception e) {
            ok = false;
            reasons.add("Cannot compute hash: " + e.getMessage());
            corruptedCount.incrementAndGet();
        }

        record.lastVerified = System.currentTimeMillis();

        if (ok) {
            totalVerified.incrementAndGet();
            IntegrityResult result = IntegrityResult.passed();
            appendHistory(name, result);
            return result;
        } else {
            failedCount.incrementAndGet();
            IntegrityResult result;
            if (reasons.stream().anyMatch(r -> r.contains("Hash mismatch") || r.contains("corrupt"))) {
                result = IntegrityResult.corrupted(reasons);
            } else {
                result = IntegrityResult.failed(reasons);
            }
            appendHistory(name, result);
            return result;
        }
    }

    public void scanAll() {
        lastScanTime = System.currentTimeMillis();
        for (String name : new ArrayList<>(records.keySet())) {
            verifyBackup(name);
        }
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalBackups", records.size());
        status.put("verifiedCount", totalVerified.get());
        status.put("failedCount", failedCount.get());
        status.put("corruptedCount", corruptedCount.get());
        status.put("lastScanTime", lastScanTime > 0 ? new java.util.Date(lastScanTime).toString() : "never");
        status.put("configEnabled", config.getSecurity().getSuperEvolution().isBackupIntegrity());
        return status;
    }

    public Map<String, BackupRecord> getRecords() {
        return new LinkedHashMap<>(records);
    }

    public List<IntegrityResult> getHistory(String name) {
        List<IntegrityResult> h = history.get(name);
        return h != null ? new ArrayList<>(h) : List.of();
    }

    private String computeSha256(Path path) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        byte[] hashBytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void appendHistory(String name, IntegrityResult result) {
        List<IntegrityResult> list = history.get(name);
        if (list != null) {
            list.add(result);
            while (list.size() > 50) {
                list.remove(0);
            }
        }
    }

    // -- BackupRecord --
    public static class BackupRecord {
        public final String name;
        public final String filePath;
        public final long expectedSize;
        public final String expectedHash;
        public final long registeredAt;
        public volatile long lastVerified;

        BackupRecord(String name, String filePath, long expectedSize, String expectedHash, long registeredAt) {
            this.name = name;
            this.filePath = filePath;
            this.expectedSize = expectedSize;
            this.expectedHash = expectedHash;
            this.registeredAt = registeredAt;
            this.lastVerified = 0L;
        }
    }

    // -- IntegrityResult --
    public static class IntegrityResult {
        private final boolean passed;
        private final boolean failed;
        private final boolean corrupted;
        private final boolean missing;
        private final List<String> reasons;

        private IntegrityResult(boolean passed, boolean failed, boolean corrupted, boolean missing, List<String> reasons) {
            this.passed = passed;
            this.failed = failed;
            this.corrupted = corrupted;
            this.missing = missing;
            this.reasons = reasons;
        }

        public static IntegrityResult passed() {
            return new IntegrityResult(true, false, false, false, List.of());
        }

        public static IntegrityResult failed(List<String> reasons) {
            return new IntegrityResult(false, true, false, false, reasons);
        }

        public static IntegrityResult corrupted(List<String> reasons) {
            return new IntegrityResult(false, false, true, false, reasons);
        }

        public static IntegrityResult missing() {
            return new IntegrityResult(false, false, false, true, List.of("Backup record not found"));
        }

        public boolean isPassed() { return passed; }
        public boolean isFailed() { return failed; }
        public boolean isCorrupted() { return corrupted; }
        public boolean isMissing() { return missing; }
        public List<String> getReasons() { return reasons; }
    }
}
