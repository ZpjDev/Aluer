package com.aluer.security;

import org.springframework.stereotype.Service;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class SecureFileDeletionService {

    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, DeletionRecord> deletionLog = new ConcurrentHashMap<>();
    private final AtomicLong totalFilesDeleted = new AtomicLong(0);
    private final AtomicLong totalBytesWiped = new AtomicLong(0);

    private static final int DEFAULT_PASSES = 3;
    private static final int MAX_PASSES = 7;
    private static final int BUFFER_SIZE = 8192;

    public DeletionResult secureDelete(String filePath, int passes) {
        File file = new File(filePath);
        if (!file.exists()) {
            return DeletionResult.error("File does not exist: " + filePath);
        }
        if (!file.isFile()) {
            return DeletionResult.error("Not a file: " + filePath);
        }
        if (!file.canWrite()) {
            return DeletionResult.error("File not writable: " + filePath);
        }

        int effectivePasses = Math.min(Math.max(passes, 1), MAX_PASSES);
        long fileSize = file.length();
        long bytesWritten = 0;

        try {
            for (int pass = 0; pass < effectivePasses; pass++) {
                try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
                    long remaining = fileSize;
                    byte[] buffer = new byte[BUFFER_SIZE];

                    while (remaining > 0) {
                        int writeSize = (int) Math.min(remaining, BUFFER_SIZE);
                        // Pass 0: zero-fill, Pass 1: random, Pass 2+: alternating patterns
                        if (pass == 0) {
                            Arrays.fill(buffer, 0, writeSize, (byte) 0);
                        } else if (pass == 1) {
                            secureRandom.nextBytes(buffer);
                        } else if (pass % 2 == 0) {
                            Arrays.fill(buffer, 0, writeSize, (byte) 0xFF);
                        } else {
                            Arrays.fill(buffer, 0, writeSize, (byte) 0xAA);
                        }
                        raf.write(buffer, 0, writeSize);
                        remaining -= writeSize;
                        bytesWritten += writeSize;
                    }
                }
                // Sync to disk
                try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
                    raf.getFD().sync();
                }
            }

            // Truncate to 0 before deleting
            try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
                raf.setLength(0);
            }

            // Delete the file
            if (!file.delete()) {
                file.deleteOnExit();
                return DeletionResult.warning("File wiped but could not be immediately deleted: " + filePath);
            }

            DeletionRecord record = new DeletionRecord(filePath, fileSize, effectivePasses, Instant.now());
            deletionLog.put(filePath, record);
            totalFilesDeleted.incrementAndGet();
            totalBytesWiped.addAndGet(bytesWritten);

            return DeletionResult.success(filePath, fileSize, effectivePasses);

        } catch (Exception e) {
            return DeletionResult.error("Secure deletion failed: " + e.getMessage());
        }
    }

    public DeletionResult secureDelete(String filePath) {
        return secureDelete(filePath, DEFAULT_PASSES);
    }

    public DeletionResult secureDeleteDirectory(String dirPath, int passes) {
        File dir = new File(dirPath);
        if (!dir.exists() || !dir.isDirectory()) {
            return DeletionResult.error("Not a directory: " + dirPath);
        }

        List<String> failedFiles = new ArrayList<>();
        long totalSize = 0;
        int count = 0;

        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    DeletionResult subResult = secureDeleteDirectory(file.getAbsolutePath(), passes);
                    count += subResult.filesDeleted;
                    totalSize += subResult.bytesWiped;
                    failedFiles.addAll(subResult.failedFiles);
                } else {
                    DeletionResult result = secureDelete(file.getAbsolutePath(), passes);
                    if (result.success) {
                        count++;
                        totalSize += result.bytesWiped;
                    } else {
                        failedFiles.add(file.getAbsolutePath());
                    }
                }
            }
        }

        dir.delete();

        return new DeletionResult(true, count, totalSize, dirPath, failedFiles, null);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalFilesDeleted", totalFilesDeleted.get());
        status.put("totalBytesWiped", totalBytesWiped.get());
        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, DeletionRecord> e : deletionLog.entrySet()) {
            DeletionRecord r = e.getValue();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("path", r.path);
            m.put("size", r.fileSize);
            m.put("passes", r.passes);
            m.put("time", r.timestamp.toString());
            recent.add(m);
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentDeletions", recent.subList(0, Math.min(recent.size(), 20)));
        return status;
    }

    public long getTotalFilesDeleted() { return totalFilesDeleted.get(); }
    public long getTotalBytesWiped() { return totalBytesWiped.get(); }

    private static class DeletionRecord {
        final String path;
        final long fileSize;
        final int passes;
        final Instant timestamp;

        DeletionRecord(String path, long fileSize, int passes, Instant timestamp) {
            this.path = path;
            this.fileSize = fileSize;
            this.passes = passes;
            this.timestamp = timestamp;
        }
    }

    public static class DeletionResult {
        private final boolean success;
        private final int filesDeleted;
        private final long bytesWiped;
        private final String path;
        private final List<String> failedFiles;
        private final String error;

        DeletionResult(boolean success, int filesDeleted, long bytesWiped, String path,
                       List<String> failedFiles, String error) {
            this.success = success;
            this.filesDeleted = filesDeleted;
            this.bytesWiped = bytesWiped;
            this.path = path;
            this.failedFiles = failedFiles != null ? failedFiles : List.of();
            this.error = error;
        }

        public static DeletionResult success(String path, long size, int passes) {
            return new DeletionResult(true, 1, size, path, List.of(), null);
        }

        public static DeletionResult error(String error) {
            return new DeletionResult(false, 0, 0, null, List.of(), error);
        }

        public static DeletionResult warning(String warning) {
            return new DeletionResult(true, 1, 0, null, List.of(), warning);
        }

        public boolean isSuccess() { return success; }
        public int getFilesDeleted() { return filesDeleted; }
        public long getBytesWiped() { return bytesWiped; }
        public String getPath() { return path; }
        public List<String> getFailedFiles() { return failedFiles; }
        public String getError() { return error; }
    }
}
