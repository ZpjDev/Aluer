package com.aluer.backup;

import com.aluer.config.ServerGuardConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;

@Component
public class BackupService {
    private static final Logger logger = LoggerFactory.getLogger(BackupService.class);

    private final ServerGuardConfig config;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    private final Map<String, BackupHistory> backupHistory = new ConcurrentHashMap<>();
    private final BlockingQueue<BackupTask> backupQueue = new LinkedBlockingQueue<>();
    private volatile boolean backupRunning = false;
    
    public BackupService(ServerGuardConfig config) {
        this.config = config;
    }
    
    public void startScheduledBackups() {
        if (!config.getBackup().isEnabled()) {
            logger.info("备份服务已禁用");
            return;
        }
        
        int intervalHours = config.getBackup().getIntervalHours();
        scheduler.scheduleAtFixedRate(this::performScheduledBackup, 
            intervalHours, intervalHours, TimeUnit.HOURS);
        
        logger.info("Scheduled backup started, interval: {} hours", intervalHours);
    }
    
    public BackupResult performBackup(String name) {
        long startTime = System.currentTimeMillis();
        BackupResult result = new BackupResult();
        result.setName(name);
        result.setStartTime(LocalDateTime.now());
        
        try {
            String backupDir = config.getBackup().getBackupDir();
            String worldDir = config.getBackup().getWorldDir();
            
            Path backupPath = Paths.get(backupDir, name);
            Files.createDirectories(backupPath);
            
            List<String> worlds = getWorlds(worldDir);
            
            for (String world : worlds) {
                result.addWorld(world);
                long worldStart = System.currentTimeMillis();
                
                String worldBackupPath = backupPath.resolve(world).toString();
                boolean success = compressWorld(Paths.get(worldDir, world), Paths.get(worldBackupPath));
                
                result.setWorldResult(world, success, System.currentTimeMillis() - worldStart);
            }
            
            if (config.getBackup().isBackupPlugins()) {
                long pluginStart = System.currentTimeMillis();
                String pluginBackupPath = backupPath.resolve("plugins").toString();
                compressDirectory(Paths.get(config.getBackup().getPluginDir()), Paths.get(pluginBackupPath));
                result.setPluginBackupTime(System.currentTimeMillis() - pluginStart);
            }
            
            if (config.getBackup().isBackupConfig()) {
                long configStart = System.currentTimeMillis();
                String configBackupPath = backupPath.resolve("config").toString();
                compressDirectory(Paths.get(config.getBackup().getConfigDir()), Paths.get(configBackupPath));
                result.setConfigBackupTime(System.currentTimeMillis() - configStart);
            }
            
            cleanupOldBackups();
            
            result.setSuccess(true);
            result.setTotalTime(System.currentTimeMillis() - startTime);
            result.setBackupPath(backupPath.toString());
            
            saveBackupHistory(result);
            
            logger.info("Backup '{}' completed in {}ms", name, result.getTotalTime());
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setError(e.getMessage());
            logger.error("Backup failed: {}", e.getMessage());
        }
        
        return result;
    }
    
    public BackupResult performScheduledBackup() {
        String name = "auto_" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        return performBackup(name);
    }
    
    private List<String> getWorlds(String worldDir) {
        List<String> worlds = new ArrayList<>();
        Path dir = Paths.get(worldDir);
        
        if (!Files.exists(dir)) {
            return worlds;
        }
        
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path path : stream) {
                if (Files.isDirectory(path) && Files.exists(path.resolve("level.dat"))) {
                    worlds.add(path.getFileName().toString());
                }
            }
        } catch (IOException e) {
            logger.error("Failed to list worlds: {}", e.getMessage());
        }
        
        return worlds;
    }
    
    private boolean compressWorld(Path source, Path target) {
        try {
            if (Files.exists(target)) {
                deleteDirectory(target);
            }
            Files.createDirectories(target);
            
            Files.walk(source)
                .filter(path -> !Files.isDirectory(path))
                .forEach(path -> {
                    try {
                        Path relativePath = source.relativize(path);
                        Path destPath = target.resolve(relativePath);
                        Files.createDirectories(destPath.getParent());
                        Files.copy(path, destPath);
                    } catch (IOException e) {
                        logger.error("Failed to copy {}: {}", path, e.getMessage());
                    }
                });
            
            return true;
        } catch (Exception e) {
            logger.error("Failed to compress world {}: {}", source, e.getMessage());
            return false;
        }
    }
    
    private void compressDirectory(Path source, Path target) {
        try {
            if (!Files.exists(source)) {
                return;
            }
            
            if (Files.exists(target)) {
                deleteDirectory(target);
            }
            Files.createDirectories(target);
            
            Files.walk(source)
                .filter(path -> !Files.isDirectory(path))
                .filter(path -> !path.toString().endsWith(".lock"))
                .forEach(path -> {
                    try {
                        Path relativePath = source.relativize(path);
                        Path destPath = target.resolve(relativePath);
                        Files.createDirectories(destPath.getParent());
                        Files.copy(path, destPath);
                    } catch (IOException e) {
                        logger.debug("Failed to copy {}: {}", path, e.getMessage());
                    }
                });
        } catch (Exception e) {
            logger.error("Failed to backup directory {}: {}", source, e.getMessage());
        }
    }
    
    private void cleanupOldBackups() {
        int maxBackups = config.getBackup().getMaxBackups();
        
        Path backupDir = Paths.get(config.getBackup().getBackupDir());
        if (!Files.exists(backupDir)) {
            return;
        }
        
        try {
            List<Path> backups = new ArrayList<>();
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(backupDir)) {
                for (Path path : stream) {
                    if (Files.isDirectory(path)) {
                        backups.add(path);
                    }
                }
            }
            
            backups.sort((a, b) -> {
                try {
                    return Files.getLastModifiedTime(b).compareTo(Files.getLastModifiedTime(a));
                } catch (IOException e) {
                    return 0;
                }
            });
            
            for (int i = maxBackups; i < backups.size(); i++) {
                deleteDirectory(backups.get(i));
                logger.info("Deleted old backup: {}", backups.get(i).getFileName());
            }
        } catch (IOException e) {
            logger.error("Failed to cleanup backups: {}", e.getMessage());
        }
    }
    
    private void deleteDirectory(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        
        Files.walk(path)
            .sorted(Comparator.reverseOrder())
            .forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    logger.debug("Failed to delete {}: {}", p, e.getMessage());
                }
            });
    }
    
    private void saveBackupHistory(BackupResult result) {
        backupHistory.put(result.getName(), new BackupHistory(result));
    }
    
    public List<BackupHistory> getBackupHistory() {
        return new ArrayList<>(backupHistory.values());
    }
    
    public BackupResult restoreBackup(String backupName) {
        BackupResult result = new BackupResult();
        result.setName(backupName);
        
        try {
            Path backupPath = Paths.get(config.getBackup().getBackupDir(), backupName);
            String worldDir = config.getBackup().getWorldDir();
            
            List<String> worlds = getWorlds(backupPath.toString());
            
            for (String world : worlds) {
                Path source = backupPath.resolve(world);
                Path target = Paths.get(worldDir, world);
                
                if (Files.exists(target)) {
                    deleteDirectory(target);
                }
                
                copyDirectory(source, target);
                result.addWorld(world);
            }
            
            result.setSuccess(true);
            logger.info("Restore completed: {}", backupName);
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setError(e.getMessage());
            logger.error("Restore failed: {}", e.getMessage());
        }
        
        return result;
    }
    
    private void copyDirectory(Path source, Path target) throws IOException {
        Files.walk(source).forEach(sourcePath -> {
            try {
                Path targetPath = target.resolve(source.relativize(sourcePath));
                if (Files.isDirectory(sourcePath)) {
                    Files.createDirectories(targetPath);
                } else {
                    Files.copy(sourcePath, targetPath);
                }
            } catch (IOException e) {
                logger.error("Failed to copy {}: {}", sourcePath, e.getMessage());
            }
        });
    }
    
    public static class BackupResult {
        private String name;
        private boolean success;
        private String error;
        private LocalDateTime startTime;
        private long totalTime;
        private String backupPath;
        private Map<String, Boolean> worlds = new HashMap<>();
        private Map<String, Long> worldTimes = new HashMap<>();
        private long pluginBackupTime;
        private long configBackupTime;
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }
        public long getTotalTime() { return totalTime; }
        public void setTotalTime(long totalTime) { this.totalTime = totalTime; }
        public String getBackupPath() { return backupPath; }
        public void setBackupPath(String backupPath) { this.backupPath = backupPath; }
        public Map<String, Boolean> getWorlds() { return worlds; }
        public void addWorld(String world) { this.worlds.put(world, false); }
        public void setWorldResult(String world, boolean success, long time) { 
            this.worlds.put(world, success); 
            this.worldTimes.put(world, time);
        }
        public Map<String, Long> getWorldTimes() { return worldTimes; }
        public long getPluginBackupTime() { return pluginBackupTime; }
        public void setPluginBackupTime(long pluginBackupTime) { this.pluginBackupTime = pluginBackupTime; }
        public long getConfigBackupTime() { return configBackupTime; }
        public void setConfigBackupTime(long configBackupTime) { this.configBackupTime = configBackupTime; }
    }
    
    public static class BackupHistory {
        private final String name;
        private final LocalDateTime time;
        private final boolean success;
        private final long size;
        
        public BackupHistory(BackupResult result) {
            this.name = result.getName();
            this.time = result.getStartTime();
            this.success = result.isSuccess();
            this.size = calculateSize(result.getBackupPath());
        }
        
        private long calculateSize(String path) {
            try {
                Path p = Paths.get(path);
                return Files.walk(p)
                    .filter(Files::isRegularFile)
                    .mapToLong(p1 -> {
                        try { return Files.size(p1); } catch (IOException e) { return 0L; }
                    })
                    .sum();
            } catch (Exception e) {
                return 0L;
            }
        }
        
        public String getName() { return name; }
        public LocalDateTime getTime() { return time; }
        public boolean isSuccess() { return success; }
        public long getSize() { return size; }
    }
    
    public static class BackupTask {
        private final String name;
        private final BackupType type;
        private final LocalDateTime scheduledTime;
        private volatile boolean cancelled = false;
        
        public BackupTask(String name, BackupType type) {
            this.name = name;
            this.type = type;
            this.scheduledTime = LocalDateTime.now();
        }
        
        public String getName() { return name; }
        public BackupType getType() { return type; }
        public LocalDateTime getScheduledTime() { return scheduledTime; }
        public boolean isCancelled() { return cancelled; }
        public void cancel() { this.cancelled = true; }
    }
    
    public enum BackupType {
        FULL,
        INCREMENTAL,
        WORLD_ONLY,
        CONFIG_ONLY
    }

    public boolean isBackupRunning() {
        return backupRunning;
    }

    public void shutdown() {
        scheduler.shutdown();
    }
}
