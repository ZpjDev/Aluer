package com.aluer.export;

import com.aluer.audit.SecurityAuditService;
import com.aluer.backup.BackupService;
import com.aluer.punishment.PunishmentService;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Component
public class DataExportService {
    private static final Logger logger = LoggerFactory.getLogger(DataExportService.class);
    
    private final PunishmentService punishmentService;
    private final SecurityAuditService auditService;
    private final BackupService backupService;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    
    public DataExportService(
            PunishmentService punishmentService,
            SecurityAuditService auditService,
            BackupService backupService) {
        this.punishmentService = punishmentService;
        this.auditService = auditService;
        this.backupService = backupService;
    }
    
    public String exportData(String format, String outputPath) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("generatedAt", LocalDateTime.now().toString());
            data.put("message", "Data export completed");
            
            String filename = generateFilename("export", format);
            String fullPath = outputPath != null ? outputPath : "/tmp/" + filename;
            
            writeToFile(fullPath, data);
            return "Exported to: " + fullPath;
        } catch (Exception e) {
            return "Export failed: " + e.getMessage();
        }
    }
    
    public String exportAuditLogs(String format, String outputPath) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("generatedAt", LocalDateTime.now().toString());
            data.put("auditLogs", "Audit log data");
            
            String filename = generateFilename("audit_logs", format);
            String fullPath = outputPath != null ? outputPath : "/tmp/" + filename;
            
            writeToFile(fullPath, data);
            return "Exported to: " + fullPath;
        } catch (Exception e) {
            return "Export failed: " + e.getMessage();
        }
    }
    
    public String exportBackupList(String format, String outputPath) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("generatedAt", LocalDateTime.now().toString());
            data.put("backups", "Backup list data");
            
            String filename = generateFilename("backups", format);
            String fullPath = outputPath != null ? outputPath : "/tmp/" + filename;
            
            writeToFile(fullPath, data);
            return "Exported to: " + fullPath;
        } catch (Exception e) {
            return "Export failed: " + e.getMessage();
        }
    }
    
    private String generateFilename(String prefix, String format) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        return prefix + "_" + timestamp + "." + format;
    }
    
    private void writeToFile(String path, Map<String, Object> data) throws IOException {
        Path filePath = Paths.get(path);
        Files.createDirectories(filePath.getParent());
        
        try (FileWriter writer = new FileWriter(path)) {
            gson.toJson(data, writer);
        }
    }
}
