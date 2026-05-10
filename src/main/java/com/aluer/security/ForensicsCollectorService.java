package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class ForensicsCollectorService {

    private final ServerGuardConfig config;
    private final Map<String, ForensicsCase> cases = new ConcurrentHashMap<>();
    private final Map<String, List<ForensicEvidence>> evidenceStore = new ConcurrentHashMap<>();
    private final AtomicLong totalEvidenceCollected = new AtomicLong(0);
    private final String evidenceDir = "./forensics";

    public ForensicsCollectorService() {
        this(new ServerGuardConfig());
    }

    public ForensicsCollectorService(ServerGuardConfig config) {
        this.config = config;
        try {
            Files.createDirectories(Path.of(evidenceDir));
        } catch (IOException ignored) {}
    }

    public ForensicsCase openCase(String caseName, String reason, String operator) {
        if (!config.getSecurity().getSuperEvolution().isForensics()) {
            ForensicsCase disabledCase = new ForensicsCase("forensics-module-disabled", caseName, reason, operator, Instant.now());
            disabledCase.conclusion = "forensics-module-disabled";
            disabledCase.closed = true;
            disabledCase.closeTime = Instant.now();
            return disabledCase;
        }
        String caseId = "CASE-" + Instant.now().getEpochSecond() + "-" + randomHex(6);
        ForensicsCase fCase = new ForensicsCase(caseId, caseName, reason, operator, Instant.now());
        cases.put(caseId, fCase);
        evidenceStore.put(caseId, new ArrayList<>());
        return fCase;
    }

    public ForensicEvidence collectProcessList(String caseId) {
        StringBuilder sb = new StringBuilder();
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ps aux"});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            }
        } catch (Exception e) {
            sb.append("ERROR: ").append(e.getMessage());
        }
        return addEvidence(caseId, "PROCESS_LIST", sb.toString());
    }

    public ForensicEvidence collectNetworkConnections(String caseId) {
        StringBuilder sb = new StringBuilder();
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null"});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            }
        } catch (Exception e) {
            sb.append("ERROR: ").append(e.getMessage());
        }
        return addEvidence(caseId, "NETWORK_CONNECTIONS", sb.toString());
    }

    public ForensicEvidence collectOpenFiles(String caseId) {
        StringBuilder sb = new StringBuilder();
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", "lsof -nP 2>/dev/null | head -500"});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            }
        } catch (Exception e) {
            sb.append("ERROR: ").append(e.getMessage());
        }
        return addEvidence(caseId, "OPEN_FILES", sb.toString());
    }

    public ForensicEvidence collectSystemLogs(String caseId) {
        StringBuilder sb = new StringBuilder();
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", "journalctl -n 200 --no-pager 2>/dev/null || dmesg | tail -200"});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            }
        } catch (Exception e) {
            sb.append("ERROR: ").append(e.getMessage());
        }
        return addEvidence(caseId, "SYSTEM_LOGS", sb.toString());
    }

    public ForensicEvidence collectMCPServerLogs(String caseId, String mcLogPath) {
        if (mcLogPath == null) mcLogPath = "/opt/minecraft/logs/latest.log";
        try {
            String content = Files.readString(Path.of(mcLogPath));
            return addEvidence(caseId, "MC_SERVER_LOG", content);
        } catch (Exception e) {
            return addEvidence(caseId, "MC_SERVER_LOG", "ERROR: " + e.getMessage());
        }
    }

    public ForensicEvidence collectTimestampSnapshot(String caseId) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("systemTime", Instant.now().toString());
        snapshot.put("uptime", System.getProperty("os.name"));
        snapshot.put("javaVersion", System.getProperty("java.version"));
        snapshot.put("availableProcessors", Runtime.getRuntime().availableProcessors());
        snapshot.put("freeMemory", Runtime.getRuntime().freeMemory());
        snapshot.put("totalMemory", Runtime.getRuntime().totalMemory());
        return addEvidence(caseId, "TIMESTAMP_SNAPSHOT", snapshot.toString());
    }

    public ForensicsCase closeCase(String caseId, String conclusion, String operator) {
        ForensicsCase fCase = cases.get(caseId);
        if (fCase != null) {
            fCase.close(conclusion, operator);
            saveCaseToDisk(fCase);
        }
        return fCase;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("openCases", cases.values().stream().filter(c -> !c.closed).count());
        status.put("totalCases", cases.size());
        status.put("totalEvidence", totalEvidenceCollected.get());
        List<Map<String, Object>> caseList = new ArrayList<>();
        for (ForensicsCase c : cases.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", c.caseId);
            m.put("name", c.caseName);
            m.put("reason", c.reason);
            m.put("openTime", c.openTime.toString());
            m.put("closed", c.closed);
            m.put("evidenceCount", evidenceStore.getOrDefault(c.caseId, List.of()).size());
            caseList.add(m);
        }
        caseList.sort((a, b) -> b.get("openTime").toString().compareTo(a.get("openTime").toString()));
        status.put("cases", caseList);
        return status;
    }

    public long getTotalEvidence() { return totalEvidenceCollected.get(); }

    private ForensicEvidence addEvidence(String caseId, String type, String content) {
        ForensicEvidence evidence = new ForensicEvidence(caseId, type, content, Instant.now());
        evidenceStore.computeIfAbsent(caseId, k -> new ArrayList<>()).add(evidence);
        totalEvidenceCollected.incrementAndGet();
        return evidence;
    }

    private void saveCaseToDisk(ForensicsCase fCase) {
        try {
            Path caseDir = Path.of(evidenceDir, fCase.caseId);
            Files.createDirectories(caseDir);
            StringBuilder report = new StringBuilder();
            report.append("=== FORENSICS CASE REPORT ===\n");
            report.append("Case ID: ").append(fCase.caseId).append('\n');
            report.append("Name: ").append(fCase.caseName).append('\n');
            report.append("Reason: ").append(fCase.reason).append('\n');
            report.append("Operator: ").append(fCase.operator).append('\n');
            report.append("Opened: ").append(fCase.openTime).append('\n');
            report.append("Closed: ").append(fCase.closeTime).append('\n');
            report.append("Conclusion: ").append(fCase.conclusion).append('\n');
            report.append("\n--- EVIDENCE ---\n\n");
            List<ForensicEvidence> items = evidenceStore.getOrDefault(fCase.caseId, List.of());
            for (ForensicEvidence e : items) {
                report.append("[").append(e.type).append("] ").append(e.timestamp).append('\n');
                report.append(e.content).append("\n---\n\n");
            }
            Files.writeString(caseDir.resolve("report.txt"), report.toString());
        } catch (IOException ignored) {}
    }

    private String randomHex(int len) {
        byte[] bytes = new byte[len];
        new Random().nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString().substring(0, len);
    }

    public static class ForensicsCase {
        public final String caseId;
        public final String caseName;
        public final String reason;
        public final String operator;
        public final Instant openTime;
        public Instant closeTime;
        public String conclusion;
        public boolean closed;

        ForensicsCase(String caseId, String caseName, String reason, String operator, Instant openTime) {
            this.caseId = caseId;
            this.caseName = caseName;
            this.reason = reason;
            this.operator = operator;
            this.openTime = openTime;
        }

        void close(String conclusion, String operator) {
            this.conclusion = conclusion;
            this.closeTime = Instant.now();
            this.closed = true;
        }
    }

    public static class ForensicEvidence {
        public final String caseId;
        public final String type;
        public final String content;
        public final Instant timestamp;

        ForensicEvidence(String caseId, String type, String content, Instant timestamp) {
            this.caseId = caseId;
            this.type = type;
            this.content = content;
            this.timestamp = timestamp;
        }
    }
}
