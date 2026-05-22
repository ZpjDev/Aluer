package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class ProcessInjectionDetectionService {

    private final ServerGuardConfig config;
    private final Map<Integer, ProcessSnapshot> processBaseline = new ConcurrentHashMap<>();
    private final Map<String, List<InjectionEvent>> detections = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong totalDetections = new AtomicLong(0);

    private static final Set<String> SUSPICIOUS_THREADS = Set.of(
            "ptrace", "process_vm_writev", "memfd_create",
            "dlopen", "dlsym", "mmap", "mprotect"
    );

    private static final Set<String> INJECTION_INDICATORS = Set.of(
            "/proc/self/mem", "/proc/self/maps", "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES", "gdb", "strace", "ltrace",
            "ollydbg", "x64dbg", "windbg"
    );

    public ProcessInjectionDetectionService() {
        this(new ServerGuardConfig());
    }

    public ProcessInjectionDetectionService(ServerGuardConfig config) {
        this.config = config;
        if (config.getSecurity().getSuperEvolution().isProcessInjection()) {
            captureBaseline();
            scheduler.scheduleAtFixedRate(this::scanProcesses, 60, 120, TimeUnit.SECONDS);
        }
    }

    public InjectionCheckResult scanProcesses() {
        if (!config.getSecurity().getSuperEvolution().isProcessInjection()) {
            return new InjectionCheckResult(List.of(), 0, totalDetections.get());
        }
        List<String> alerts = new ArrayList<>();
        Map<Integer, ProcessSnapshot> current = captureProcessSnapshots();

        for (Map.Entry<Integer, ProcessSnapshot> entry : current.entrySet()) {
            int pid = entry.getKey();
            ProcessSnapshot snapshot = entry.getValue();
            ProcessSnapshot baseline = processBaseline.get(pid);

            if (baseline != null) {
                // Check for new threads (possible injection)
                if (snapshot.threadCount > baseline.threadCount * 1.5 && snapshot.threadCount > 50) {
                    alerts.add("PID " + pid + " thread spike: " + baseline.threadCount + " -> " + snapshot.threadCount);
                }

                // Check for new memory mappings
                Set<String> newMappings = new HashSet<>(snapshot.memoryMaps);
                newMappings.removeAll(baseline.memoryMaps);
                for (String mapping : newMappings) {
                    for (String indicator : INJECTION_INDICATORS) {
                        if (mapping.toLowerCase().contains(indicator.toLowerCase())) {
                            alerts.add("PID " + pid + " suspicious mapping: " + mapping);
                        }
                    }
                }

                // Check for new open files
                Set<String> newFds = new HashSet<>(snapshot.openFds);
                newFds.removeAll(baseline.openFds);
                if (newFds.size() > 100) {
                    alerts.add("PID " + pid + " fd spike: +" + newFds.size());
                }
            }

            // Check for Minecraft-specific injection patterns
            if (snapshot.processName.toLowerCase().contains("java") && isMinecraftProcess(snapshot)) {
                for (String mapping : snapshot.memoryMaps) {
                    if (mapping.contains(".so") && !mapping.contains("/usr/lib") && !mapping.contains("/lib64")
                            && !mapping.contains("jdk") && !mapping.contains("jre")) {
                        alerts.add("PID " + pid + " non-standard native lib: " + mapping);
                    }
                }
            }
        }

        if (!alerts.isEmpty()) {
            InjectionEvent event = new InjectionEvent(Instant.now(), alerts);
            detections.computeIfAbsent("process", k -> new ArrayList<>()).add(event);
            totalDetections.addAndGet(alerts.size());
        }

        processBaseline.clear();
        processBaseline.putAll(current);

        return new InjectionCheckResult(alerts, current.size(), totalDetections.get());
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalDetections", totalDetections.get());
        status.put("trackedProcesses", processBaseline.size());
        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<InjectionEvent>> e : detections.entrySet()) {
            for (InjectionEvent event : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("alerts", event.alerts);
                m.put("time", event.timestamp.toString());
                recent.add(m);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentDetections", recent.subList(0, Math.min(recent.size(), 10)));
        return status;
    }

    public long getTotalDetections() { return totalDetections.get(); }

    private void captureBaseline() {
        processBaseline.putAll(captureProcessSnapshots());
    }

    private Map<Integer, ProcessSnapshot> captureProcessSnapshots() {
        Map<Integer, ProcessSnapshot> snapshots = new LinkedHashMap<>();
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ps -eo pid,comm,nlwp"});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                reader.readLine(); // skip header
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    String[] parts = line.trim().split("\\s+", 3);
                    if (parts.length >= 3) {
                        try {
                            int pid = Integer.parseInt(parts[0]);
                            String name = parts[1];
                            int threads = Integer.parseInt(parts[2]);
                            Set<String> maps = readProcMaps(pid);
                            Set<String> fds = readProcFds(pid);
                            snapshots.put(pid, new ProcessSnapshot(pid, name, threads, maps, fds));
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
        } catch (Exception ignored) {}
        return snapshots;
    }

    private Set<String> readProcMaps(int pid) {
        Set<String> maps = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(Runtime.getRuntime().exec(new String[]{"cat", "/proc/" + pid + "/maps"}).getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("/")) {
                    maps.add(line.substring(line.lastIndexOf('/')));
                }
            }
        } catch (Exception ignored) {}
        return maps;
    }

    private Set<String> readProcFds(int pid) {
        Set<String> fds = new HashSet<>();
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"ls", "/proc/" + pid + "/fd/"});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    fds.add(line.trim());
                }
            }
        } catch (Exception ignored) {}
        return fds;
    }

    private boolean isMinecraftProcess(ProcessSnapshot snapshot) {
        return snapshot.processName.contains("paper") || snapshot.processName.contains("spigot")
                || snapshot.processName.contains("bukkit") || snapshot.processName.contains("minecraft")
                || snapshot.processName.contains("serverguard") || snapshot.processName.contains("aluer");
    }

    private static class ProcessSnapshot {
        final int pid;
        final String processName;
        final int threadCount;
        final Set<String> memoryMaps;
        final Set<String> openFds;

        ProcessSnapshot(int pid, String processName, int threadCount, Set<String> memoryMaps, Set<String> openFds) {
            this.pid = pid;
            this.processName = processName;
            this.threadCount = threadCount;
            this.memoryMaps = memoryMaps;
            this.openFds = openFds;
        }
    }

    private static class InjectionEvent {
        final Instant timestamp;
        final List<String> alerts;

        InjectionEvent(Instant timestamp, List<String> alerts) {
            this.timestamp = timestamp;
            this.alerts = alerts;
        }
    }

    public static class InjectionCheckResult {
        private final List<String> alerts;
        private final int processCount;
        private final long totalDetections;

        InjectionCheckResult(List<String> alerts, int processCount, long totalDetections) {
            this.alerts = alerts;
            this.processCount = processCount;
            this.totalDetections = totalDetections;
        }

        public List<String> getAlerts() { return alerts; }
        public int getProcessCount() { return processCount; }
        public long getTotalDetections() { return totalDetections; }
        public boolean hasAlerts() { return !alerts.isEmpty(); }
    }
}
