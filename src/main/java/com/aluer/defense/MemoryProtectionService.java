package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class MemoryProtectionService {

    private final ServerGuardConfig config;
    private final MemoryMXBean memoryMXBean = ManagementFactory.getMemoryMXBean();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final Map<String, List<MemoryAlert>> alerts = new ConcurrentHashMap<>();
    private final AtomicLong totalAlerts = new AtomicLong(0);

    private static final double HEAP_THRESHOLD = 0.85;
    private static final double NON_HEAP_THRESHOLD = 0.90;
    private static final double GC_OVERHEAD_THRESHOLD = 0.15;
    private static final long MEMORY_CHECK_INTERVAL_SECONDS = 30;

    private long lastGcCount;
    private long lastGcTime;

    public MemoryProtectionService() {
        this(new ServerGuardConfig());
    }

    public MemoryProtectionService(ServerGuardConfig config) {
        this.config = config;
        lastGcCount = ManagementFactory.getGarbageCollectorMXBeans().stream()
                .mapToLong(gc -> gc.getCollectionCount()).sum();
        lastGcTime = ManagementFactory.getGarbageCollectorMXBeans().stream()
                .mapToLong(gc -> gc.getCollectionTime()).sum();
        if (config.getSecurity().getSuperEvolution().isMemoryProtection()) {
            scheduler.scheduleAtFixedRate(this::checkMemory, MEMORY_CHECK_INTERVAL_SECONDS,
                    MEMORY_CHECK_INTERVAL_SECONDS, TimeUnit.SECONDS);
        }
    }

    public MemoryCheckResult checkMemory() {
        if (!config.getSecurity().getSuperEvolution().isMemoryProtection()) {
            return new MemoryCheckResult(0, 0, 0, 0, 0, 0, List.of());
        }
        List<String> warnings = new ArrayList<>();

        MemoryUsage heap = memoryMXBean.getHeapMemoryUsage();
        double heapRatio = (double) heap.getUsed() / heap.getMax();
        if (heapRatio > HEAP_THRESHOLD) {
            warnings.add("HEAP_HIGH: " + String.format("%.1f%%", heapRatio * 100));
            MemoryAlert alert = new MemoryAlert(Instant.now(), "HEAP_HIGH",
                    String.format("Heap at %.1f%% (used=%dMB, max=%dMB)", heapRatio * 100,
                            heap.getUsed() / 1024 / 1024, heap.getMax() / 1024 / 1024));
            alerts.computeIfAbsent("heap", k -> new ArrayList<>()).add(alert);
            totalAlerts.incrementAndGet();
        }

        MemoryUsage nonHeap = memoryMXBean.getNonHeapMemoryUsage();
        double nonHeapRatio = (double) nonHeap.getUsed() / nonHeap.getMax();
        if (nonHeapRatio > NON_HEAP_THRESHOLD) {
            warnings.add("NON_HEAP_HIGH: " + String.format("%.1f%%", nonHeapRatio * 100));
        }

        long currentGcCount = ManagementFactory.getGarbageCollectorMXBeans().stream()
                .mapToLong(gc -> gc.getCollectionCount()).sum();
        long currentGcTime = ManagementFactory.getGarbageCollectorMXBeans().stream()
                .mapToLong(gc -> gc.getCollectionTime()).sum();
        long gcCountDiff = currentGcCount - lastGcCount;
        long gcTimeDiff = currentGcTime - lastGcTime;

        if (gcTimeDiff > MEMORY_CHECK_INTERVAL_SECONDS * 1000 * GC_OVERHEAD_THRESHOLD) {
            warnings.add("GC_OVERHEAD: " + gcTimeDiff + "ms spent in GC");
            MemoryAlert alert = new MemoryAlert(Instant.now(), "GC_OVERHEAD",
                    String.format("GC overhead: %dms (%d collections)", gcTimeDiff, gcCountDiff));
            alerts.computeIfAbsent("gc", k -> new ArrayList<>()).add(alert);
            totalAlerts.incrementAndGet();
        }
        lastGcCount = currentGcCount;
        lastGcTime = currentGcTime;

        // Check for memory leak patterns (steady increase without decrease)
        String leakPattern = detectLeakPattern();
        if (leakPattern != null) {
            warnings.add("MEMORY_LEAK: " + leakPattern);
        }

        return new MemoryCheckResult(
                heapRatio, nonHeapRatio, heap.getUsed() / 1024 / 1024,
                heap.getMax() / 1024 / 1024, gcCountDiff, gcTimeDiff, warnings);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        MemoryUsage heap = memoryMXBean.getHeapMemoryUsage();
        status.put("heapUsedMB", heap.getUsed() / 1024 / 1024);
        status.put("heapMaxMB", heap.getMax() / 1024 / 1024);
        status.put("heapRatio", String.format("%.1f%%", (double) heap.getUsed() / heap.getMax() * 100));
        status.put("nonHeapUsedMB", memoryMXBean.getNonHeapMemoryUsage().getUsed() / 1024 / 1024);
        status.put("totalAlerts", totalAlerts.get());
        status.put("leakDetected", detectLeakPattern() != null);
        return status;
    }

    public long getTotalAlerts() { return totalAlerts.get(); }

    public void forceGC() {
        System.gc();
    }

    private String detectLeakPattern() {
        List<MemoryAlert> heapAlerts = alerts.get("heap");
        if (heapAlerts == null || heapAlerts.size() < 5) return null;
        boolean trending = true;
        double prev = 0;
        int consecutive = 0;
        for (int i = Math.max(0, heapAlerts.size() - 10); i < heapAlerts.size(); i++) {
            double current = extractHeapPercent(heapAlerts.get(i).message);
            if (current >= prev) consecutive++;
            else consecutive = 0;
            if (consecutive >= 5) return "Heap usage consistently increasing over 5+ checks";
            prev = current;
        }
        return null;
    }

    private double extractHeapPercent(String message) {
        try {
            String pct = message.replaceAll(".*?(\\d+\\.?\\d*)%.*", "$1");
            return Double.parseDouble(pct);
        } catch (Exception e) {
            return 0;
        }
    }

    private static class MemoryAlert {
        final Instant timestamp;
        final String type;
        final String message;

        MemoryAlert(Instant timestamp, String type, String message) {
            this.timestamp = timestamp;
            this.type = type;
            this.message = message;
        }
    }

    public static class MemoryCheckResult {
        private final double heapRatio;
        private final double nonHeapRatio;
        private final long heapUsedMB;
        private final long heapMaxMB;
        private final long gcCount;
        private final long gcTimeMs;
        private final List<String> warnings;

        MemoryCheckResult(double heapRatio, double nonHeapRatio, long heapUsedMB, long heapMaxMB,
                          long gcCount, long gcTimeMs, List<String> warnings) {
            this.heapRatio = heapRatio;
            this.nonHeapRatio = nonHeapRatio;
            this.heapUsedMB = heapUsedMB;
            this.heapMaxMB = heapMaxMB;
            this.gcCount = gcCount;
            this.gcTimeMs = gcTimeMs;
            this.warnings = warnings;
        }

        public double getHeapRatio() { return heapRatio; }
        public long getHeapUsedMB() { return heapUsedMB; }
        public long getHeapMaxMB() { return heapMaxMB; }
        public long getGcTimeMs() { return gcTimeMs; }
        public List<String> getWarnings() { return warnings; }
        public boolean hasWarnings() { return !warnings.isEmpty(); }
    }
}
