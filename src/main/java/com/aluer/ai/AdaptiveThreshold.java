package com.aluer.ai;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.MetricsData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

@Component
public class AdaptiveThreshold {
    private static final Logger logger = LoggerFactory.getLogger(AdaptiveThreshold.class);
    
    private final ServerGuardConfig config;
    private final ConcurrentLinkedDeque<Double> tpsHistory = new ConcurrentLinkedDeque<>();
    private final ConcurrentLinkedDeque<Double> cpuHistory = new ConcurrentLinkedDeque<>();
    private final ConcurrentLinkedDeque<Double> memoryHistory = new ConcurrentLinkedDeque<>();
    
    private static final double K_MULTIPLIER = 2.0;

    public AdaptiveThreshold(ServerGuardConfig config) {
        this.config = config;
    }

    public void addMetric(MetricsData data) {
        tpsHistory.add(data.getTps());
        cpuHistory.add(data.getCpuUsage());
        memoryHistory.add(data.getMemoryUsage());
        
        int windowSize = config.getAi().getSlidingWindowSize();
        while (tpsHistory.size() > windowSize) tpsHistory.removeFirst();
        while (cpuHistory.size() > windowSize) cpuHistory.removeFirst();
        while (memoryHistory.size() > windowSize) memoryHistory.removeFirst();
    }

    public double getTpsThreshold() {
        if (tpsHistory.size() < 10) {
            return config.getMonitor().getTpsThreshold();
        }
        return calculateAdaptiveThreshold(tpsHistory);
    }

    public double getCpuThreshold() {
        if (cpuHistory.size() < 10) {
            return config.getMonitor().getCpuThreshold();
        }
        return calculateAdaptiveThreshold(cpuHistory);
    }

    public double getMemoryThreshold() {
        if (memoryHistory.size() < 10) {
            return config.getMonitor().getMemoryThreshold();
        }
        return calculateAdaptiveThreshold(memoryHistory);
    }

    private double calculateAdaptiveThreshold(Deque<Double> history) {
        List<Double> values = new ArrayList<>(history);
        double mean = values.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double stdDev = calculateStdDev(values, mean);
        double threshold = mean - (K_MULTIPLIER * stdDev);
        
        logger.debug("Adaptive threshold - mean: {}, stdDev: {}, threshold: {}", mean, stdDev, threshold);
        return threshold;
    }

    private double calculateStdDev(List<Double> values, double mean) {
        double variance = values.stream()
            .mapToDouble(v -> Math.pow(v - mean, 2))
            .average()
            .orElse(0);
        return Math.sqrt(variance);
    }

    public Map<String, Double> getCurrentStats() {
        Map<String, Double> stats = new HashMap<>();
        
        if (!tpsHistory.isEmpty()) {
            List<Double> tpsValues = new ArrayList<>(tpsHistory);
            stats.put("tpsMean", tpsValues.stream().mapToDouble(Double::doubleValue).average().orElse(0));
            stats.put("tpsStdDev", calculateStdDev(tpsValues, stats.get("tpsMean")));
        }
        
        if (!cpuHistory.isEmpty()) {
            List<Double> cpuValues = new ArrayList<>(cpuHistory);
            stats.put("cpuMean", cpuValues.stream().mapToDouble(Double::doubleValue).average().orElse(0));
            stats.put("cpuStdDev", calculateStdDev(cpuValues, stats.get("cpuMean")));
        }
        
        if (!memoryHistory.isEmpty()) {
            List<Double> memValues = new ArrayList<>(memoryHistory);
            stats.put("memoryMean", memValues.stream().mapToDouble(Double::doubleValue).average().orElse(0));
            stats.put("memoryStdDev", calculateStdDev(memValues, stats.get("memoryMean")));
        }
        
        return stats;
    }
}
