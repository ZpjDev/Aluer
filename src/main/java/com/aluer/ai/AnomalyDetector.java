package com.aluer.ai;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import com.aluer.model.MetricsData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

@Component
public class AnomalyDetector {
    private static final Logger logger = LoggerFactory.getLogger(AnomalyDetector.class);
    
    private final ServerGuardConfig config;
    private final ConcurrentLinkedDeque<double[]> metricsBuffer = new ConcurrentLinkedDeque<>();
    private boolean isModelTrained = false;
    
    private static final int MIN_SAMPLES = 50;
    private static final double DEFAULT_THRESHOLD = 0.7;
    private List<double[]> normalPatterns = new ArrayList<>();

    public AnomalyDetector(ServerGuardConfig config) {
        this.config = config;
    }

    public void addMetric(MetricsData data) {
        metricsBuffer.add(data.toArray());
        
        int windowSize = config.getAi().getSlidingWindowSize() * 2;
        while (metricsBuffer.size() > windowSize) {
            metricsBuffer.removeFirst();
        }
        
        if (metricsBuffer.size() >= MIN_SAMPLES && !isModelTrained) {
            analyzePatterns();
        }
    }

    private void analyzePatterns() {
        try {
            List<double[]> allData = new ArrayList<>(metricsBuffer);
            
            if (allData.size() < MIN_SAMPLES) {
                return;
            }
            
            double[] means = new double[6];
            double[] stds = new double[6];
            
            for (int j = 0; j < 6; j++) {
                double sum = 0;
                for (double[] d : allData) {
                    sum += d[j];
                }
                means[j] = sum / allData.size();
                
                double varSum = 0;
                for (double[] d : allData) {
                    varSum += Math.pow(d[j] - means[j], 2);
                }
                stds[j] = Math.sqrt(varSum / allData.size());
            }
            
            List<double[]> normalized = new ArrayList<>();
            for (double[] d : allData) {
                double[] nd = new double[6];
                for (int j = 0; j < 6; j++) {
                    nd[j] = stds[j] > 0 ? (d[j] - means[j]) / stds[j] : 0;
                }
                normalized.add(nd);
            }
            
            double totalDistance = 0;
            for (double[] nd : normalized) {
                double dist = 0;
                for (int j = 0; j < 6; j++) {
                    dist += nd[j] * nd[j];
                }
                totalDistance += Math.sqrt(dist);
            }
            double avgDistance = totalDistance / normalized.size();
            
            normalPatterns.clear();
            for (int i = 0; i < normalized.size(); i++) {
                double dist = 0;
                for (int j = 0; j < 6; j++) {
                    dist += normalized.get(i)[j] * normalized.get(i)[j];
                }
                if (Math.sqrt(dist) < avgDistance * 1.5) {
                    normalPatterns.add(allData.get(i));
                }
            }
            
            isModelTrained = true;
            logger.info("Anomaly detection pattern analysis complete. Normal patterns: {}", normalPatterns.size());
            
        } catch (Exception e) {
            logger.error("Failed to analyze patterns: {}", e.getMessage());
        }
    }

    public AlertEvent detectAnomaly(MetricsData data) {
        if (!isModelTrained || normalPatterns.isEmpty()) {
            return null;
        }
        
        try {
            double anomalyScore = calculateAnomalyScore(data.toArray());
            double threshold = config.getAi().getAnomalyThreshold();
            
            if (anomalyScore > threshold) {
                AlertEvent alert = new AlertEvent(AlertType.AI_ANOMALY, 
                    String.format("AI detected anomaly with confidence %.2f%%", anomalyScore * 100));
                alert.setConfidence(anomalyScore);
                alert.setRootCause(determineRootCause(data));
                alert.setSuggestedAction(suggestAction(data));
                return alert;
            }
        } catch (Exception e) {
            logger.debug("Anomaly detection error: {}", e.getMessage());
        }
        
        return null;
    }

    private double calculateAnomalyScore(double[] current) {
        if (normalPatterns.isEmpty()) {
            return 0.0;
        }
        
        double[] means = new double[6];
        double[] stds = new double[6];
        
        for (int j = 0; j < 6; j++) {
            double sum = 0;
            for (double[] p : normalPatterns) {
                sum += p[j];
            }
            means[j] = sum / normalPatterns.size();
            
            double varSum = 0;
            for (double[] p : normalPatterns) {
                varSum += Math.pow(p[j] - means[j], 2);
            }
            stds[j] = Math.sqrt(varSum / normalPatterns.size());
        }
        
        double[] normalized = new double[6];
        for (int j = 0; j < 6; j++) {
            normalized[j] = stds[j] > 0 ? (current[j] - means[j]) / stds[j] : 0;
        }
        
        double distance = 0;
        for (int j = 0; j < 6; j++) {
            distance += normalized[j] * normalized[j];
        }
        distance = Math.sqrt(distance);
        
        double avgNormalDist = 0;
        for (double[] p : normalPatterns) {
            double[] np = new double[6];
            for (int j = 0; j < 6; j++) {
                np[j] = stds[j] > 0 ? (p[j] - means[j]) / stds[j] : 0;
            }
            double d = 0;
            for (int j = 0; j < 6; j++) {
                d += np[j] * np[j];
            }
            avgNormalDist += Math.sqrt(d);
        }
        avgNormalDist /= normalPatterns.size();
        
        double score = Math.min(1.0, distance / (avgNormalDist * 2));
        
        return score;
    }

    private String determineRootCause(MetricsData data) {
        List<String> causes = new ArrayList<>();
        
        if (data.getTps() < 15) causes.add("Low TPS");
        if (data.getCpuUsage() > 80) causes.add("High CPU");
        if (data.getMemoryUsage() > 85) causes.add("Memory pressure");
        if (data.getConnections() > 50) causes.add("Connection flood");
        if (data.getTickTime() > 50) causes.add("Server lag");
        
        if (causes.isEmpty()) {
            return "Unknown - abnormal metric pattern";
        }
        
        return String.join(" + ", causes);
    }

    private String suggestAction(MetricsData data) {
        if (data.getConnections() > 50) {
            return "Consider enabling connection rate limiting and blocking suspicious IPs";
        }
        if (data.getMemoryUsage() > 85) {
            return "Consider increasing JVM heap size or optimizing server performance";
        }
        if (data.getTps() < 15) {
            return "Consider reducing world load, limiting entities, or disabling chunk generation";
        }
        return "Monitor server closely and prepare for potential issues";
    }
}
