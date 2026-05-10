package com.aluer.ai;

import com.aluer.config.ServerGuardConfig;
import com.aluer.model.MetricsData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

@Component
public class TimeSeriesPredictor {
    private static final Logger logger = LoggerFactory.getLogger(TimeSeriesPredictor.class);
    
    private final ServerGuardConfig config;
    private final ConcurrentLinkedDeque<Double> tpsHistory = new ConcurrentLinkedDeque<>();
    private final int predictionHorizon;

    public TimeSeriesPredictor(ServerGuardConfig config) {
        this.config = config;
        this.predictionHorizon = config.getAi().getPredictionHorizonMinutes();
    }

    public void addMetric(MetricsData data) {
        tpsHistory.add(data.getTps());
        
        int windowSize = config.getAi().getSlidingWindowSize();
        while (tpsHistory.size() > windowSize) {
            tpsHistory.removeFirst();
        }
    }

    public PredictionResult predict() {
        if (tpsHistory.size() < 20) {
            return null;
        }
        
        List<Double> tps = new ArrayList<>(tpsHistory);
        
        Double mean = tps.stream().mapToDouble(Double::doubleValue).average().orElse(20.0);
        
        Double trend = calculateTrend(tps);
        
        Double volatility = calculateVolatility(tps);
        
        Double predictedValue = mean + (trend * predictionHorizon / 60.0);
        predictedValue = Math.max(0, Math.min(20, predictedValue));
        
        double confidence = calculateConfidence(tps, volatility);
        
        boolean willBreach = predictedValue < config.getMonitor().getTpsThreshold();
        
        return new PredictionResult(predictedValue, confidence, willBreach, trend, volatility);
    }

    private double calculateTrend(List<Double> data) {
        if (data.size() < 2) return 0;
        
        int n = data.size();
        double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
        
        for (int i = 0; i < n; i++) {
            sumX += i;
            sumY += data.get(i);
            sumXY += i * data.get(i);
            sumX2 += i * i;
        }
        
        double slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
        
        return slope;
    }

    private double calculateVolatility(List<Double> data) {
        if (data.size() < 2) return 0;
        
        double mean = data.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        
        double variance = data.stream()
            .mapToDouble(v -> Math.pow(v - mean, 2))
            .average()
            .orElse(0);
        
        return Math.sqrt(variance);
    }

    private double calculateConfidence(List<Double> data, double volatility) {
        if (data.size() < 10) return 0.3;
        
        double mean = data.stream().mapToDouble(Double::doubleValue).average().orElse(20);
        
        double relativeVolatility = volatility / mean;
        
        double confidence = 1.0 - Math.min(0.7, relativeVolatility);
        
        confidence *= Math.min(1.0, data.size() / 100.0);
        
        return Math.max(0.3, Math.min(0.95, confidence));
    }

    public static class PredictionResult {
        private final double predictedValue;
        private final double confidence;
        private final boolean willBreachThreshold;
        private final double trend;
        private final double volatility;

        public PredictionResult(double predictedValue, double confidence, boolean willBreachThreshold, 
                               double trend, double volatility) {
            this.predictedValue = predictedValue;
            this.confidence = confidence;
            this.willBreachThreshold = willBreachThreshold;
            this.trend = trend;
            this.volatility = volatility;
        }

        public double getPredictedValue() { return predictedValue; }
        public double getConfidence() { return confidence; }
        public boolean isWillBreachThreshold() { return willBreachThreshold; }
        public double getTrend() { return trend; }
        public double getVolatility() { return volatility; }
        
        public String getRecommendation() {
            if (willBreachThreshold && confidence > 0.6) {
                if (trend < 0) {
                    return "WARNING: TPS predicted to drop below threshold. Consider: " +
                           "1) Reduce entity count, 2) Limit chunk loading, 3) Disable world generation";
                }
            }
            return "Monitor normally - no immediate action required";
        }
    }
}
