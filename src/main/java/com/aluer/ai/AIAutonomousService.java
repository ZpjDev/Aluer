package com.aluer.ai;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.regex.*;

import com.aluer.ai.DeepSeekClient.AiAnalysisResult;

@Service
public class AIAutonomousService {

    private final DeepSeekClient deepSeekClient;
    private final AluerSovereignEngine aluerSovereignEngine;
    private final Queue<ThreatIntelligence> threatIntelQueue = new ConcurrentLinkedQueue<>();
    private final Map<String, ThreatPattern> knownThreats = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> threatCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> trafficCounts = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(3);
    private final List<AIDecision> decisionHistory = new CopyOnWriteArrayList<>();

    private final AtomicLong totalThreatsDetected = new AtomicLong(0);
    private final AtomicLong totalAutoActions = new AtomicLong(0);
    private volatile boolean autonomousMode = true;

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AIAutonomousService.class);

    public AIAutonomousService(DeepSeekClient deepSeekClient,
                               AluerSovereignEngine aluerSovereignEngine) {
        this.deepSeekClient = deepSeekClient;
        this.aluerSovereignEngine = aluerSovereignEngine;
        initializeThreatPatterns();
        startAutonomousMonitoring();
    }

    private void initializeThreatPatterns() {
        addThreatPattern("SQL注入", "union.*select|or.*1=1|drop.*table", 90);
        addThreatPattern("XSS攻击", "<script|javascript:|onerror=", 85);
        addThreatPattern("暴力破解", "failed.*login|authentication.*fail", 70);
        addThreatPattern("DDoS攻击", "flood|amplification|botnet", 95);
        addThreatPattern("端口扫描", "port.*scan|connection.*attempt", 60);
        addThreatPattern("恶意爬虫", "scraper|bot|crawler", 50);
        addThreatPattern("CC攻击", "request.*flood|http.*flood", 85);
        addThreatPattern("Syn flood", "syn.*flood|tcp.*syn", 90);
    }

    public void addThreatPattern(String name, String regex, int severity) {
        ThreatPattern tp = new ThreatPattern(name, regex, severity);
        knownThreats.put(name, tp);
    }

    public boolean analyzeLogEntry(String logContent, String sourceIP) {
        if (!autonomousMode) {
            return false;
        }

        for (ThreatPattern pattern : knownThreats.values()) {
            if (pattern.matches(logContent)) {
                ThreatIntelligence intel = new ThreatIntelligence(
                    pattern.name,
                    sourceIP,
                    logContent,
                    pattern.severity,
                    System.currentTimeMillis()
                );
                threatIntelQueue.offer(intel);
                
                threatCounts.computeIfAbsent(pattern.name, k -> new AtomicInteger(0)).incrementAndGet();
                totalThreatsDetected.incrementAndGet();

                if (pattern.severity >= 80) {
                    aluerSovereignEngine.runSovereignCycle("threat-pattern:" + pattern.name);
                    executeAutoDefense(pattern.name, sourceIP);
                }

                return true;
            }
        }
        return false;
    }

    public void analyzeNetworkTraffic(String sourceIP, int packetSize, String protocol) {
        if (!autonomousMode) {
            return;
        }

        if (packetSize > 10000) {
            ThreatIntelligence intel = new ThreatIntelligence(
                "大包攻击",
                sourceIP,
                "异常大包: " + packetSize + " bytes",
                75,
                System.currentTimeMillis()
            );
            threatIntelQueue.offer(intel);
            totalThreatsDetected.incrementAndGet();
        }

        if (isSuspiciousTrafficPattern(sourceIP)) {
            ThreatIntelligence intel = new ThreatIntelligence(
                "流量异常",
                sourceIP,
                "可疑流量模式",
                80,
                System.currentTimeMillis()
            );
            threatIntelQueue.offer(intel);
            totalThreatsDetected.incrementAndGet();
            aluerSovereignEngine.runSovereignCycle("network-traffic:" + sourceIP);
            executeAutoDefense("流量限制", sourceIP);
        }
    }

    private boolean isSuspiciousTrafficPattern(String ip) {
        AtomicInteger count = trafficCounts.computeIfAbsent(ip, k -> new AtomicInteger(0));
        return count.incrementAndGet() > 1000;
    }

    public void executeAutoDefense(String threatType, String target) {
        AIDecision decision = new AIDecision(
            "AUTO_DEFENSE",
            threatType,
            target,
            "自动防御",
            System.currentTimeMillis()
        );

        decisionHistory.add(decision);
        totalAutoActions.incrementAndGet();

        while (decisionHistory.size() > 100) {
            decisionHistory.remove(0);
        }

        logger.info("[AI自主防御] 检测到威胁: {} - 目标: {} - 已执行自动防御", threatType, target);
    }

    public void predictServerIssues() {
        if (!deepSeekClient.isEnabled()) {
            return;
        }

        try {
            AiAnalysisResult result = deepSeekClient.getServerHealthReport();
            if (result != null) {
                String prediction = result.getDescription();
                logger.info("[AI预测] 服务器健康预测: {}", prediction);

                if ("critical".equals(result.getSeverity()) || "warning".equals(result.getSeverity())) {
                    aluerSovereignEngine.runSovereignCycle("predictive-maintenance");
                    executePreventiveAction("预防性维护", prediction);
                }
            }
        } catch (Exception e) {
            logger.error("AI预测错误: {}", e.getMessage());
        }
    }

    public void executePreventiveAction(String actionType, String reason) {
        AIDecision decision = new AIDecision(
            "PREVENTIVE",
            actionType,
            "system",
            reason,
            System.currentTimeMillis()
        );
        decisionHistory.add(decision);
        logger.info("[AI预防] 执行预防措施: {} - 原因: {}", actionType, reason);
    }

    public List<ThreatIntelligence> getRecentThreats(int limit) {
        List<ThreatIntelligence> result = new ArrayList<>();
        int count = 0;
        for (ThreatIntelligence intel : threatIntelQueue) {
            if (count++ >= limit) break;
            result.add(intel);
        }
        return result;
    }

    public List<AIDecision> getDecisionHistory(int limit) {
        List<AIDecision> result = new ArrayList<>();
        int count = 0;
        for (AIDecision decision : decisionHistory) {
            if (count++ >= limit) break;
            result.add(decision);
        }
        return result;
    }

    public Map<String, Object> getAutonomousStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalThreatsDetected", totalThreatsDetected.get());
        stats.put("totalAutoActions", totalAutoActions.get());
        stats.put("autonomousMode", autonomousMode);
        stats.put("knownThreatPatterns", knownThreats.size());
        stats.put("recentDecisions", decisionHistory.size());
        return stats;
    }

    public void setAutonomousMode(boolean enabled) {
        this.autonomousMode = enabled;
        logger.info("[AI自主] 模式已设置为: {}", enabled ? "开启" : "关闭");
    }

    public boolean isAutonomousMode() {
        return autonomousMode;
    }

    private void startAutonomousMonitoring() {
        scheduler.scheduleAtFixedRate(() -> {
            predictServerIssues();
            cleanupOldData();
        }, 60, 60, TimeUnit.SECONDS);
    }

    private void cleanupOldData() {
        long cutoff = System.currentTimeMillis() - 3600000;
        threatIntelQueue.removeIf(i -> i.timestamp < cutoff);
        trafficCounts.entrySet().removeIf(e -> e.getValue().get() == 0);
    }

    public static class ThreatPattern {
        public final String name;
        public final Pattern pattern;
        public final int severity;

        public ThreatPattern(String name, String regex, int severity) {
            this.name = name;
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            this.severity = severity;
        }

        public boolean matches(String input) {
            return pattern.matcher(input).find();
        }
    }

    public static class ThreatIntelligence {
        public final String threatType;
        public final String sourceIP;
        public final String details;
        public final int severity;
        public final long timestamp;

        public ThreatIntelligence(String threatType, String sourceIP, String details, int severity, long timestamp) {
            this.threatType = threatType;
            this.sourceIP = sourceIP;
            this.details = details;
            this.severity = severity;
            this.timestamp = timestamp;
        }
    }

    public static class AIDecision {
        public final String decisionType;
        public final String threatType;
        public final String target;
        public final String reason;
        public final long timestamp;

        public AIDecision(String decisionType, String threatType, String target, String reason, long timestamp) {
            this.decisionType = decisionType;
            this.threatType = threatType;
            this.target = target;
            this.reason = reason;
            this.timestamp = timestamp;
        }
    }
}
