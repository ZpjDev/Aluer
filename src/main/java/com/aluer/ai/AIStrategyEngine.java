package com.aluer.ai;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@Service
public class AIStrategyEngine {

    private final Map<String, DefenseStrategy> strategies = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> strategyUsageCount = new ConcurrentHashMap<>();
    private final Queue<StrategyExecution> executionLog = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private volatile String currentDefenseLevel = "NORMAL";
    private final AtomicLong totalExecutions = new AtomicLong(0);

    public AIStrategyEngine() {
        initializeDefaultStrategies();
    }

    private void initializeDefaultStrategies() {
        addStrategy("DDoS防御", "HIGH", 90, 
            "检测到DDoS攻击时自动启用", 
            Arrays.asList("启用连接限制", "启用流量限制", "启用IP封禁"));

        addStrategy("暴力破解防御", "MEDIUM", 80,
            "检测到暴力破解时自动启用",
            Arrays.asList("临时封禁IP", "增加验证码", "通知管理员"));

        addStrategy("异常流量", "MEDIUM", 70,
            "检测到异常流量模式",
            Arrays.asList("记录流量", "触发告警", "启动监控"));

        addStrategy("服务器过载", "HIGH", 85,
            "服务器资源使用率过高",
            Arrays.asList("清理缓存", "限制新连接", "重启非必要服务"));

        addStrategy("可疑登录", "LOW", 60,
            "检测到可疑登录尝试",
            Arrays.asList("增加验证", "发送告警", "记录日志"));
    }

    public void addStrategy(String name, String level, int threshold, String description, List<String> actions) {
        DefenseStrategy strategy = new DefenseStrategy(name, level, threshold, description, actions);
        strategies.put(name, strategy);
        strategyUsageCount.put(name, new AtomicInteger(0));
    }

    public DefenseStrategy evaluateAndSelect(String threatType, int severity) {
        DefenseStrategy bestStrategy = null;
        int bestScore = 0;

        for (DefenseStrategy strategy : strategies.values()) {
            int score = calculateStrategyScore(strategy, threatType, severity);
            if (score > bestScore) {
                bestScore = score;
                bestStrategy = strategy;
            }
        }

        if (bestStrategy != null && bestScore >= bestStrategy.threshold) {
            executeStrategy(bestStrategy, threatType, severity);
        }

        return bestStrategy;
    }

    private int calculateStrategyScore(DefenseStrategy strategy, String threatType, int severity) {
        int score = 0;

        if (threatType.toLowerCase().contains(strategy.name.toLowerCase())) {
            score += 50;
        }

        score += severity;

        if ("HIGH".equals(strategy.defenseLevel)) {
            score += 20;
        }

        return score;
    }

    public void executeStrategy(DefenseStrategy strategy, String threatType, int severity) {
        StrategyExecution execution = new StrategyExecution(
            strategy.name,
            threatType,
            severity,
            strategy.actions,
            System.currentTimeMillis()
        );

        executionLog.offer(execution);
        strategyUsageCount.get(strategy.name).incrementAndGet();
        totalExecutions.incrementAndGet();

        while (executionLog.size() > 500) {
            executionLog.poll();
        }
    }

    public void adjustDefenseLevel(String level) {
        this.currentDefenseLevel = level;
    }

    public String getCurrentDefenseLevel() {
        return currentDefenseLevel;
    }

    public List<StrategyExecution> getExecutionLog(int limit) {
        List<StrategyExecution> result = new ArrayList<>();
        int count = 0;
        for (StrategyExecution exec : executionLog) {
            if (count++ >= limit) break;
            result.add(exec);
        }
        return result;
    }

    public Map<String, Object> getStrategyStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalStrategies", strategies.size());
        stats.put("totalExecutions", totalExecutions.get());
        stats.put("currentDefenseLevel", currentDefenseLevel);
        
        Map<String, Integer> usage = new HashMap<>();
        strategyUsageCount.forEach((k, v) -> usage.put(k, v.get()));
        stats.put("strategyUsage", usage);
        
        return stats;
    }

    public Collection<DefenseStrategy> getAllStrategies() {
        return strategies.values();
    }

    public static class DefenseStrategy {
        public final String name;
        public final String defenseLevel;
        public final int threshold;
        public final String description;
        public final List<String> actions;

        public DefenseStrategy(String name, String level, int threshold, String description, List<String> actions) {
            this.name = name;
            this.defenseLevel = level;
            this.threshold = threshold;
            this.description = description;
            this.actions = actions;
        }
    }

    public static class StrategyExecution {
        public final String strategyName;
        public final String threatType;
        public final int severity;
        public final List<String> actions;
        public final long timestamp;

        public StrategyExecution(String strategyName, String threatType, int severity, List<String> actions, long timestamp) {
            this.strategyName = strategyName;
            this.threatType = threatType;
            this.severity = severity;
            this.actions = actions;
            this.timestamp = timestamp;
        }
    }
}
