package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 超距攻击（Reach）检测服务 — V4.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 正常攻击距离检测 — Minecraft生存模式默认攻击距离约3.0方块，考虑网络延迟容差
 *    将阈值设为3.8方块，超过此值视为可疑
 * 2. 绝对超距判定 — 攻击距离超过6.0方块时，排除任何延迟可能性，绝对判定为超距攻击
 * 3. 连续超距记录追踪 — 追踪每个玩家最近10次攻击距离，如果有多次超过阈值则标记为作弊者
 * 4. 超距频率统计 — 如果某个玩家的超距攻击占总攻击的一定比例，表明可能使用Reach扩展
 *
 * 配置开关：serverguard.security.super-evolution.anti-reach
 */
@Service
public class AntiReachService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的攻击距离历史（playerName -> 距离记录列表）
     */
    private final Map<String, List<DistanceRecord>> playerDistanceHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的违规攻击记录（playerName -> 违规详情列表），保留用于getStatus()展示
     */
    private final Map<String, List<Map<String, Object>>> playerViolations = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong violations = new AtomicLong(0);

    /**
     * 宽松阈值（考虑网络延迟）— 超过此值视为可疑但非绝对确认
     */
    private static final double SUSPICIOUS_REACH_THRESHOLD = 3.8;

    /**
     * 绝对超距阈值 — 超过此值无任何合法可能性，直接判定
     */
    private static final double ABSOLUTE_REACH_THRESHOLD = 6.0;

    /**
     * 超距比例阈值 — 如果玩家最近攻击中超距攻击超过这个比例，标记为作弊
     */
    private static final double VIOLATION_RATIO_THRESHOLD = 0.3;

    /**
     * 最小攻击次数 — 需要足够的攻击样本才能做出可靠判断
     */
    private static final int MIN_ATTACKS_FOR_ANALYSIS = 5;

    /**
     * 追踪每个玩家的最大攻击记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 30;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiReachService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiReachService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家攻击距离是否异常
     *
     * @param playerName 攻击者玩家名称
     * @param playerUUID 攻击者UUID
     * @param attackerX 攻击者X坐标
     * @param attackerY 攻击者Y坐标
     * @param attackerZ 攻击者Z坐标
     * @param targetX 目标X坐标
     * @param targetY 目标Y坐标
     * @param targetZ 目标Z坐标
     * @param actualDistance 客户端报告的或服务端计算的实际距离
     * @param timestamp 攻击时间
     * @return 检测结果
     */
    public ReachCheckResult detect(String playerName, String playerUUID,
                                    double attackerX, double attackerY, double attackerZ,
                                    double targetX, double targetY, double targetZ,
                                    double actualDistance, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiReach()) {
            return ReachCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        // 计算服务端确认的距离（欧几里得距离）
        double serverDistance = Math.sqrt(
                Math.pow(targetX - attackerX, 2) +
                        Math.pow(targetY - attackerY, 2) +
                        Math.pow(targetZ - attackerZ, 2));

        List<DistanceRecord> history = playerDistanceHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        DistanceRecord record = new DistanceRecord(timestamp, serverDistance, actualDistance,
                attackerX, attackerY, attackerZ, targetX, targetY, targetZ);
        history.add(record);

        // 限制记录数量，只保留最近记录
        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }

        // 绝对超距判定 — 超过6.0方块无任何合法可能
        if (serverDistance > ABSOLUTE_REACH_THRESHOLD) {
            violations.incrementAndGet();
            List<String> reasons = List.of(
                    "ABSOLUTE_REACH: " + String.format("%.2f", serverDistance)
                            + " blocks (max legit ~3.0, threshold 6.0)");
            recordViolation(playerName, serverDistance, "ABSOLUTE_REACH");
            return ReachCheckResult.flagged(reasons);
        }

        // 可疑超距检测 — 超过3.8方块但不满6.0（可能是延迟或开挂）
        if (serverDistance > SUSPICIOUS_REACH_THRESHOLD) {
            recordViolation(playerName, serverDistance, "SUSPICIOUS_REACH");

            // 检查最近的攻击历史中超距攻击的比例
            if (history.size() >= MIN_ATTACKS_FOR_ANALYSIS) {
                long exceedCount = history.stream()
                        .filter(r -> r.serverDistance > SUSPICIOUS_REACH_THRESHOLD)
                        .count();
                double exceedRatio = (double) exceedCount / history.size();

                if (exceedRatio > VIOLATION_RATIO_THRESHOLD) {
                    violations.incrementAndGet();
                    List<String> reasons = List.of(
                            "FREQUENT_REACH: " + String.format("%.0f", exceedRatio * 100)
                                    + "% of recent attacks exceed " + SUSPICIOUS_REACH_THRESHOLD
                                    + " blocks (" + exceedCount + "/" + history.size() + ")",
                            "LATEST_REACH: " + String.format("%.2f", serverDistance) + " blocks");
                    return ReachCheckResult.flagged(reasons);
                }
            }

            return ReachCheckResult.suspicious(
                    List.of("SUSPICIOUS_REACH: " + String.format("%.2f", serverDistance) + " blocks"));
        }

        return ReachCheckResult.clean();
    }

    /**
     * 记录违规事件用于getStatus()展示
     */
    private void recordViolation(String playerName, double distance, String type) {
        List<Map<String, Object>> violations = playerViolations.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("time", Instant.now().toString());
        v.put("distance", String.format("%.2f", distance));
        v.put("type", type);
        violations.add(v);
        while (violations.size() > 20) {
            violations.remove(0);
        }
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerDistanceHistory.remove(playerName);
        playerViolations.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器、最近违规列表的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("violations", violations.get());
        status.put("activeTrackedPlayers", playerDistanceHistory.size());

        // 汇总最近违规记录
        List<Map<String, Object>> recentViolations = new ArrayList<>();
        for (Map.Entry<String, List<Map<String, Object>>> entry : playerViolations.entrySet()) {
            if (!entry.getValue().isEmpty()) {
                Map<String, Object> summary = new LinkedHashMap<>();
                summary.put("player", entry.getKey());
                Map<String, Object> lastV = entry.getValue().get(entry.getValue().size() - 1);
                summary.put("lastViolationDistance", lastV.get("distance"));
                summary.put("lastViolationType", lastV.get("type"));
                summary.put("lastViolationTime", lastV.get("time"));
                summary.put("totalViolations", entry.getValue().size());
                recentViolations.add(summary);
            }
        }
        // 按最新违规时间排序
        recentViolations.sort((a, b) -> {
            String ta = (String) a.get("lastViolationTime");
            String tb = (String) b.get("lastViolationTime");
            return tb.compareTo(ta);
        });
        status.put("recentViolations", recentViolations.subList(0, Math.min(recentViolations.size(), 20)));
        return status;
    }

    /**
     * 内部距离记录 — 保存单次攻击的空间和距离信息
     */
    private static class DistanceRecord {
        final Instant timestamp;
        final double serverDistance;
        final double actualDistance;
        final double ax, ay, az, tx, ty, tz;

        DistanceRecord(Instant timestamp, double serverDistance, double actualDistance,
                       double ax, double ay, double az, double tx, double ty, double tz) {
            this.timestamp = timestamp;
            this.serverDistance = serverDistance;
            this.actualDistance = actualDistance;
            this.ax = ax; this.ay = ay; this.az = az;
            this.tx = tx; this.ty = ty; this.tz = tz;
        }
    }

    /**
     * 超距检测结果 — 不可变结果类
     */
    public static class ReachCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private ReachCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常攻击距离 */
        public static ReachCheckResult clean() {
            return new ReachCheckResult(false, false, List.of());
        }

        /** 可疑 — 攻击距离略微超过阈值，但可能由延迟引起 */
        public static ReachCheckResult suspicious(List<String> reasons) {
            return new ReachCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认超距攻击，距离显著超出合法范围 */
        public static ReachCheckResult flagged(List<String> reasons) {
            return new ReachCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
