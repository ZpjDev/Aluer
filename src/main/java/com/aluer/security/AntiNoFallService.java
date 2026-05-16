package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 无摔落伤害（NoFall）检测服务 — V4.0 反作弊扩展模块
 *
 * 检测原理：
 * 1. 坠落检测 — 追踪玩家从高处坠落的事件。在Minecraft中，从3+方块高度坠落后
 *    玩家应受到摔落伤害（每超过3方块的每方块造成1点伤害，即0.5心）。
 *    NoFall hack通过修改或伪造摔落距离数据包来避免伤害。
 * 2. 合法无伤害区分 — 需要排除以下合法的无摔落伤害情况：
 *    - 落入水中（浅水或深水）
 *    - 落在粘液块上
 *    - 落在床上
 *    - 落在干草块上
 *    - 鞘翅飞行
 *    - 缓降效果
 *    - 抗性提升效果
 *    - 创造/旁观模式
 * 3. 可疑NoFall模式检测 — 如果同一玩家反复经历高空坠落但从未受伤，
 *    且无法用合法情况解释，则标记为作弊。
 * 4. 摔落距离与伤害不一致检测 — 比较服务端计算的摔落距离与客户端报告的伤害。
 *
 * 配置开关：serverguard.security.super-evolution.anti-no-fall
 */
@Service
public class AntiNoFallService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的坠落数据（playerName -> 坠落记录列表）
     */
    private final Map<String, List<FallRecord>> playerFallHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家当前是否处于坠落状态及其起始信息（playerName -> 当前坠落上下文）
     */
    private final Map<String, ActiveFall> activeFalls = new ConcurrentHashMap<>();

    /**
     * 追踪疑似NoFall的事件（playerName -> NoFall事件列表）
     */
    private final Map<String, List<Map<String, Object>>> noFallEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalFalls = new AtomicLong(0);
    private final AtomicLong noFallViolations = new AtomicLong(0);
    private final AtomicLong falsePositives = new AtomicLong(0);

    /**
     * 坠落伤害触发高度（方块）— 从3方块高度坠落开始产生摔落伤害
     */
    private static final double FALL_DAMAGE_HEIGHT = 3.0;

    /**
     * 危险坠落高度（方块）— 超过此高度几乎肯定产生伤害
     */
    private static final double DANGEROUS_FALL_HEIGHT = 8.0;

    /**
     * 连续无伤坠落次数阈值 — 超过此值标记为NoFall hack
     */
    private static final int MAX_CONSECUTIVE_NO_DAMAGE_FALLS = 3;

    /**
     * 每个玩家保留的最大坠落记录数
     */
    private static final int MAX_FALL_RECORDS = 20;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiNoFallService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiNoFallService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录玩家开始坠落（空中下落开始）
     * 应在玩家离开地面且垂直速度向下时调用
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param highestY 坠落起始的Y坐标（最高点）
     * @param gameMode 玩家游戏模式
     * @param timestamp 时间戳
     */
    public void recordFallStart(String playerName, String playerUUID,
                                 double highestY, String gameMode, Instant timestamp) {
        // 模块关闭时不追踪数据
        if (!config.getSecurity().getSuperEvolution().isAntiNoFall()) {
            return;
        }

        // 创造/旁观模式不受摔落伤害，不需要追踪
        if ("creative".equalsIgnoreCase(gameMode) || "spectator".equalsIgnoreCase(gameMode)) {
            return;
        }

        activeFalls.put(playerName, new ActiveFall(highestY, gameMode, timestamp));
    }

    /**
     * 记录玩家落地事件
     * 应在玩家接触地面时调用
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家UUID
     * @param landingY 着陆时Y坐标
     * @param tookDamage 玩家是否受到摔落伤害
     * @param damageAmount 受到的伤害量（0表示无伤害）
     * @param isInLiquid 是否在水中（合法无伤害情况）
     * @param isOnSlimeBlock 是否落在粘液块上（合法无伤害情况）
     * @param isOnHayBale 是否落在干草块上（减少80%伤害）
     * @param isOnBed 是否落在床上（减少50%伤害）
     * @param hasSlowFalling 是否有缓降效果
     * @param isElytraFlying 是否鞘翅飞行
     * @param timestamp 时间戳
     * @return 检测结果
     */
    public NoFallCheckResult recordLanding(String playerName, String playerUUID,
                                            double landingY, boolean tookDamage, double damageAmount,
                                            boolean isInLiquid, boolean isOnSlimeBlock,
                                            boolean isOnHayBale, boolean isOnBed,
                                            boolean hasSlowFalling, boolean isElytraFlying,
                                            Instant timestamp) {
        // 模块开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiNoFall()) {
            return NoFallCheckResult.clean();
        }

        totalFalls.incrementAndGet();

        ActiveFall activeFall = activeFalls.remove(playerName);
        if (activeFall == null) {
            // 没有记录的坠落起始 — 无法判断
            return NoFallCheckResult.clean();
        }

        double fallDistance = activeFall.highestY - landingY;

        // 坠落高度不足，不产生伤害，无需检测
        if (fallDistance < FALL_DAMAGE_HEIGHT) {
            return NoFallCheckResult.clean();
        }

        List<String> reasons = new ArrayList<>();
        boolean legitimateNoDamage = false;

        // 检查合法无伤害情况
        if (isInLiquid) {
            // 落入水中完全免疫摔落伤害
            legitimateNoDamage = true;
            falsePositives.incrementAndGet();
        }
        if (isOnSlimeBlock) {
            // 粘液块完全免疫摔落伤害（不反弹则无伤害）
            legitimateNoDamage = true;
            falsePositives.incrementAndGet();
        }
        // 干草块减少80%摔落伤害
        if (isOnHayBale && fallDistance < 15.0) {
            // 极端高度的坠落（>15方块）在干草块上仍可能产生可见伤害
            // 此处保守地认为15方块以下在干草块上无伤害是合法的
            if (!tookDamage) {
                legitimateNoDamage = true;
            }
        }
        if (isOnBed) {
            // 床减少50%摔落伤害，结合一定高度判断
            if (fallDistance < 6.0 && !tookDamage) {
                legitimateNoDamage = true;
            }
        }
        if (hasSlowFalling) {
            // 缓降效果完全免疫摔落伤害
            legitimateNoDamage = true;
            falsePositives.incrementAndGet();
        }
        if (isElytraFlying) {
            // 鞘翅飞行期间不受摔落伤害
            legitimateNoDamage = true;
            falsePositives.incrementAndGet();
        }

        // 记录坠落事件
        FallRecord fallRecord = new FallRecord(timestamp, fallDistance, tookDamage, damageAmount,
                legitimateNoDamage);
        List<FallRecord> history = playerFallHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        history.add(fallRecord);
        while (history.size() > MAX_FALL_RECORDS) {
            history.remove(0);
        }

        // 如果坠落高度显著且没有受到伤害，且没有合法理由，则标记
        if (!tookDamage && !legitimateNoDamage && fallDistance >= FALL_DAMAGE_HEIGHT) {
            reasons.add("NO_FALL_DAMAGE: fell " + String.format("%.1f", fallDistance)
                    + " blocks, no damage taken");

            // 记录NoFall事件
            List<Map<String, Object>> events = noFallEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("fallDistance", String.format("%.1f", fallDistance));
            event.put("landingY", String.format("%.2f", landingY));
            event.put("highestY", String.format("%.2f", activeFall.highestY));
            events.add(event);
            while (events.size() > 10) {
                events.remove(0);
            }

            // 检查连续无伤坠落模式
            long recentNoDamageCount = history.stream()
                    .filter(r -> !r.tookDamage && !r.legitimateNoDamage)
                    .count();

            if (recentNoDamageCount >= MAX_CONSECUTIVE_NO_DAMAGE_FALLS) {
                reasons.add("REPEATED_NO_DAMAGE: " + recentNoDamageCount
                        + " consecutive falls without damage");
                noFallViolations.incrementAndGet();
                return NoFallCheckResult.flagged(reasons);
            }

            if (fallDistance >= DANGEROUS_FALL_HEIGHT) {
                // 从危险高度坠落无伤害 — 高度可疑
                reasons.add("DANGEROUS_FALL: " + String.format("%.1f", fallDistance)
                        + " blocks fall with no damage (extremely unlikely)");
                noFallViolations.incrementAndGet();
                return NoFallCheckResult.flagged(reasons);
            }

            return NoFallCheckResult.suspicious(reasons);
        }

        return NoFallCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerFallHistory.remove(playerName);
        activeFalls.remove(playerName);
        noFallEvents.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器、违规数量和误报数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalFalls", totalFalls.get());
        status.put("noFallViolations", noFallViolations.get());
        status.put("falsePositives", falsePositives.get());
        status.put("activeTrackedPlayers", playerFallHistory.size());
        status.put("playersInFall", activeFalls.size());

        // 列出可疑NoFall玩家
        List<Map<String, Object>> suspiciousPlayers = new ArrayList<>();
        for (Map.Entry<String, List<FallRecord>> entry : playerFallHistory.entrySet()) {
            long noDamageCount = entry.getValue().stream()
                    .filter(r -> !r.tookDamage && !r.legitimateNoDamage).count();
            if (noDamageCount > 0) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("noDamageFalls", noDamageCount);
                info.put("totalFalls", entry.getValue().size());
                suspiciousPlayers.add(info);
            }
        }
        suspiciousPlayers.sort((a, b) ->
                Long.compare((Long) b.get("noDamageFalls"), (Long) a.get("noDamageFalls")));
        status.put("suspiciousPlayers", suspiciousPlayers.subList(0, Math.min(suspiciousPlayers.size(), 10)));
        return status;
    }

    /**
     * 追踪玩家当前活跃的坠落状态
     */
    private static class ActiveFall {
        final double highestY;      // 坠落起始时最高点的Y坐标
        final String gameMode;      // 坠落开始时的游戏模式
        final Instant startTime;    // 坠落开始时间

        ActiveFall(double highestY, String gameMode, Instant startTime) {
            this.highestY = highestY;
            this.gameMode = gameMode;
            this.startTime = startTime;
        }
    }

    /**
     * 内部坠落记录 — 记录单次坠落的详细信息
     */
    private static class FallRecord {
        final Instant timestamp;
        final double fallDistance;
        final boolean tookDamage;
        final double damageAmount;
        final boolean legitimateNoDamage;  // 是否为合法的无伤害情况

        FallRecord(Instant timestamp, double fallDistance, boolean tookDamage,
                   double damageAmount, boolean legitimateNoDamage) {
            this.timestamp = timestamp;
            this.fallDistance = fallDistance;
            this.tookDamage = tookDamage;
            this.damageAmount = damageAmount;
            this.legitimateNoDamage = legitimateNoDamage;
        }
    }

    /**
     * NoFall检测结果 — 不可变结果类
     */
    public static class NoFallCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private NoFallCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常坠落并受到伤害，或有合法无伤害理由 */
        public static NoFallCheckResult clean() {
            return new NoFallCheckResult(false, false, List.of());
        }

        /** 可疑 — 未受伤害但坠落高度不够极端，或存在未知因素 */
        public static NoFallCheckResult suspicious(List<String> reasons) {
            return new NoFallCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认NoFall hack，从危险高度坠落未受伤害且无合法理由 */
        public static NoFallCheckResult flagged(List<String> reasons) {
            return new NoFallCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
