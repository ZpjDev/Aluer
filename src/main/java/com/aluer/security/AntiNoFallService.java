package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 无摔落伤害（NoFall）检测服务 — V4.0 反作弊扩展模块，V5.2 增强
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
 * V5.2 新增检测：
 * 5. GroundSpoof检测 — 客户端声称onGround=true但服务端Y速度指示应在空中
 * 6. 数据包级分析 — 逐tick比较客户端声称onGround与服务端计算onGround状态的差异
 * 7. 坠落距离累积 — 服务端独立计算坠落距离，与客户端报告对比
 * 8. 传送式NoFall — 玩家瞬间下落5+方块后无伤害（与VClip/TeleportFall配合）
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

    // ─── V5.2 新增追踪数据结构 ───

    /**
     * 追踪玩家地面伪造（GroundSpoof）的连续tick数（playerName -> 连续次数）
     * 用于检测客户端onGround=true但服务端Y速度指示应在空中
     */
    private final Map<String, Integer> playerGroundSpoofTicks = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家服务端计算的onGround状态历史（playerName -> 服务端onGround历史）
     * 用于与客户端声称的onGround进行交叉对比
     */
    private final Map<String, List<GroundStateRecord>> playerGroundStateHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家服务端累积的坠落距离（playerName -> 累积坠落距离）
     * 从离开地面开始累积，直到接触地面或受伤重置
     */
    private final Map<String, Double> playerAccumulatedFallDistance = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近一次开始累积坠落距离的起始Y坐标
     */
    private final Map<String, Double> playerFallStartY = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家是否处于服务端判断的空中状态
     */
    private final Map<String, Boolean> playerServerSideAirborne = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的最近一次Y坐标，用于检测传送式下落
     */
    private final Map<String, Double> playerLastY = new ConcurrentHashMap<>();

    private final AtomicLong totalFalls = new AtomicLong(0);
    private final AtomicLong noFallViolations = new AtomicLong(0);
    private final AtomicLong falsePositives = new AtomicLong(0);

    /**
     * V5.2 新增计数器
     */
    private final AtomicLong groundSpoofViolations = new AtomicLong(0);
    private final AtomicLong teleportNoFallViolations = new AtomicLong(0);

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

    // ─── V5.2 新增常量 ───

    /**
     * GroundSpoof连续tick阈值 — 连续超过此tick数的ground伪造判定为NoFall
     * AntiHunger hack同样使用ground伪造，但此处关注的是坠落伤害规避场景
     */
    private static final int MAX_GROUND_SPOOF_TICKS = 5;

    /**
     * 传送式下落检测阈值（方块）— 单tick内Y坐标下降超过此值且无伤害
     */
    private static final double TELEPORT_FALL_THRESHOLD = 5.0;

    /**
     * 服务端累积坠落距离阈值 — 超过此距离且无伤害时标记
     */
    private static final double ACCUMULATED_FALL_THRESHOLD = 3.0;

    /**
     * Y速度正值阈值 — 低于此值的波动忽略
     */
    private static final double ZERO_VELOCITY_THRESHOLD = 0.01;

    /**
     * 每个玩家保留的最大地面状态记录数
     */
    private static final int MAX_GROUND_STATE_RECORDS = 30;

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

    // ═══════════════════════════════════════════════════════════════
    // V5.2 新增检测方法
    // ═══════════════════════════════════════════════════════════════

    /**
     * V5.2 GroundSpoof检测 — 逐tick调用
     *
     * 检测客户端声称onGround=true但服务端Y速度指示玩家应在空中。
     * NoFall hack常通过伪造onGround=true来跳过服务端的摔落伤害计算，
     * 因为Minecraft服务端在onGround=true时重置摔落距离。
     *
     * @param playerName      玩家名称
     * @param yVelocity       当前tick的Y速度（负值=下落中）
     * @param clientOnGround  客户端声称的onGround状态
     * @param timestamp       时间戳
     * @return 如果检测到持续的ground伪造则返回flagged，否则返回clean
     */
    public NoFallCheckResult detectGroundSpoof(String playerName,
                                                double yVelocity,
                                                boolean clientOnGround,
                                                Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiNoFall()) {
            return NoFallCheckResult.clean();
        }

        // 客户端声称在地面，但Y速度为负（在下落）— 物理上矛盾
        // 正常在地面时Y速度应接近0（重力被地面法向力抵消）
        boolean serverSideLikelyAirborne = yVelocity < -ZERO_VELOCITY_THRESHOLD;

        if (clientOnGround && serverSideLikelyAirborne) {
            int spoofTicks = playerGroundSpoofTicks.getOrDefault(playerName, 0) + 1;
            playerGroundSpoofTicks.put(playerName, spoofTicks);

            if (spoofTicks >= MAX_GROUND_SPOOF_TICKS) {
                List<String> reasons = new ArrayList<>();
                reasons.add("GROUND_SPOOF: client claims onGround=true for "
                        + spoofTicks + " consecutive ticks while server Y velocity ("
                        + String.format("%.3f", yVelocity) + ") indicates falling");
                reasons.add("This is consistent with NoFall: faking onGround to reset fall distance");
                groundSpoofViolations.incrementAndGet();
                noFallViolations.incrementAndGet();
                return NoFallCheckResult.flagged(reasons);
            }

            if (spoofTicks >= 3) {
                List<String> reasons = new ArrayList<>();
                reasons.add("GROUND_SPOOF_SUSPICIOUS: " + spoofTicks
                        + " ticks of onGround=true while yVel="
                        + String.format("%.3f", yVelocity));
                return NoFallCheckResult.suspicious(reasons);
            }
        } else {
            // 状态一致或客户端正确报告了空中状态，重置计数
            playerGroundSpoofTicks.remove(playerName);
        }

        return NoFallCheckResult.clean();
    }

    /**
     * V5.2 数据包级地面状态分析 — 逐tick调用
     *
     * 比较客户端声称的onGround与服务端独立计算的onGround状态。
     * 服务端根据以下条件自行判断地面状态：
     * - Y坐标与整数边界的关系（脚部Y坐标接近整数表示在地面）
     * - Y速度接近0且上一tick在下降
     * - 碰撞检测（服务端的方块碰撞计算结果）
     *
     * 如果客户端与服务端在onGround上持续不一致，说明客户端在伪造数据包。
     *
     * @param playerName          玩家名称
     * @param clientOnGround      客户端声称的onGround
     * @param serverCalcOnGround  服务端计算的onGround（基于Y坐标/碰撞）
     * @param playerY             玩家当前Y坐标
     * @param yVelocity           玩家Y速度
     * @param timestamp           时间戳
     * @return 检测结果
     */
    public NoFallCheckResult analyzePacketGroundState(String playerName,
                                                       boolean clientOnGround,
                                                       boolean serverCalcOnGround,
                                                       double playerY,
                                                       double yVelocity,
                                                       Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiNoFall()) {
            return NoFallCheckResult.clean();
        }

        // 记录地面状态历史
        List<GroundStateRecord> history = playerGroundStateHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        GroundStateRecord record = new GroundStateRecord(timestamp, clientOnGround,
                serverCalcOnGround, playerY, yVelocity);
        history.add(record);
        while (history.size() > MAX_GROUND_STATE_RECORDS) {
            history.remove(0);
        }

        List<String> reasons = new ArrayList<>();

        // 逐tick比较：客户端声称在地面但服务端计算显示在空中
        if (clientOnGround && !serverCalcOnGround && yVelocity < -ZERO_VELOCITY_THRESHOLD) {
            // 服务端计算在空中 + 客户端说在地面 + Y速度在下落 = 典型的NoFall数据包伪造
            reasons.add("PACKET_GROUND_MISMATCH: client onGround=true but server "
                    + "calculates onGround=false (yVel=" + String.format("%.3f", yVelocity)
                    + ", playerY=" + String.format("%.2f", playerY + ")"));
        }

        // 长期模式分析：统计客户端/服务端不一致的比例
        if (history.size() >= 10) {
            long mismatchCount = history.stream()
                    .filter(r -> r.clientOnGround != r.serverCalcOnGround)
                    .count();
            double mismatchRatio = (double) mismatchCount / history.size();

            // 超过60%的tick存在onGround不一致 — 客户端在系统性伪造
            if (mismatchRatio > 0.6) {
                reasons.add("SYSTEMATIC_GROUND_MISMATCH: "
                        + String.format("%.0f", mismatchRatio * 100)
                        + "% ground state mismatch over " + history.size()
                        + " ticks (" + mismatchCount + "/" + history.size() + " ticks)");
                noFallViolations.incrementAndGet();
            }
        }

        if (reasons.size() >= 2) {
            return NoFallCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return NoFallCheckResult.suspicious(reasons);
        }

        return NoFallCheckResult.clean();
    }

    /**
     * V5.2 服务端坠落距离累积追踪 — 逐tick调用
     *
     * 服务端独立追踪玩家的坠落距离，不受客户端报告的onGround影响。
     * 从服务端判断的离地瞬间开始累积Y坐标的下降量，直到接触地面或受到伤害。
     *
     * 如果服务端累积的坠落距离超过3.0方块但玩家未受到任何伤害，
     * 说明客户端可能伪造了onGround或摔落距离数据包。
     *
     * @param playerName      玩家名称
     * @param currentY        玩家当前Y坐标
     * @param yVelocity       玩家Y速度
     * @param serverOnGround  服务端判断的onGround状态
     * @param tookDamage      玩家是否受到伤害（本tick）
     * @param timestamp       时间戳
     * @return 检测结果
     */
    public NoFallCheckResult checkFallDistanceAccumulation(String playerName,
                                                            double currentY,
                                                            double yVelocity,
                                                            boolean serverOnGround,
                                                            boolean tookDamage,
                                                            Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiNoFall()) {
            return NoFallCheckResult.clean();
        }

        Double previousY = playerLastY.get(playerName);

        // 在地面上，重置坠落累积
        if (serverOnGround) {
            Double accumulated = playerAccumulatedFallDistance.get(playerName);
            if (accumulated != null && accumulated >= ACCUMULATED_FALL_THRESHOLD && !tookDamage) {
                // 累积了足够的坠落距离但没有受伤 — NoFall
                List<String> reasons = new ArrayList<>();
                reasons.add("ACCUMULATED_FALL_NO_DAMAGE: server-side fall distance of "
                        + String.format("%.1f", accumulated) + " blocks accumulated,"
                        + " landed without taking damage");
                reasons.add("Client likely faked onGround or fall distance packet");
                noFallViolations.incrementAndGet();

                // 重置累积
                playerAccumulatedFallDistance.remove(playerName);
                playerFallStartY.remove(playerName);

                return NoFallCheckResult.flagged(reasons);
            }

            // 正常落地，重置
            playerAccumulatedFallDistance.remove(playerName);
            playerFallStartY.remove(playerName);
            playerServerSideAirborne.put(playerName, false);
        } else {
            // 在空中 — 累积坠落距离
            playerServerSideAirborne.put(playerName, true);

            if (previousY != null && yVelocity < -ZERO_VELOCITY_THRESHOLD) {
                double fallDelta = previousY - currentY;
                if (fallDelta > 0) {
                    double accumulated = playerAccumulatedFallDistance.getOrDefault(playerName, 0.0);
                    accumulated += fallDelta;
                    playerAccumulatedFallDistance.put(playerName, accumulated);

                    // 记录坠落起始Y
                    playerFallStartY.putIfAbsent(playerName, previousY);

                    // 如果累积超过阈值但玩家未受伤且仍在空中 — 记录可疑状态
                    if (accumulated >= ACCUMULATED_FALL_THRESHOLD + 3.0) {
                        // 积累了大量坠落距离但还未落地 — 可能是Blink或持续空中状态
                        // 暂时仅记录，等落地时再判断
                    }
                }
            }
        }

        // 如果玩家受到伤害，重置累积（伤害已正确应用，非NoFall）
        if (tookDamage) {
            playerAccumulatedFallDistance.remove(playerName);
            playerFallStartY.remove(playerName);
        }

        // 更新最近Y坐标
        if (previousY == null || !serverOnGround) {
            playerLastY.put(playerName, currentY);
        }

        return NoFallCheckResult.clean();
    }

    /**
     * V5.2 传送式NoFall检测 — 逐tick调用
     *
     * 检测玩家在单tick内Y坐标突然下降5+方块且没有受到伤害。
     * 这通常意味着hack结合了VClip（垂直传送）和NoFall（免疫伤害）功能。
     *
     * 合法情况排除：
     * - 末影珍珠传送（有投掷音效+伤害/粒子）
     * - /tp命令（有日志）
     * - 紫颂果传送（有粒子效果）
     * - 鞘翅俯冲然后突然拉起（有速度渐变+无伤害是因为鞘翅免疫）
     *
     * @param playerName       玩家名称
     * @param fromY            上一tick Y坐标
     * @param toY              当前tick Y坐标
     * @param tookDamage       本tick是否受到伤害
     * @param isElytraFlying   是否鞘翅飞行
     * @param isTeleportCommand 是否为/tp命令触发
     * @param timestamp        时间戳
     * @return 检测结果
     */
    public NoFallCheckResult detectTeleportNoFall(String playerName,
                                                   double fromY, double toY,
                                                   boolean tookDamage,
                                                   boolean isElytraFlying,
                                                   boolean isTeleportCommand,
                                                   Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiNoFall()) {
            return NoFallCheckResult.clean();
        }

        double dy = toY - fromY;
        double fallAmount = Math.abs(dy);

        // 没有显著下落，跳过
        if (dy >= 0 || fallAmount < TELEPORT_FALL_THRESHOLD) {
            return NoFallCheckResult.clean();
        }

        // 排除合法情况
        if (isElytraFlying || isTeleportCommand) {
            return NoFallCheckResult.clean();
        }

        // 大幅下落但无伤害 — 典型的Teleport+NoFall组合
        if (!tookDamage && fallAmount >= TELEPORT_FALL_THRESHOLD) {
            List<String> reasons = new ArrayList<>();
            reasons.add("TELEPORT_NOFALL: instant drop of "
                    + String.format("%.1f", fallAmount) + " blocks (Y "
                    + String.format("%.1f", fromY) + " -> " + String.format("%.1f", toY)
                    + ") with zero damage taken");
            reasons.add("Consistent with VClip + NoFall combination cheat");

            if (fallAmount >= DANGEROUS_FALL_HEIGHT) {
                reasons.add("CRITICAL_TELEPORT_NOFALL: drop distance ("
                        + String.format("%.1f", fallAmount)
                        + " blocks) would cause " + String.format("%.0f", fallAmount - FALL_DAMAGE_HEIGHT)
                        + " damage points normally");
                teleportNoFallViolations.incrementAndGet();
                noFallViolations.incrementAndGet();
                return NoFallCheckResult.flagged(reasons);
            }

            // 小于危险高度但超过阈值
            teleportNoFallViolations.incrementAndGet();
            return NoFallCheckResult.flagged(reasons);
        }

        return NoFallCheckResult.clean();
    }

    /**
     * V5.2 逐tick综合检测入口 — 在一个方法调用中执行所有tick级检测
     *
     * 调用方应在每个玩家移动tick中调用此方法，传入完整的移动和状态数据。
     * 此方法内部协调调用所有V5.2新增的子检测方法。
     *
     * @param playerName          玩家名称
     * @param currentY            玩家当前Y坐标
     * @param previousY           玩家上一tick Y坐标
     * @param yVelocity           玩家Y速度
     * @param clientOnGround      客户端声称的onGround
     * @param serverCalcOnGround  服务端计算的onGround
     * @param tookDamage          本tick是否受到伤害
     * @param isElytraFlying      是否鞘翅飞行
     * @param isTeleportCommand   是否为/tp命令传送
     * @param timestamp           时间戳
     * @return 综合检测结果（合并所有子检测的发现）
     */
    public NoFallCheckResult detect(String playerName,
                                     double currentY, double previousY,
                                     double yVelocity,
                                     boolean clientOnGround, boolean serverCalcOnGround,
                                     boolean tookDamage,
                                     boolean isElytraFlying, boolean isTeleportCommand,
                                     Instant timestamp) {
        if (!config.getSecurity().getSuperEvolution().isAntiNoFall()) {
            return NoFallCheckResult.clean();
        }

        List<String> allReasons = new ArrayList<>();
        boolean anyFlagged = false;
        boolean anySuspicious = false;

        // 1. GroundSpoof检测
        NoFallCheckResult groundSpoofResult = detectGroundSpoof(
                playerName, yVelocity, clientOnGround, timestamp);
        if (groundSpoofResult.isFlagged()) {
            anyFlagged = true;
            allReasons.addAll(groundSpoofResult.getReasons());
        } else if (groundSpoofResult.isSuspicious()) {
            anySuspicious = true;
            allReasons.addAll(groundSpoofResult.getReasons());
        }

        // 2. 数据包级地面状态分析
        NoFallCheckResult packetResult = analyzePacketGroundState(
                playerName, clientOnGround, serverCalcOnGround,
                currentY, yVelocity, timestamp);
        if (packetResult.isFlagged()) {
            anyFlagged = true;
            allReasons.addAll(packetResult.getReasons());
        } else if (packetResult.isSuspicious()) {
            anySuspicious = true;
            allReasons.addAll(packetResult.getReasons());
        }

        // 3. 服务端坠落距离累积
        NoFallCheckResult accumulationResult = checkFallDistanceAccumulation(
                playerName, currentY, yVelocity, serverCalcOnGround,
                tookDamage, timestamp);
        if (accumulationResult.isFlagged()) {
            anyFlagged = true;
            allReasons.addAll(accumulationResult.getReasons());
        } else if (accumulationResult.isSuspicious()) {
            anySuspicious = true;
            allReasons.addAll(accumulationResult.getReasons());
        }

        // 4. 传送式NoFall检测
        NoFallCheckResult teleportResult = detectTeleportNoFall(
                playerName, previousY, currentY, tookDamage,
                isElytraFlying, isTeleportCommand, timestamp);
        if (teleportResult.isFlagged()) {
            anyFlagged = true;
            allReasons.addAll(teleportResult.getReasons());
        } else if (teleportResult.isSuspicious()) {
            anySuspicious = true;
            allReasons.addAll(teleportResult.getReasons());
        }

        if (anyFlagged) {
            return NoFallCheckResult.flagged(allReasons);
        } else if (anySuspicious) {
            return NoFallCheckResult.suspicious(allReasons);
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
        // V5.2 新增数据结构清理
        playerGroundSpoofTicks.remove(playerName);
        playerGroundStateHistory.remove(playerName);
        playerAccumulatedFallDistance.remove(playerName);
        playerFallStartY.remove(playerName);
        playerServerSideAirborne.remove(playerName);
        playerLastY.remove(playerName);
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
        status.put("groundSpoofViolations", groundSpoofViolations.get());
        status.put("teleportNoFallViolations", teleportNoFallViolations.get());
        status.put("activeTrackedPlayers", playerFallHistory.size());
        status.put("playersInFall", activeFalls.size());
        status.put("playersInGroundSpoof", playerGroundSpoofTicks.size());
        status.put("playersAccumulatingFall", playerAccumulatedFallDistance.size());

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

        // V5.2: 列出正在伪造ground的玩家
        List<Map<String, Object>> groundSpoofPlayers = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : playerGroundSpoofTicks.entrySet()) {
            if (entry.getValue() >= 1) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("spoofTicks", entry.getValue());
                groundSpoofPlayers.add(info);
            }
        }
        status.put("groundSpoofPlayers", groundSpoofPlayers);

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
     * V5.2 地面状态记录 — 存储每次地面状态数据包分析的结果
     * 用于逐tick的客户端/服务端onGround交叉对比
     */
    private static class GroundStateRecord {
        final Instant timestamp;
        final boolean clientOnGround;
        final boolean serverCalcOnGround;
        final double playerY;
        final double yVelocity;

        GroundStateRecord(Instant timestamp, boolean clientOnGround,
                          boolean serverCalcOnGround, double playerY,
                          double yVelocity) {
            this.timestamp = timestamp;
            this.clientOnGround = clientOnGround;
            this.serverCalcOnGround = serverCalcOnGround;
            this.playerY = playerY;
            this.yVelocity = yVelocity;
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
