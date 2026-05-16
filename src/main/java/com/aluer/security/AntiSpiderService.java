package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 爬墙（Spider）检测服务 — V5.2 反作弊移动模块
 *
 * 检测原理：
 * 1. 贴墙垂直上升检测 — Minecraft中玩家无法在不使用梯子、藤蔓、脚手架等攀爬方块
 *    的情况下贴墙垂直上升。Spider hack修改客户端与墙壁碰撞逻辑，
 *    使玩家可以向普通固体墙壁移动并以类似爬梯方式上升。
 * 2. 相邻方块类型检查 — 在玩家上升过程中检查其头部/肩部相邻方块是否为固体方块。
 *    如果是固体方块且不是可攀爬方块（梯子/藤蔓/脚手架/垂泪藤/缠怨藤），则为异常。
 * 3. 持续贴墙上升时间追踪 — 追踪玩家连续贴墙并上升的tick数。正常玩家无法维持
 *    贴墙上升状态超过1tick（除非使用攀爬方块），Spider hack用户可持续上升。
 * 4. 水平接触+垂直运动综合分析 — 同时检测玩家水平方向是否紧贴墙壁且
 *    垂直方向持续向上移动，排除跳跃、飞行、鞘翅等合法上升方式。
 *
 * 配置开关：serverguard.security.super-evolution.anti-spider
 */
@Service
public class AntiSpiderService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的移动历史（playerName -> 移动记录列表）
     */
    private final Map<String, List<WallMoveRecord>> playerMoveHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家连续贴墙上升的tick计数（playerName -> 连续tick数）
     */
    private final Map<String, Integer> playerWallClimbTicks = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近的Y坐标（playerName -> Y坐标列表，用于趋势分析）
     */
    private final Map<String, List<Double>> playerYHistory = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong spiderViolations = new AtomicLong(0);

    /**
     * 正常单tick最大垂直上升量（无跳跃）— 正常爬梯约0.2 blocks/tick
     * 超过0.6 blocks/tick的值表明可能存在异常加速上升
     */
    private static final double MAX_NORMAL_CLIMB_PER_TICK = 0.6;

    /**
     * 连续贴墙上升tick阈值 — 超过此值判定为Spider hack
     * 正常玩家即使因bug短暂贴墙，也无法维持4+ ticks
     */
    private static final int MAX_CONSECUTIVE_WALL_CLIMB_TICKS = 4;

    /**
     * 贴墙水平距离阈值（方块）— 玩家XZ距离墙壁边缘在此范围内视为"贴墙"
     */
    private static final double WALL_PROXIMITY_THRESHOLD = 0.4;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiSpiderService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiSpiderService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否在无攀爬方块的情况下贴墙上升（Spider hack）
     *
     * @param playerName        玩家名称
     * @param playerUUID        玩家UUID
     * @param fromX             移动起始X坐标
     * @param fromY             移动起始Y坐标
     * @param fromZ             移动起始Z坐标
     * @param toX               移动结束X坐标
     * @param toY               移动结束Y坐标
     * @param toZ               移动结束Z坐标
     * @param adjacentBlockType 玩家相邻方块类型（SOLID, CLIMBABLE, AIR, LIQUID）
     * @param isClimbableBlock  相邻方块是否为可攀爬方块（梯子/藤蔓/脚手架等）
     * @param isAgainstWall     玩家是否紧贴垂直固体墙壁
     * @param onGround          玩家是否在地面
     * @param isJumping         玩家是否在跳跃中
     * @param timestamp         时间戳
     * @return 检测结果
     */
    public SpiderCheckResult detect(String playerName, String playerUUID,
                                     double fromX, double fromY, double fromZ,
                                     double toX, double toY, double toZ,
                                     String adjacentBlockType, boolean isClimbableBlock,
                                     boolean isAgainstWall, boolean onGround,
                                     boolean isJumping, Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiSpider()) {
            return SpiderCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        double dy = toY - fromY;
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);

        List<WallMoveRecord> history = playerMoveHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());
        List<Double> yHistory = playerYHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        WallMoveRecord record = new WallMoveRecord(timestamp, fromX, fromY, fromZ,
                toX, toY, toZ, dy, horizontalDist, adjacentBlockType,
                isClimbableBlock, isAgainstWall, onGround, isJumping);
        history.add(record);
        yHistory.add(toY);

        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }
        while (yHistory.size() > 30) {
            yHistory.remove(0);
        }

        List<String> reasons = new ArrayList<>();

        // 1. 核心检测：贴墙上升且无攀爬方块
        if (isAgainstWall && dy > 0 && !onGround && !isJumping && !isClimbableBlock) {
            int climbTicks = playerWallClimbTicks.getOrDefault(playerName, 0) + 1;
            playerWallClimbTicks.put(playerName, climbTicks);

            if (climbTicks >= MAX_CONSECUTIVE_WALL_CLIMB_TICKS) {
                spiderViolations.incrementAndGet();
                reasons.add("SUSTAINED_WALL_CLIMB: " + climbTicks
                        + " consecutive ticks climbing solid wall without climbable block"
                        + " (adjacent: " + adjacentBlockType + ", dy="
                        + String.format("%.3f", dy) + ")");
            }
        } else {
            // 不再贴墙上升，重置计数
            playerWallClimbTicks.remove(playerName);
        }

        // 2. 单tick异常上升量检测 — 即使贴墙，单tick上升量也不应超过正常爬梯
        if (isAgainstWall && dy > MAX_NORMAL_CLIMB_PER_TICK && !isJumping) {
            if (!isClimbableBlock) {
                reasons.add("RAPID_WALL_CLIMB: dy=" + String.format("%.3f", dy)
                        + " per tick against " + adjacentBlockType.toLowerCase()
                        + " wall (max normal: "
                        + String.format("%.2f", MAX_NORMAL_CLIMB_PER_TICK) + ")");
            }
        }

        // 3. 贴墙+持续上升趋势检测 — 分析Y坐标的整体趋势
        if (isAgainstWall && !isClimbableBlock && yHistory.size() >= 10) {
            double totalDy = yHistory.get(yHistory.size() - 1) - yHistory.get(0);
            // 如果整体上升超过2方块且一直贴墙，非常可疑
            if (totalDy > 2.0 && !onGround) {
                long wallContactTicks = history.stream()
                        .filter(r -> r.isAgainstWall && !r.isClimbableBlock)
                        .count();
                if (wallContactTicks >= 8) {
                    reasons.add("VERTICAL_WALL_ADVANCEMENT: rose "
                            + String.format("%.1f", totalDy) + " blocks while against"
                            + " solid wall (" + wallContactTicks + " wall-contact ticks)");
                }
            }
        }

        // 4. 水平贴墙+垂直上升模式分析 — Spider的典型移动模式
        //    水平移动极小（紧贴墙壁），垂直持续上升
        if (isAgainstWall && !isClimbableBlock && dy > 0.05 && horizontalDist < 0.2) {
            long pureClimbTicks = history.stream()
                    .filter(r -> r.isAgainstWall && !r.isClimbableBlock
                            && r.dy > 0.05 && r.horizontalDist < 0.3)
                    .count();
            if (pureClimbTicks >= 6) {
                reasons.add("SPIDER_PATTERN: " + pureClimbTicks
                        + " ticks of vertical-only movement against solid wall");
            }
        }

        if (reasons.size() >= 2) {
            return SpiderCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return SpiderCheckResult.suspicious(reasons);
        }

        return SpiderCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerMoveHistory.remove(playerName);
        playerWallClimbTicks.remove(playerName);
        playerYHistory.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("spiderViolations", spiderViolations.get());
        status.put("activeTrackedPlayers", playerMoveHistory.size());

        // 列出当前贴墙的玩家
        List<String> wallClimbers = new ArrayList<>(playerWallClimbTicks.keySet());
        status.put("wallClimbingPlayers", wallClimbers);
        return status;
    }

    /**
     * 内部贴墙移动记录 — 记录玩家贴墙时的移动数据
     */
    private static class WallMoveRecord {
        final Instant timestamp;
        final double fromX, fromY, fromZ;
        final double toX, toY, toZ;
        final double dy;
        final double horizontalDist;
        final String adjacentBlockType;
        final boolean isClimbableBlock;
        final boolean isAgainstWall;
        final boolean onGround;
        final boolean isJumping;

        WallMoveRecord(Instant timestamp, double fromX, double fromY, double fromZ,
                       double toX, double toY, double toZ, double dy,
                       double horizontalDist, String adjacentBlockType,
                       boolean isClimbableBlock, boolean isAgainstWall,
                       boolean onGround, boolean isJumping) {
            this.timestamp = timestamp;
            this.fromX = fromX; this.fromY = fromY; this.fromZ = fromZ;
            this.toX = toX; this.toY = toY; this.toZ = toZ;
            this.dy = dy;
            this.horizontalDist = horizontalDist;
            this.adjacentBlockType = adjacentBlockType;
            this.isClimbableBlock = isClimbableBlock;
            this.isAgainstWall = isAgainstWall;
            this.onGround = onGround;
            this.isJumping = isJumping;
        }
    }

    /**
     * Spider检测结果 — 不可变结果类
     */
    public static class SpiderCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private SpiderCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常使用可攀爬方块或在地面移动 */
        public static SpiderCheckResult clean() {
            return new SpiderCheckResult(false, false, List.of());
        }

        /** 可疑 — 短暂贴墙但不足够确认为Spider hack */
        public static SpiderCheckResult suspicious(List<String> reasons) {
            return new SpiderCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认Spider hack，持续贴固体墙壁上升 */
        public static SpiderCheckResult flagged(List<String> reasons) {
            return new SpiderCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
