package com.aluer.anticheat.movement;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 垂直穿墙（VClip）检测服务 — V5.2 反作弊移动模块
 *
 * 检测原理：
 * 1. 瞬间垂直位移检测 — VClip hack使玩家在单tick内Y坐标变化超过3方块，
 *    中间无任何移动数据包。正常情况下玩家无法在单tick内垂直穿越多个完整方块。
 * 2. 固体方块穿透验证 — 检查玩家起始位置与结束位置之间是否存在固体方块。
 *    如果起始和结束Y坐标之间的所有位置都包含不可穿越的固体方块，则确认为VClip。
 * 3. 合法传送方式区分 — 需要排除以下合法的快速垂直位移：
 *    - 末影珍珠（需要投掷动画+落地伤害）
 *    - 紫颂果（随机8方块以内，有传送粒子效果）
 *    - /tp命令（有日志记录）
 *    - 船/矿车等载具（无中间方块穿透）
 *    - 鞘翅俯冲（有速度渐变过程）
 *    - 水中快速上浮（有水环境）
 * 4. 连续VClip模式检测 — 某些hack允许连续多次VClip实现快速垂直穿梭。
 *    检测短时间内的多次大Y位移事件。
 * 5. 斜向VClip检测 — 某些变种hack同时改变X/Z坐标以规避纯Y检测，
 *    但仍然呈现不合理的垂直穿越模式。
 *
 * 配置开关：serverguard.security.super-evolution.anti-vclip
 */
@Service
public class AntiVClipService {

    private final ServerGuardConfig config;

    /**
     * 追踪每个玩家的移动历史（playerName -> 移动记录列表）
     */
    private final Map<String, List<VClipRecord>> playerMoveHistory = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的VClip事件列表（playerName -> 事件列表）
     */
    private final Map<String, List<Map<String, Object>>> playerVClipEvents = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家的连续VClip次数（playerName -> 连续次数）
     */
    private final Map<String, Integer> playerConsecutiveVClips = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近一次大Y位移的时间戳（playerName -> 时间戳）
     */
    private final Map<String, Instant> playerLastLargeYChange = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近一次末影珍珠使用时间（playerName -> 时间戳）
     */
    private final Map<String, Instant> playerLastEnderPearl = new ConcurrentHashMap<>();

    /**
     * 追踪每个玩家最近一次紫颂果使用时间（playerName -> 时间戳）
     */
    private final Map<String, Instant> playerLastChorusFruit = new ConcurrentHashMap<>();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong vclipViolations = new AtomicLong(0);

    /**
     * VClip最小检测阈值（方块）— 单tick Y变化超过此值
     * 正常跳跃约1.25方块，加上台阶/楼梯等情况，3方块是合理的检测起点
     */
    private static final double VCLIP_MIN_Y_CHANGE = 3.0;

    /**
     * 严重VClip阈值（方块）— Y变化超过此值几乎肯定是VClip
     */
    private static final double SEVERE_VCLIP_Y_CHANGE = 10.0;

    /**
     * 紫颂果最大传送范围（方块）— 合法紫颂果传送在8方块以内
     */
    private static final double CHORUS_FRUIT_MAX_RANGE = 8.0;

    /**
     * 末影珍珠使用后的合法传送窗口（毫秒）
     * 末影珍珠落地后约1-2 tick产生传送
     */
    private static final long ENDER_PEARL_WINDOW_MS = 1000;

    /**
     * 紫颂果使用后的合法传送窗口（毫秒）
     */
    private static final long CHORUS_FRUIT_WINDOW_MS = 500;

    /**
     * 连续VClip事件间隔（毫秒）— 在此间隔内再次VClip视为连续事件
     */
    private static final long CONSECUTIVE_VCLIP_WINDOW_MS = 2000;

    /**
     * 连续VClip违规阈值 — 连续超过此次数标记为系统化VClip使用
     */
    private static final int MAX_CONSECUTIVE_VCLIPS = 2;

    /**
     * 每个玩家保留的最大记录数
     */
    private static final int MAX_RECORDS_PER_PLAYER = 50;

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public AntiVClipService() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关控制
     */
    public AntiVClipService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家是否使用了垂直穿墙（VClip hack）
     *
     * @param playerName          玩家名称
     * @param playerUUID          玩家UUID
     * @param fromX               移动起始X坐标
     * @param fromY               移动起始Y坐标
     * @param fromZ               移动起始Z坐标
     * @param toX                 移动结束X坐标
     * @param toY                 移动结束Y坐标
     * @param toZ                 移动结束Z坐标
     * @param blockBetweenSolid   起始和结束位置之间是否存在固体方块
     *                            调用方需要通过服务端方块查询来确定
     * @param solidBlocksBetween  起始和结束之间的固体方块数量（-1表示未知）
     * @param isUsingEnderPearl   玩家是否刚使用了末影珍珠
     * @param isUsingChorusFruit  玩家是否刚使用了紫颂果
     * @param isTeleportCommand   是否为/tp命令触发的传送（检查权限日志）
     * @param isInVehicle         玩家是否在载具中
     * @param isInWater           玩家是否在水中（排除快速上浮）
     * @param timestamp           时间戳
     * @return 检测结果
     */
    public VClipCheckResult detect(String playerName, String playerUUID,
                                    double fromX, double fromY, double fromZ,
                                    double toX, double toY, double toZ,
                                    boolean blockBetweenSolid,
                                    int solidBlocksBetween,
                                    boolean isUsingEnderPearl,
                                    boolean isUsingChorusFruit,
                                    boolean isTeleportCommand,
                                    boolean isInVehicle,
                                    boolean isInWater,
                                    Instant timestamp) {
        // 模块开关检查 — 关闭时跳过所有检测
        if (!config.getSecurity().getSuperEvolution().isAntiVClip()) {
            return VClipCheckResult.clean();
        }

        totalChecks.incrementAndGet();

        double dy = toY - fromY;
        double absDy = Math.abs(dy);
        double dx = toX - fromX;
        double dz = toZ - fromZ;
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);

        // 更新末影珍珠/紫颂果使用时间
        if (isUsingEnderPearl) {
            playerLastEnderPearl.put(playerName, timestamp);
        }
        if (isUsingChorusFruit) {
            playerLastChorusFruit.put(playerName, timestamp);
        }

        List<VClipRecord> history = playerMoveHistory.computeIfAbsent(
                playerName, k -> new ArrayList<>());

        VClipRecord record = new VClipRecord(timestamp, fromX, fromY, fromZ,
                toX, toY, toZ, dy, absDy, horizontalDist, blockBetweenSolid,
                solidBlocksBetween);
        history.add(record);
        while (history.size() > MAX_RECORDS_PER_PLAYER) {
            history.remove(0);
        }

        // Y变化不够大 — 不可能是VClip
        if (absDy < VCLIP_MIN_Y_CHANGE) {
            // 检查是否值得重置连续VClip计数
            if (horizontalDist < 1.0 && absDy < 1.0) {
                // 正常微小移动，可重置计数
                Integer consecutive = playerConsecutiveVClips.get(playerName);
                if (consecutive != null && consecutive > 0) {
                    long lastLargeChange = playerLastLargeYChange.getOrDefault(
                            playerName, Instant.EPOCH).toEpochMilli();
                    if (timestamp.toEpochMilli() - lastLargeChange > CONSECUTIVE_VCLIP_WINDOW_MS) {
                        playerConsecutiveVClips.remove(playerName);
                    }
                }
            }
            return VClipCheckResult.clean();
        }

        // 记录大Y位移时间
        playerLastLargeYChange.put(playerName, timestamp);

        List<String> reasons = new ArrayList<>();

        // ─── 合法传送方式的排除检查 ───
        boolean legitimateVerticalMove = false;

        // 末影珍珠检查
        Instant lastPearl = playerLastEnderPearl.get(playerName);
        if (lastPearl != null) {
            long msSincePearl = timestamp.toEpochMilli() - lastPearl.toEpochMilli();
            if (msSincePearl <= ENDER_PEARL_WINDOW_MS) {
                // 末影珍珠传送距离可以很大，且是合法的
                if (absDy <= 300) { // Minecraft世界中末影珍珠最大射程
                    legitimateVerticalMove = true;
                }
            }
        }

        // 紫颂果检查
        Instant lastChorus = playerLastChorusFruit.get(playerName);
        if (lastChorus != null) {
            long msSinceChorus = timestamp.toEpochMilli() - lastChorus.toEpochMilli();
            if (msSinceChorus <= CHORUS_FRUIT_WINDOW_MS) {
                // 紫颂果传送范围在8方块以内
                if (absDy <= CHORUS_FRUIT_MAX_RANGE) {
                    legitimateVerticalMove = true;
                }
            }
        }

        // /tp命令检查
        if (isTeleportCommand) {
            legitimateVerticalMove = true;
        }

        // 载具中的垂直移动（如船掉落/气泡柱上浮）
        if (isInVehicle) {
            // 载具移动是服务端控制的，玩家无法直接操控VClip
            legitimateVerticalMove = true;
        }

        // 水中上浮 — 灵魂沙气泡柱可快速上浮
        if (isInWater && dy > 0 && absDy < 20) {
            // 气泡柱上浮速度约11方块/秒，单tick约0.55方块
            // 但多个tick累积可能一次性处理，保守处理
            if (absDy < 15) {
                legitimateVerticalMove = true;
            }
        }

        // ─── 核心VClip检测 ───

        // 检测1：固体方块穿越
        if (blockBetweenSolid && !legitimateVerticalMove) {
            reasons.add("SOLID_BLOCK_PENETRATION: moved " + String.format("%.1f", absDy)
                    + " blocks vertically (from Y=" + String.format("%.1f", fromY)
                    + " to Y=" + String.format("%.1f", toY) + ") through "
                    + (solidBlocksBetween >= 0 ? solidBlocksBetween + " solid blocks" : "solid blocks"));
            vclipViolations.incrementAndGet();
        }

        // 检测2：极端垂直位移 — 超过严重阈值且无合法理由
        if (absDy >= SEVERE_VCLIP_Y_CHANGE && !legitimateVerticalMove) {
            if (!blockBetweenSolid) {
                // 即使中间没有固体方块（可能是空气柱），如此大的单tick位移也不正常
                // 需要检查水平位移是否也很小（纯垂直穿越）
                if (horizontalDist < 2.0) {
                    reasons.add("EXTREME_VERTICAL_SHIFT: " + String.format("%.1f", absDy)
                            + " blocks pure vertical movement in one tick"
                            + " (horizontal: " + String.format("%.2f", horizontalDist) + ")");
                    vclipViolations.incrementAndGet();
                } else if (horizontalDist < absDy * 0.5) {
                    // 斜向但以垂直为主，也高度可疑
                    reasons.add("DIAGONAL_VCLIP: " + String.format("%.1f", absDy)
                            + " blocks vertical with only " + String.format("%.1f", horizontalDist)
                            + " blocks horizontal displacement");
                }
            }
        }

        // 检测3：无合法理由的大Y位移 + 无中间过渡
        if (!legitimateVerticalMove && absDy >= VCLIP_MIN_Y_CHANGE) {
            // 检查是否水平位移极小（纯垂直穿越的典型特征）
            if (horizontalDist < 0.5 && absDy >= 5.0) {
                reasons.add("PURE_VERTICAL_PHASE: " + String.format("%.1f", absDy)
                        + " blocks vertical with negligible horizontal movement");
                vclipViolations.incrementAndGet();
            }

            // 检查位移大小与合法方式不匹配
            if (absDy > CHORUS_FRUIT_MAX_RANGE && !legitimateVerticalMove && !blockBetweenSolid) {
                // 超过紫颂果范围且无固体方块穿透证据 — 添加可疑标记
                reasons.add("UNEXPLAINED_LARGE_Y_CHANGE: " + String.format("%.1f", absDy)
                        + " blocks Y change with no legitimate source identified");
            }
        }

        // ─── 检测4：连续VClip模式 ───
        if (!legitimateVerticalMove && absDy >= VCLIP_MIN_Y_CHANGE) {
            int consecutiveVClips = playerConsecutiveVClips.getOrDefault(playerName, 0) + 1;
            playerConsecutiveVClips.put(playerName, consecutiveVClips);

            // 记录事件
            List<Map<String, Object>> events = playerVClipEvents.computeIfAbsent(
                    playerName, k -> new ArrayList<>());
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("time", timestamp.toString());
            event.put("dy", String.format("%.1f", absDy));
            event.put("fromY", String.format("%.2f", fromY));
            event.put("toY", String.format("%.2f", toY));
            event.put("solidBlocks", solidBlocksBetween);
            events.add(event);
            while (events.size() > 20) {
                events.remove(0);
            }

            if (consecutiveVClips >= MAX_CONSECUTIVE_VCLIPS) {
                reasons.add("CONSECUTIVE_VCLIPS: " + consecutiveVClips
                        + " consecutive large Y movements detected");
                vclipViolations.incrementAndGet();
            }
        }

        // ─── 检测5：历史模式分析 ───
        if (history.size() >= 10) {
            long largeYChanges = history.stream()
                    .filter(r -> r.absDy >= VCLIP_MIN_Y_CHANGE)
                    .count();
            if (largeYChanges >= 4 && history.size() <= 30) {
                reasons.add("FREQUENT_LARGE_Y_CHANGES: " + largeYChanges
                        + " large Y changes in last " + history.size()
                        + " moves (possible VClip pattern)");
            }
        }

        if (reasons.size() >= 2) {
            return VClipCheckResult.flagged(reasons);
        } else if (reasons.size() == 1) {
            return VClipCheckResult.suspicious(reasons);
        }

        return VClipCheckResult.clean();
    }

    /**
     * 玩家离线时清理追踪数据
     * @param playerName 离线玩家名称
     */
    public void clearPlayer(String playerName) {
        playerMoveHistory.remove(playerName);
        playerVClipEvents.remove(playerName);
        playerConsecutiveVClips.remove(playerName);
        playerLastLargeYChange.remove(playerName);
        playerLastEnderPearl.remove(playerName);
        playerLastChorusFruit.remove(playerName);
    }

    /**
     * 获取模块运行状态
     * @return 包含计数器和违规数量的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalChecks", totalChecks.get());
        status.put("vclipViolations", vclipViolations.get());
        status.put("activeTrackedPlayers", playerMoveHistory.size());

        // 列出VClip事件较多的玩家
        List<Map<String, Object>> vclipSuspects = new ArrayList<>();
        for (Map.Entry<String, List<Map<String, Object>>> entry : playerVClipEvents.entrySet()) {
            int eventCount = entry.getValue().size();
            if (eventCount >= 1) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("player", entry.getKey());
                info.put("vclipEvents", eventCount);
                info.put("consecutiveVClips",
                        playerConsecutiveVClips.getOrDefault(entry.getKey(), 0));
                vclipSuspects.add(info);
            }
        }
        vclipSuspects.sort((a, b) ->
                Integer.compare((Integer) b.get("vclipEvents"), (Integer) a.get("vclipEvents")));
        status.put("vclipSuspects", vclipSuspects);
        return status;
    }

    /**
     * 内部VClip移动记录 — 记录玩家单次移动的完整数据
     */
    private static class VClipRecord {
        final Instant timestamp;
        final double fromX, fromY, fromZ;
        final double toX, toY, toZ;
        final double dy;
        final double absDy;
        final double horizontalDist;
        final boolean blockBetweenSolid;
        final int solidBlocksBetween;

        VClipRecord(Instant timestamp, double fromX, double fromY, double fromZ,
                    double toX, double toY, double toZ, double dy, double absDy,
                    double horizontalDist, boolean blockBetweenSolid,
                    int solidBlocksBetween) {
            this.timestamp = timestamp;
            this.fromX = fromX; this.fromY = fromY; this.fromZ = fromZ;
            this.toX = toX; this.toY = toY; this.toZ = toZ;
            this.dy = dy;
            this.absDy = absDy;
            this.horizontalDist = horizontalDist;
            this.blockBetweenSolid = blockBetweenSolid;
            this.solidBlocksBetween = solidBlocksBetween;
        }
    }

    /**
     * VClip检测结果 — 不可变结果类
     */
    public static class VClipCheckResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final List<String> reasons;

        private VClipCheckResult(boolean flagged, boolean suspicious, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.reasons = reasons;
        }

        /** 无异常 — 正常的垂直移动或合法的传送方式 */
        public static VClipCheckResult clean() {
            return new VClipCheckResult(false, false, List.of());
        }

        /** 可疑 — Y位移偏大但有合法可能或证据不充分 */
        public static VClipCheckResult suspicious(List<String> reasons) {
            return new VClipCheckResult(false, true, reasons);
        }

        /** 已标记 — 确认VClip hack，穿越固体方块或持续性垂直相位 */
        public static VClipCheckResult flagged(List<String> reasons) {
            return new VClipCheckResult(true, false, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public List<String> getReasons() { return reasons; }
    }
}
