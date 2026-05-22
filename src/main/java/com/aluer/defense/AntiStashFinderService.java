package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自动储藏箱探测检测 (StashFinder) — V5.3 世界/玩家/杂物安全模块
 *
 * 检测原理：
 *   Meteor Client 的 StashFinder 模块通过系统性地加载区块来扫描地图，
 *   寻找其他玩家隐藏的容器和储藏点。正常玩家探索具有自然的不规则性——
 *   会停下来与方块交互、改变方向、偶尔中断。StashFinder 则表现出高度
 *   机械化的探测模式。本模块通过以下维度检测：
 *   1. 网格化区块加载——检测玩家是否以完美的网格模式加载区块
 *      （而非自然的蜿蜒路径）。正常移动产生的是不规则的路径，
 *      StashFinder 产生的是等间距的网格遍历。
 *   2. 零交互探测比——统计在探测过程中区块加载数与方块交互数的比率。
 *      正常探索伴随大量交互（挖掘、放置、打开容器），StashFinder 的
 *      区块加载与交互比率极高（加载很多区块但从不与任何东西交互）。
 *   3. 系统化方向序列——检测移动方向是否遵循系统化的扫描模式
 *      （如：蛇形扫描、螺旋扩展、直线往返）。
 *   4. 区块弹跳——检测"加载区块→等待渲染→移动到下一区块"的节奏，
 *      即在每个区块边缘短暂停留然后继续，不进行任何游戏内操作。
 *   5. 加载速度最大化——检测新区块加载速率是否持续接近客户端极限。
 *      正常探索偶尔会快速加载，但不会长时间持续全速加载。
 *
 * 配置开关：serverguard.security.super-evolution.anti-stash-finder
 */
@Service
public class AntiStashFinderService {

    private final ServerGuardConfig config;
    /** 每个玩家的区块进入记录 */
    private final Map<String, List<ChunkEntry>> playerChunkEntries = new ConcurrentHashMap<>();
    /** 每个玩家的交互计数 */
    private final Map<String, AtomicLong> playerInteractionCount = new ConcurrentHashMap<>();
    /** 每个玩家的移动路径记录 */
    private final Map<String, List<MovementPoint>> playerMovementPaths = new ConcurrentHashMap<>();
    /** 每个玩家的方向历史（用于模式分析） */
    private final Map<String, List<DirectionChange>> playerDirectionHistory = new ConcurrentHashMap<>();
    /** 已标记的玩家 */
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong totalChunkEntries = new AtomicLong(0);
    private final AtomicLong stashFinderViolations = new AtomicLong(0);

    /** 网格化移动检测——方向变化的完美一致性阈值 */
    private static final double DIRECTION_UNIFORMITY_THRESHOLD = 0.90;
    /** 零交互区块比阈值——加载 N 个区块却无交互即触发 */
    private static final double ZERO_INTERACT_CHUNK_RATIO = 10.0;
    /** 最少区块数用于比率计算 */
    private static final int MIN_CHUNKS_FOR_RATIO = 10;
    /** 区块加载速率阈值（每分钟）——持续超此速率即异常 */
    private static final int CHUNK_RATE_PER_MINUTE_THRESHOLD = 40;
    /** 系统化扫描判定——连续直线移动最少段数 */
    private static final int MIN_LINEAR_SEGMENTS = 5;
    /** 直线移动容差（度）——方向变化小于此值视为直线 */
    private static final double STRAIGHT_LINE_TOLERANCE_DEG = 10.0;
    /** 网格间距判定——区块间距在此范围内视为等距网格 */
    private static final double GRID_SPACING_TOLERANCE = 0.3;
    /** 最少路径点用于模式分析 */
    private static final int MIN_PATH_POINTS = 15;
    /** 方向切换模式——90 度转向的容忍度 */
    private static final double RIGHT_ANGLE_TOLERANCE_DEG = 15.0;
    /** 区块弹跳停留时间窗口（毫秒） */
    private static final long CHUNK_BOUNCE_PAUSE_MS = 500;
    /** 连续未交互的最大区块加载数 */
    private static final int MAX_CHUNKS_NO_INTERACT = 15;

    /** 记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 900;
    /** 标记持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    /** 8 个基本方向（用于方向序列分析） */
    private enum Direction { N, NE, E, SE, S, SW, W, NW, STILL }

    public AntiStashFinderService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiStashFinderService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 记录一次区块进入事件——玩家进入新区块时调用。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param chunkX     区块 X 坐标（区块坐标，非方块坐标）
     * @param chunkZ     区块 Z 坐标（区块坐标，非方块坐标）
     * @param playerX    玩家当前 X 坐标（世界坐标）
     * @param playerZ    玩家当前 Z 坐标（世界坐标）
     */
    public void recordChunkEntry(String playerName, String playerUUID,
                                  int chunkX, int chunkZ,
                                  double playerX, double playerZ) {
        if (!config.getSecurity().getSuperEvolution().isAntiStashFinder()) {
            return;
        }

        Instant now = Instant.now();
        List<ChunkEntry> chunks = playerChunkEntries.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        chunks.add(new ChunkEntry(now, chunkX, chunkZ, playerX, playerZ));
        totalChunkEntries.incrementAndGet();
    }

    /**
     * 记录一次玩家有意义交互（挖掘、放置、开箱等任意非移动操作）。
     *
     * @param playerName 玩家名称
     */
    public void recordInteraction(String playerName) {
        if (!config.getSecurity().getSuperEvolution().isAntiStashFinder()) {
            return;
        }
        playerInteractionCount.computeIfAbsent(playerName, k -> new AtomicLong(0))
            .incrementAndGet();
    }

    /**
     * 记录一次玩家移动位置更新——用于构建移动路径和方向分析。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param x          玩家 X 坐标
     * @param y          玩家 Y 坐标
     * @param z          玩家 Z 坐标
     */
    public void recordMovement(String playerName, String playerUUID,
                                double x, double y, double z) {
        if (!config.getSecurity().getSuperEvolution().isAntiStashFinder()) {
            return;
        }

        Instant now = Instant.now();
        List<MovementPoint> paths = playerMovementPaths.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));
        paths.add(new MovementPoint(now, x, y, z));

        // 分析方向变化
        if (paths.size() >= 2) {
            MovementPoint prev = paths.get(paths.size() - 2);
            MovementPoint curr = paths.get(paths.size() - 1);
            double dx = curr.x - prev.x;
            double dz = curr.z - prev.z;
            if (Math.sqrt(dx * dx + dz * dz) > 0.05) {
                // 有意义的移动（非微调）
                double angle = Math.toDegrees(Math.atan2(dz, dx));
                Direction dir = quantizeDirection(angle);
                List<DirectionChange> dirHistory = playerDirectionHistory.computeIfAbsent(playerName,
                    k -> Collections.synchronizedList(new ArrayList<>()));
                Direction prevDir = dirHistory.isEmpty() ? null :
                    dirHistory.get(dirHistory.size() - 1).direction;
                dirHistory.add(new DirectionChange(now, dir, prevDir));
            }
        }
    }

    /**
     * 全面检测自动储藏扫描行为——综合分析多个维度。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @return 检测结果
     */
    public DetectionResult detectStashFinder(String playerName, String playerUUID) {
        if (!config.getSecurity().getSuperEvolution().isAntiStashFinder()) {
            return DetectionResult.clean();
        }

        Instant flaggedUntil = flaggedPlayers.get(playerName);
        if (flaggedUntil != null) {
            if (Instant.now().isAfter(flaggedUntil)) {
                flaggedPlayers.remove(playerName);
            } else {
                return DetectionResult.flagged(List.of(
                    "PLAYER_ALREADY_FLAGGED: " + playerName + " under stash-finder investigation"));
            }
        }

        Instant now = Instant.now();
        List<ChunkEntry> chunks = playerChunkEntries.get(playerName);
        List<MovementPoint> movements = playerMovementPaths.get(playerName);
        List<DirectionChange> dirHistory = playerDirectionHistory.get(playerName);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        if (chunks == null || chunks.size() < MIN_CHUNKS_FOR_RATIO) {
            return DetectionResult.clean();
        }

        // === 检测 1: 网格化区块加载 ===
        // 分析区块加载的坐标模式
        if (chunks.size() >= MIN_CHUNKS_FOR_RATIO) {
            double gridScore = analyzeGridPattern(chunks);
            if (gridScore > 0.7) {
                score += 30;
                reasons.add("GRID_PATTERN: chunk loading grid score=" +
                    String.format("%.2f", gridScore) +
                    " (systematic grid scanning, stash-finder pattern)");
            }
        }

        // === 检测 2: 零交互探测比 ===
        long totalChunks = chunks.size();
        long totalInteractions = playerInteractionCount.getOrDefault(playerName,
            new AtomicLong(0)).get();
        if (totalChunks >= MIN_CHUNKS_FOR_RATIO) {
            double chunkToInteractRatio = totalInteractions == 0 ?
                totalChunks : (double) totalChunks / totalInteractions;
            if (chunkToInteractRatio > ZERO_INTERACT_CHUNK_RATIO) {
                score += 30;
                reasons.add("LOW_INTERACTION_RATIO: " + totalChunks + " chunks loaded" +
                    " with only " + totalInteractions +
                    " interactions (ratio=" + String.format("%.1f", chunkToInteractRatio) +
                    ", stash-finder has near-zero world interaction)");
            }

            // 连续未交互区块数
            long consecutiveNoInteract = countConsecutiveNoInteract(chunks, totalInteractions);
            if (consecutiveNoInteract >= MAX_CHUNKS_NO_INTERACT) {
                score += 20;
                reasons.add("CONSECUTIVE_NO_INTERACT: " + consecutiveNoInteract +
                    " consecutive chunks loaded without any world interaction");
            }
        }

        // === 检测 3: 系统化方向序列 ===
        if (dirHistory != null && dirHistory.size() >= MIN_LINEAR_SEGMENTS) {
            double systemScore = analyzeSystematicDirections(dirHistory);
            if (systemScore > 0.7) {
                score += 25;
                reasons.add("SYSTEMATIC_DIRECTION: direction pattern score=" +
                    String.format("%.2f", systemScore) +
                    " (snake scan or spiral pattern detected)");
            }
        }

        // === 检测 4: 区块弹跳 ===
        if (chunks.size() >= 5) {
            int bounceCount = countChunkBounces(chunks);
            if (bounceCount >= 5) {
                score += 20;
                reasons.add("CHUNK_BOUNCE: " + bounceCount +
                    " chunk-to-chunk transitions with brief pause" +
                    " (load→render→move pattern, stash scanning)");
            }
        }

        // === 检测 5: 加载速度最大化 ===
        long oneMinuteAgo = now.toEpochMilli() - 60000;
        long recentChunks = chunks.stream()
            .filter(c -> c.time.toEpochMilli() > oneMinuteAgo)
            .count();
        if (recentChunks > CHUNK_RATE_PER_MINUTE_THRESHOLD) {
            score += 20;
            reasons.add("MAX_CHUNK_RATE: " + recentChunks +
                " chunks loaded in last minute (threshold=" +
                CHUNK_RATE_PER_MINUTE_THRESHOLD + "/min, max-speed scanning)");
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            stashFinderViolations.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 30) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 分析区块加载的网格模式分数（0.0 - 1.0）。
     *
     * 网格化特征：区块坐标形成规则的等间距排列，
     * 而非自然移动产生的随机间距分布。
     */
    private double analyzeGridPattern(List<ChunkEntry> chunks) {
        if (chunks.size() < 8) return 0.0;

        int start = Math.max(0, chunks.size() - 20);
        // 提取最近区块的坐标并计算间距分布
        List<Double> spacings = new ArrayList<>();
        List<ChunkEntry> recent = new ArrayList<>();
        for (int i = start; i < chunks.size(); i++) {
            recent.add(chunks.get(i));
        }

        // 计算相邻区块之间的间距
        for (int i = 1; i < recent.size(); i++) {
            ChunkEntry prev = recent.get(i - 1);
            ChunkEntry curr = recent.get(i);
            double dist = Math.sqrt(
                Math.pow(curr.chunkX - prev.chunkX, 2) +
                Math.pow(curr.chunkZ - prev.chunkZ, 2));
            if (dist > 0) spacings.add(dist);
        }

        if (spacings.size() < 5) return 0.0;

        // 网格化评分：间距的一致性越高，网格特征越强
        double mean = spacings.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        if (mean == 0) return 0.0;

        double variance = spacings.stream()
            .mapToDouble(s -> Math.pow(s - mean, 2))
            .average().orElse(0);
        double cov = Math.sqrt(variance) / mean;

        // COV 低 = 间距高度一致 = 网格化强
        if (cov < 0.2) return 0.9;  // 极高一致性
        if (cov < 0.4) return 0.7;  // 较高一致性
        if (cov < 0.6) return 0.4;  // 中等一致性
        return 0.1;                  // 接近随机
    }

    /**
     * 统计连续加载但无任何交互的区块数量。
     */
    private long countConsecutiveNoInteract(List<ChunkEntry> chunks, long totalInteractions) {
        if (totalInteractions > 0 || chunks.isEmpty()) return 0;
        return chunks.size();
    }

    /**
     * 分析方向序列的系统性分数（0.0 - 1.0）。
     *
     * 蛇形扫描：交替方向 + 若干直线段
     * 螺旋扫描：顺时针或逆时针的 90 度转向序列
     */
    private double analyzeSystematicDirections(List<DirectionChange> dirHistory) {
        if (dirHistory.size() < MIN_LINEAR_SEGMENTS) return 0.0;

        int start = Math.max(0, dirHistory.size() - 30);
        List<DirectionChange> recent = new ArrayList<>();
        for (int i = start; i < dirHistory.size(); i++) {
            recent.add(dirHistory.get(i));
        }

        // 统计 90 度转向的比例（90 度转向是系统化扫描的显著特征）
        int rightAngleTurns = 0;
        int totalTurns = 0;
        for (int i = 1; i < recent.size(); i++) {
            Direction prev = recent.get(i - 1).direction;
            Direction curr = recent.get(i).direction;
            if (prev != curr && prev != Direction.STILL && curr != Direction.STILL) {
                totalTurns++;
                int diff = Math.abs(prev.ordinal() - curr.ordinal());
                // 90 度 = 方向索引差 2（8 方向系统），180 度 = 差 4
                if (diff == 2 || diff == 6) {
                    rightAngleTurns++;
                }
            }
        }

        if (totalTurns < 3) return 0.0;

        double rightAngleRatio = (double) rightAngleTurns / totalTurns;

        // 同时计算连续直线段长度的一致性
        double lineConsistency = calculateLineSegmentConsistency(recent);

        // 综合评分：直角比例 + 直线一致性
        return (rightAngleRatio * 0.5 + lineConsistency * 0.5);
    }

    /**
     * 计算方向序列中直线段长度的一致性（0.0 - 1.0）。
     * 系统化扫描的直线段长度倾向于一致。
     */
    private double calculateLineSegmentConsistency(List<DirectionChange> dirHistory) {
        List<Integer> segmentLengths = new ArrayList<>();
        int currentLength = 1;
        for (int i = 1; i < dirHistory.size(); i++) {
            if (dirHistory.get(i).direction == dirHistory.get(i - 1).direction &&
                dirHistory.get(i).direction != Direction.STILL) {
                currentLength++;
            } else {
                if (currentLength > 1) segmentLengths.add(currentLength);
                currentLength = 1;
            }
        }
        if (currentLength > 1) segmentLengths.add(currentLength);

        if (segmentLengths.size() < 2) return 0.0;

        double mean = segmentLengths.stream().mapToInt(Integer::intValue).average().orElse(0);
        if (mean == 0) return 0.0;

        double variance = segmentLengths.stream()
            .mapToDouble(l -> Math.pow(l - mean, 2))
            .average().orElse(0);
        double cov = Math.sqrt(variance) / mean;

        // 段长一致性越高，系统化程度越高
        if (cov < 0.3) return 0.9;
        if (cov < 0.5) return 0.6;
        return 0.2;
    }

    /**
     * 统计区块弹跳事件数——加载区块后短暂停留再移动到下一区块。
     */
    private int countChunkBounces(List<ChunkEntry> chunks) {
        int bounces = 0;
        int start = Math.max(0, chunks.size() - 20);
        for (int i = start + 1; i < chunks.size() - 1; i++) {
            ChunkEntry prev = chunks.get(i - 1);
            ChunkEntry curr = chunks.get(i);
            ChunkEntry next = chunks.get(i + 1);

            // 检查：不同区块但进入间隔很短
            boolean sameChunk = (curr.chunkX == prev.chunkX && curr.chunkZ == prev.chunkZ);
            boolean nextSameChunk = (next.chunkX == curr.chunkX && next.chunkZ == curr.chunkZ);

            if (!sameChunk && !nextSameChunk) {
                long stayMs = next.time.toEpochMilli() - curr.time.toEpochMilli();
                if (stayMs < CHUNK_BOUNCE_PAUSE_MS) {
                    bounces++;
                }
            }
        }
        return bounces;
    }

    /**
     * 将角度量化为 8 个基本方向之一。
     */
    private Direction quantizeDirection(double angleDeg) {
        // 标准化到 [0, 360)
        double normalized = ((angleDeg % 360) + 360) % 360;
        // N=0, NE=45, E=90, SE=135, S=180, SW=225, W=270, NW=315
        int sector = (int) Math.round(normalized / 45.0) % 8;
        return Direction.values()[sector];
    }

    public void clearPlayer(String playerName) {
        playerChunkEntries.remove(playerName);
        playerInteractionCount.remove(playerName);
        playerMovementPaths.remove(playerName);
        playerDirectionHistory.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalChunkEntries", totalChunkEntries.get());
        s.put("stashFinderViolations", stashFinderViolations.get());
        s.put("trackedPlayers", playerChunkEntries.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiStashFinder());
        return s;
    }

    public long getTotalChunkEntries() { return totalChunkEntries.get(); }
    public long getStashFinderViolations() { return stashFinderViolations.get(); }

    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerChunkEntries.entrySet().removeIf(e -> {
            List<ChunkEntry> list = e.getValue();
            list.removeIf(c -> c.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerMovementPaths.entrySet().removeIf(e -> {
            List<MovementPoint> list = e.getValue();
            list.removeIf(m -> m.time.isBefore(cutoff));
            return list.isEmpty();
        });
        playerDirectionHistory.entrySet().removeIf(e -> {
            List<DirectionChange> list = e.getValue();
            list.removeIf(d -> d.time.isBefore(cutoff));
            return list.isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 区块进入记录——追踪玩家每次进入新区块的坐标和时间。
     */
    private static class ChunkEntry {
        final Instant time;
        final int chunkX, chunkZ;    // 区块坐标
        final double playerX, playerZ; // 进入时玩家的世界坐标

        ChunkEntry(Instant time, int chunkX, int chunkZ, double playerX, double playerZ) {
            this.time = time;
            this.chunkX = chunkX;
            this.chunkZ = chunkZ;
            this.playerX = playerX;
            this.playerZ = playerZ;
        }
    }

    /**
     * 移动路径点——追踪玩家移动轨迹用于扫描模式分析。
     */
    private static class MovementPoint {
        final Instant time;
        final double x, y, z;

        MovementPoint(Instant time, double x, double y, double z) {
            this.time = time;
            this.x = x;
            this.y = y;
            this.z = z;
        }
    }

    /**
     * 方向变化记录——追踪每次有意义的移动方向变更。
     */
    private static class DirectionChange {
        final Instant time;
        final Direction direction;
        final Direction previousDirection; // 可为 null

        DirectionChange(Instant time, Direction direction, Direction previousDirection) {
            this.time = time;
            this.direction = direction;
            this.previousDirection = previousDirection;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 自动储藏箱探测检测结果。
     */
    public static class DetectionResult {
        private final boolean flagged;
        private final boolean suspicious;
        private final int score;
        private final List<String> reasons;

        private DetectionResult(boolean flagged, boolean suspicious, int score, List<String> reasons) {
            this.flagged = flagged;
            this.suspicious = suspicious;
            this.score = score;
            this.reasons = reasons;
        }

        /** 无异常：探索行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在 StashFinder 特征但置信度不足 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度 StashFinder 行为 */
        public static DetectionResult flagged(List<String> reasons) {
            return new DetectionResult(true, true, 100, reasons);
        }

        public boolean isFlagged() { return flagged; }
        public boolean isSuspicious() { return suspicious; }
        public boolean isClean() { return !flagged && !suspicious; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
