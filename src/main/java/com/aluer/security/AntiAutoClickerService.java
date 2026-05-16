package com.aluer.security;

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
 * 自动点击检测 (Auto Clicker/Macro) — V4.0 玩家行为安全模块
 *
 * 检测原理：
 *   Auto Clicker（自动点击器/宏）通过模拟鼠标点击来获得非法的PvP优势或挂机优势。
 *   本模块通过多种统计分析方法来区分人类操作和自动化操作：
 *   1. CPS 频率检测——正常人类 CPS（每秒点击次数）上限约 12-15，持续超过 15 CPS 判定异常。
 *   2. 香农熵值分析——人类点击间隔存在自然的随机抖动（熵值高 > 3.5），
 *      宏/连点器生成的点击间隔极其均匀（熵值低 < 2.0），这是核心区分手段。
 *   3. 持续高 CPS 检测——短时间爆发高 CPS 可能是紧张操作，但连续超过 10 秒维持 > 15 CPS
 *      则是绝对宏行为。
 *   4. 点击模式周期性——自动点击器的点击间隔中位数与标准差比值异常（标准差/均值 < 0.05）。
 *
 * 配置开关：serverguard.security.super-evolution.anti-auto-clicker
 */
@Service
public class AntiAutoClickerService {

    private final ServerGuardConfig config;
    private final Map<String, List<ClickEvent>> playerClickRecords = new ConcurrentHashMap<>();
    private final Map<String, Instant> flaggedPlayers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 被追踪的玩家总数 */
    private final AtomicLong totalPlayers = new AtomicLong(0);
    /** 高 CPS 检测次数 */
    private final AtomicLong highCpsCount = new AtomicLong(0);
    /** 宏/连点器疑似次数 */
    private final AtomicLong macroSuspected = new AtomicLong(0);

    /** 正常人类 CPS 上限 */
    private static final double MAX_NORMAL_CPS = 15.0;

    /** 持续高 CPS 判定时间阈值（秒）——超过此时间维持高CPS判定为宏 */
    private static final long HIGH_CPS_DURATION_THRESHOLD_SEC = 10;

    /** 香农熵正常人类下限——低于此值说明点击间隔过于均匀 */
    private static final double MIN_ENTROPY_HUMAN = 2.0;

    /** 点击间隔变异系数阈值——标准差/均值低于此值为机械点击 */
    private static final double MAX_COV_MECHANICAL = 0.08;

    /** 计算 CPS 的时间窗口（秒） */
    private static final long CPS_WINDOW_SEC = 1;

    /** 玩家记录保留时间（秒） */
    private static final long RECORD_RETENTION_SECONDS = 600;

    /** 标记玩家持续时间（秒） */
    private static final long FLAG_DURATION_SECONDS = 1800;

    public AntiAutoClickerService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiAutoClickerService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldRecords, 120, 300, TimeUnit.SECONDS);
    }

    /**
     * 记录一次点击事件（左键攻击或右键交互），并检测是否为自动点击行为。
     *
     * 实现说明：
     *   每次点击事件记录其时间戳，通过分析连续点击的时间间隔序列，
     *   计算 CPS、熵值和变异系数来区分人类和宏操作。
     *
     * @param playerName 玩家名称
     * @param playerUUID 玩家 UUID
     * @param clickType  点击类型（"LEFT_CLICK" 攻击 / "RIGHT_CLICK" 交互）
     * @return 检测结果
     */
    public DetectionResult detect(String playerName, String playerUUID, String clickType) {
        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiAutoClicker()) {
            return DetectionResult.clean();
        }

        Instant now = Instant.now();
        List<ClickEvent> records = playerClickRecords.computeIfAbsent(playerName,
            k -> Collections.synchronizedList(new ArrayList<>()));

        // 记录点击事件
        ClickEvent event = new ClickEvent(now, clickType);
        records.add(event);

        // 首次追踪此玩家时增加计数
        if (records.size() == 1) {
            totalPlayers.incrementAndGet();
        }

        // 至少需要 10 个点击样本才能进行有效分析
        if (records.size() < 10) {
            return DetectionResult.clean();
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // === 检测 1: CPS 频率检测 ===
        // 计算最近 1 秒内的点击次数
        long cpsWindowStart = now.toEpochMilli() - (CPS_WINDOW_SEC * 1000);
        long clicksInWindow = records.stream()
            .filter(r -> r.time.toEpochMilli() > cpsWindowStart)
            .count();
        double currentCps = (double) clicksInWindow / CPS_WINDOW_SEC;

        if (currentCps > MAX_NORMAL_CPS) {
            score += 25;
            reasons.add("HIGH_CPS: " + String.format("%.1f", currentCps) +
                " CPS (max human ~" + MAX_NORMAL_CPS + ")");
            highCpsCount.incrementAndGet();
        }

        // === 检测 2: 持续高 CPS 检测 ===
        // 检查过去 15 秒内是否有持续超过 10 秒的高 CPS 区间
        long extendedWindowStart = now.toEpochMilli() - 15000;
        List<ClickEvent> extendedRecords = records.stream()
            .filter(r -> r.time.toEpochMilli() > extendedWindowStart)
            .toList();

        if (extendedRecords.size() >= 20) {
            // 使用滑动窗口检测持续高 CPS
            long sustainedHighCps = detectSustainedHighCps(extendedRecords);
            if (sustainedHighCps >= HIGH_CPS_DURATION_THRESHOLD_SEC) {
                score += 35;
                reasons.add("SUSTAINED_HIGH_CPS: " + sustainedHighCps +
                    "s continuous > " + MAX_NORMAL_CPS + " CPS (absolute macro indicator)");
            }
        }

        // === 检测 3: 香农熵值分析 ===
        // 计算最近点击间隔的香农熵——人类点击有自然抖动，宏极其均匀
        if (records.size() >= 15) {
            double entropy = calculateClickEntropy(records);
            if (entropy < MIN_ENTROPY_HUMAN) {
                score += 30;
                reasons.add("LOW_ENTROPY: Shannon entropy=" + String.format("%.3f", entropy) +
                    " (mechanical pattern, human > " + MIN_ENTROPY_HUMAN + ")");
            }
        }

        // === 检测 4: 点击间隔变异系数 ===
        // 标准差 / 均值 —— 机械式点击此值极低（< 0.05）
        if (records.size() >= 20) {
            double cov = calculateIntervalCOV(records);
            if (cov < MAX_COV_MECHANICAL) {
                score += 25;
                reasons.add("MECHANICAL_RHYTHM: interval COV=" + String.format("%.4f", cov) +
                    " (mechanical threshold < " + MAX_COV_MECHANICAL + ")");
            }
        }

        if (score >= 50) {
            flaggedPlayers.put(playerName, Instant.now().plusSeconds(FLAG_DURATION_SECONDS));
            macroSuspected.incrementAndGet();
            return DetectionResult.flagged(reasons);
        } else if (score >= 25) {
            return DetectionResult.suspicious(score, reasons);
        }

        return DetectionResult.clean();
    }

    /**
     * 清除指定玩家的所有点击数据。
     *
     * @param playerName 玩家名称
     */
    public void clearPlayer(String playerName) {
        playerClickRecords.remove(playerName);
        flaggedPlayers.remove(playerName);
    }

    /**
     * 获取模块运行状态。
     *
     * @return 包含统计数据的 LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalPlayers", totalPlayers.get());
        s.put("highCpsCount", highCpsCount.get());
        s.put("macroSuspected", macroSuspected.get());
        s.put("trackedPlayers", playerClickRecords.size());
        s.put("flaggedPlayers", flaggedPlayers.size());
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiAutoClicker());

        List<Map<String, Object>> flagged = new ArrayList<>();
        for (Map.Entry<String, Instant> e : flaggedPlayers.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("player", e.getKey());
            m.put("flaggedUntil", e.getValue().toString());
            List<ClickEvent> records = playerClickRecords.get(e.getKey());
            if (records != null) {
                m.put("totalClicks", records.size());
            }
            flagged.add(m);
        }
        s.put("flaggedPlayersList", flagged);

        return s;
    }

    public long getTotalPlayers() { return totalPlayers.get(); }
    public long getHighCpsCount() { return highCpsCount.get(); }
    public long getMacroSuspected() { return macroSuspected.get(); }

    /**
     * 检测在给定记录序列中是否存在持续超过阈值的高 CPS 区间。
     *
     * 使用滑动窗口扫描点击记录，找出在任意时间窗口内平均 CPS 持续超过
     * MAX_NORMAL_CPS 的最长持续时间。返回值为检测到的最长持续秒数。
     *
     * @param records 点击事件列表（按时间排序）
     * @return 最长持续高 CPS 秒数
     */
    private long detectSustainedHighCps(List<ClickEvent> records) {
        if (records.size() < 3) return 0;

        long maxSustainedSec = 0;
        // 使用 2 秒滑动窗口计算
        for (int i = 0; i < records.size(); i++) {
            long windowEnd = records.get(i).time.toEpochMilli();
            long windowStart = windowEnd - 2000; // 2 秒窗口
            int count = 0;
            for (int j = i; j >= 0; j--) {
                if (records.get(j).time.toEpochMilli() > windowStart) {
                    count++;
                } else {
                    break;
                }
            }
            double cps = count / 2.0;
            if (cps > MAX_NORMAL_CPS) {
                // 找到高 CPS 窗口，追溯其开始时间
                long streakStart = records.get(i).time.toEpochMilli();
                for (int j = i - 1; j >= 0; j--) {
                    long jTime = records.get(j).time.toEpochMilli();
                    // 如果前一个点击和此窗口间距太大（> 3 秒），中断连续计算
                    if (i > 0) {
                        long prevTime = records.get(Math.max(0, j)).time.toEpochMilli();
                        if (streakStart - jTime > 3000) break;
                    }
                    streakStart = jTime;
                }
                long durationSec = (records.get(i).time.toEpochMilli() - streakStart) / 1000;
                if (durationSec > maxSustainedSec) {
                    maxSustainedSec = durationSec;
                }
            }
        }
        return maxSustainedSec;
    }

    /**
     * 计算点击间隔序列的香农熵值。
     *
     * 香农熵度量随机性：人类点击有自然抖动，熵值较高（> 3.5）；
     * 宏产生的点击间隔极其均匀，熵值低（< 2.0）。
     * 计算方法：将间隔四舍五入到毫秒，构建频率分布，计算 H = -sum(p * log2(p))。
     *
     * @param records 点击事件列表（按时间排序）
     * @return 香农熵值
     */
    private double calculateClickEntropy(List<ClickEvent> records) {
        if (records.size() < 3) return 0;

        // 提取最近 20 个点击的间隔（毫秒）
        List<Long> intervals = new ArrayList<>();
        int startIdx = Math.max(0, records.size() - 20);
        for (int i = startIdx + 1; i < records.size(); i++) {
            long interval = records.get(i).time.toEpochMilli() -
                records.get(i - 1).time.toEpochMilli();
            intervals.add(interval);
        }

        if (intervals.isEmpty()) return 0;

        // 构建间隔频率分布（将间隔映射到桶中以处理微小波动）
        Map<Long, Integer> frequency = new HashMap<>();
        for (Long interval : intervals) {
            // 将间隔大约分桶到 5ms 精度以容忍微小抖动
            long bucket = Math.round(interval / 5.0) * 5;
            frequency.merge(bucket, 1, Integer::sum);
        }

        // 计算香农熵：H(X) = -sum(p(x) * log2(p(x)))
        double entropy = 0;
        double totalIntervals = intervals.size();
        for (int count : frequency.values()) {
            double probability = count / totalIntervals;
            if (probability > 0) {
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }

        return entropy;
    }

    /**
     * 计算点击间隔的变异系数（Coefficient of Variation）。
     *
     * COV = 标准差 / 均值。机械式点击间隔中变异系数极低，
     * 因为宏/连点器按照固定周期触发。
     *
     * @param records 点击事件列表（按时间排序）
     * @return 变异系数
     */
    private double calculateIntervalCOV(List<ClickEvent> records) {
        if (records.size() < 4) return 1.0;

        List<Long> intervals = new ArrayList<>();
        int startIdx = Math.max(0, records.size() - 30);
        for (int i = startIdx + 1; i < records.size(); i++) {
            long interval = records.get(i).time.toEpochMilli() -
                records.get(i - 1).time.toEpochMilli();
            intervals.add(interval);
        }

        if (intervals.isEmpty()) return 1.0;

        double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
        if (mean == 0) return 1.0;

        double variance = intervals.stream()
            .mapToDouble(i -> Math.pow(i - mean, 2))
            .average()
            .orElse(0);

        return Math.sqrt(variance) / mean;
    }

    /**
     * 定期清理过期的点击记录，避免内存泄漏。
     */
    private void cleanupOldRecords() {
        Instant cutoff = Instant.now().minusSeconds(RECORD_RETENTION_SECONDS);
        playerClickRecords.entrySet().removeIf(e -> {
            List<ClickEvent> records = e.getValue();
            records.removeIf(r -> r.time.isBefore(cutoff));
            return records.isEmpty();
        });
        flaggedPlayers.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    // ==================== 内部数据类 ====================

    /**
     * 点击事件记录——记录每次点击的类型和时间戳。
     */
    private static class ClickEvent {
        final Instant time;
        final String clickType;

        ClickEvent(Instant time, String clickType) {
            this.time = time;
            this.clickType = clickType;
        }
    }

    // ==================== 检测结果类 ====================

    /**
     * 自动点击检测结果。
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

        /** 无异常：点击行为正常 */
        public static DetectionResult clean() {
            return new DetectionResult(false, false, 0, List.of());
        }

        /** 可疑行为：存在异常点击模式但置信度不足 */
        public static DetectionResult suspicious(int score, List<String> reasons) {
            return new DetectionResult(false, true, score, reasons);
        }

        /** 已标记：检测到高置信度自动点击行为 */
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
