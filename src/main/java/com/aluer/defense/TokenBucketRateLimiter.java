package com.aluer.defense;

import com.aluer.config.ServerGuardConfig;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 高性能令牌桶（Token Bucket）速率限制器 — 可复用限速原语
 *
 * 算法原理：
 * 经典令牌桶算法：以固定速率R（令牌/秒）向桶中添加令牌，桶容量上限B（突发容量）。
 * 每次请求需要消耗N个令牌，如果桶中令牌不足则拒绝。
 * 这种算法天然允许一定程度的突发流量（最多B个），同时保证长期速率不超过R。
 *
 * 应用场景：
 * 1. 数据包速率限制（PacketRateLimiter）— 限制每个玩家的发包速率
 * 2. 连接速率限制（ConnectionThrottle）— 限制每个IP的连接建立速率
 * 3. 聊天洪水防护（ChatFlood）— 限制每个玩家的消息发送速率
 * 4. 命令频率限制 — 限制敏感命令的执行频率
 *
 * 线程安全设计：
 * - ConcurrentHashMap 存储所有桶状态（按key索引）
 * - 每个桶内部的 check-refill-consume 操作在 synchronized 块内完成，保证原子性
 * - 定期清理超时未访问的陈旧桶以释放内存
 *
 * 配置开关：serverguard.security.super-evolution.token-bucket-rate-limiter
 */
@Service
public class TokenBucketRateLimiter {

    private final ServerGuardConfig config;

    /**
     * 存储所有限速桶的状态（key → 桶状态）
     * key可以是IP地址、玩家UUID或任意自定义标识符
     */
    private final Map<String, BucketState> buckets = new ConcurrentHashMap<>();

    /**
     * 追踪每个key的最后访问时间（用于清理陈旧桶）
     */
    private final Map<String, Long> lastAccessTime = new ConcurrentHashMap<>();

    /**
     * 被拒绝的请求计数统计
     */
    private final AtomicLong totalAttempts = new AtomicLong(0);
    private final AtomicLong totalAccepted = new AtomicLong(0);
    private final AtomicLong totalRefused = new AtomicLong(0);

    /**
     * 默认令牌填充速率（令牌/秒）
     * 可通过 ServerGuardConfig 自定义
     */
    private static final double DEFAULT_RATE = 10.0;

    /**
     * 默认桶容量（最大突发令牌数）
     */
    private static final double DEFAULT_CAPACITY = 20.0;

    /**
     * 陈旧桶清理间隔（毫秒）— 超过此时间未访问的桶将被清理
     */
    private static final long STALE_BUCKET_MS = 5 * 60 * 1000;

    /**
     * 上次执行清理的时间戳
     */
    private volatile long lastCleanupTime = System.currentTimeMillis();

    /**
     * 无参构造函数 — 测试/默认配置使用
     */
    public TokenBucketRateLimiter() {
        this(new ServerGuardConfig());
    }

    /**
     * Spring 注入构造函数
     * @param config 全局配置，提供模块开关和限速参数
     */
    public TokenBucketRateLimiter(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 尝试从指定key的桶中消耗1个令牌
     *
     * @param key 限速标识符（IP地址、玩家UUID等）
     * @return true=消耗成功（允许），false=令牌不足（拒绝）
     */
    public boolean tryConsume(String key) {
        return tryConsume(key, 1.0, DEFAULT_RATE, DEFAULT_CAPACITY);
    }

    /**
     * 尝试从指定key的桶中消耗指定数量的令牌
     *
     * @param key    限速标识符
     * @param tokens 需要消耗的令牌数量
     * @return true=消耗成功，false=令牌不足
     */
    public boolean tryConsume(String key, double tokens) {
        return tryConsume(key, tokens, DEFAULT_RATE, DEFAULT_CAPACITY);
    }

    /**
     * 尝试从指定key的桶中消耗指定数量的令牌（自定义速率和容量）
     *
     * @param key      限速标识符
     * @param tokens   需要消耗的令牌数量
     * @param rate     令牌填充速率（令牌/秒）
     * @param capacity 桶最大容量（突发令牌数）
     * @return true=消耗成功（允许通过），false=令牌不足（被限速拒绝）
     */
    public boolean tryConsume(String key, double tokens, double rate, double capacity) {
        totalAttempts.incrementAndGet();

        if (!config.getSecurity().getSuperEvolution().isTokenBucketRateLimiter()) {
            totalAccepted.incrementAndGet();
            return true; // 模块关闭时全部放行
        }

        // 定期清理陈旧桶
        long now = System.currentTimeMillis();
        if (now - lastCleanupTime > 60_000) {
            cleanupStaleBuckets();
            lastCleanupTime = now;
        }

        lastAccessTime.put(key, now);

        BucketState bucket = buckets.computeIfAbsent(key, k -> new BucketState(capacity));
        boolean result = bucket.tryConsume(rate, capacity, tokens);

        if (result) {
            totalAccepted.incrementAndGet();
        } else {
            totalRefused.incrementAndGet();
        }

        return result;
    }

    /**
     * 获取指定key的桶中当前可用令牌数
     *
     * @param key 限速标识符
     * @return 当前可用令牌数（含本次调用的补充）
     */
    public double getAvailableTokens(String key) {
        return getAvailableTokens(key, DEFAULT_RATE, DEFAULT_CAPACITY);
    }

    /**
     * 获取指定key的桶中当前可用令牌数（自定义参数）
     *
     * @param key      限速标识符
     * @param rate     令牌填充速率
     * @param capacity 桶最大容量
     * @return 当前可用令牌数
     */
    public double getAvailableTokens(String key, double rate, double capacity) {
        BucketState bucket = buckets.get(key);
        if (bucket == null) {
            return capacity; // 未初始化的桶视为满的
        }
        synchronized (bucket) {
            bucket.refill(rate, capacity);
            return bucket.tokens;
        }
    }

    /**
     * 重置指定key的令牌桶（充满至容量上限）
     *
     * @param key 限速标识符
     */
    public void resetBucket(String key) {
        BucketState bucket = buckets.get(key);
        if (bucket != null) {
            synchronized (bucket) {
                bucket.tokens = bucket.capacity;
                bucket.lastRefillTimeMs = System.currentTimeMillis();
            }
        }
    }

    /**
     * 手动设置指定key的桶容量和令牌数（用于运行时动态调整）
     *
     * @param key      限速标识符
     * @param capacity 新容量
     */
    public void setBucketCapacity(String key, double capacity) {
        BucketState bucket = buckets.computeIfAbsent(key, k -> new BucketState(capacity));
        synchronized (bucket) {
            bucket.capacity = capacity;
            bucket.tokens = Math.min(bucket.tokens, capacity);
        }
    }

    /**
     * 完全移除指定key的桶（如玩家离线时释放资源）
     *
     * @param key 限速标识符
     */
    public void removeBucket(String key) {
        buckets.remove(key);
        lastAccessTime.remove(key);
    }

    /**
     * 获取模块运行状态
     *
     * @return 包含通过/拒绝计数、活跃桶数等统计信息的Map
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalAttempts", totalAttempts.get());
        status.put("totalAccepted", totalAccepted.get());
        status.put("totalRefused", totalRefused.get());
        status.put("activeBuckets", buckets.size());

        double acceptRate = 0;
        long attempts = totalAttempts.get();
        if (attempts > 0) {
            acceptRate = (double) totalAccepted.get() / attempts * 100.0;
        }
        status.put("acceptRate", String.format("%.2f%%", acceptRate));
        return status;
    }

    /**
     * 清理超过5分钟未访问的陈旧桶，释放内存
     */
    private void cleanupStaleBuckets() {
        long now = System.currentTimeMillis();
        long cutoff = now - STALE_BUCKET_MS;

        List<String> staleKeys = new ArrayList<>();
        for (Map.Entry<String, Long> entry : lastAccessTime.entrySet()) {
            if (entry.getValue() < cutoff) {
                staleKeys.add(entry.getKey());
            }
        }

        for (String key : staleKeys) {
            buckets.remove(key);
            lastAccessTime.remove(key);
        }
    }

    /**
     * 内部令牌桶状态 — 使用 synchronized 保证 check-refill-consume 的原子性
     *
     * 设计说明：
     * 不使用 AtomicReference 是因为令牌补充和消耗是一个"读取→计算→写入"的多步骤操作，
     * 必须作为原子事务执行。synchronized 比 CAS 自旋在此场景下更清晰可靠。
     */
    private static class BucketState {
        /** 当前令牌数 */
        double tokens;

        /** 桶最大容量 */
        double capacity;

        /** 上次补充时间戳（毫秒） */
        long lastRefillTimeMs;

        /**
         * @param capacity 桶的初始容量（初始时桶是满的）
         */
        BucketState(double capacity) {
            this.tokens = capacity;
            this.capacity = capacity;
            this.lastRefillTimeMs = System.currentTimeMillis();
        }

        /**
         * 尝试消耗令牌 — 先补充再检查，整个操作在调用方的 synchronized 块中执行
         *
         * @param rate      补充速率（令牌/秒）
         * @param capacity  桶容量上限
         * @param requested 请求消耗的令牌数
         * @return true=消耗成功，false=令牌不足
         */
        synchronized boolean tryConsume(double rate, double capacity, double requested) {
            refill(rate, capacity);
            if (tokens >= requested) {
                tokens -= requested;
                return true;
            }
            return false;
        }

        /**
         * 按时间比例补充令牌 — 令牌数 = min(容量, 当前令牌 + 经过时间 * 填充速率)
         * 防止长时间离线后一次性获得大量令牌，实际生产环境中 long offline 后
         * 桶应重置为满，但这里保持经典实现：最多补充到容量上限。
         */
        void refill(double rate, double capacity) {
            long now = System.currentTimeMillis();
            double elapsedSeconds = (now - lastRefillTimeMs) / 1000.0;

            // 防止时钟回拨导致的负偏移
            if (elapsedSeconds < 0) {
                elapsedSeconds = 0;
            }

            // 限制单次补充量不超过容量（防止长时间不活动后积攒过多）
            tokens = Math.min(capacity, tokens + elapsedSeconds * rate);
            lastRefillTimeMs = now;
        }
    }

    /**
     * 限速检查结果 — 不可变结果类
     * 与项目其他security模块保持一致的 clean/blocked 命名约定
     */
    public static class RateLimitResult {
        private final boolean allowed;
        private final boolean blocked;
        private final double availableTokens;
        private final String reason;

        private RateLimitResult(boolean allowed, boolean blocked, double availableTokens, String reason) {
            this.allowed = allowed;
            this.blocked = blocked;
            this.availableTokens = availableTokens;
            this.reason = reason;
        }

        /** 通过限速检查 — 正常放行 */
        public static RateLimitResult clean() {
            return new RateLimitResult(true, false, 0, null);
        }

        /** 被限速拒绝 — 令牌不足 */
        public static RateLimitResult blocked(double availableTokens) {
            return new RateLimitResult(false, true, availableTokens,
                    "Rate limit exceeded, available tokens: " + String.format("%.2f", availableTokens));
        }

        public boolean isAllowed() { return allowed; }
        public boolean isBlocked() { return blocked; }
        public double getAvailableTokens() { return availableTokens; }
        public String getReason() { return reason; }
    }
}
