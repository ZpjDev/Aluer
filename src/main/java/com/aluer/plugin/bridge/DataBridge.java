package com.aluer.plugin.bridge;

import com.aluer.model.AlertEvent;
import com.aluer.model.AlertType;
import com.aluer.model.MetricsData;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * 数据桥接中心 — Bukkit 事件与安全服务之间的实时数据中枢
 *
 * 职责：
 * 1. 维护所有在线玩家的实时快照（位置、速度、攻击记录等）
 * 2. 采集 TPS、连接数等服务器级指标
 * 3. 接收 Bukkit 监听器推送的原始事件并转换为 AlertEvent
 * 4. 为安全服务提供实时查询接口
 * 5. 将告警事件投递至 ServerGuardService 的告警处理管道
 *
 * 所有方法均为线程安全设计（ConcurrentHashMap + AtomicReference）
 */
@Service
public class DataBridge {
    private static final Logger logger = LoggerFactory.getLogger(DataBridge.class);

    // ─── 玩家状态 ──────────────────────────────────────

    /** 在线玩家实时快照（UUID → 快照） */
    private final ConcurrentHashMap<UUID, PlayerSnapshot> players = new ConcurrentHashMap<>();

    // ─── 服务器指标 ────────────────────────────────────

    /** 当前 TPS（20.0 = 满速） */
    private final ConcurrentHashMap<String, AtomicLong> eventCounters = new ConcurrentHashMap<>();

    /** 告警事件生产者（由 ServerGuardService 注入） */
    private volatile Consumer<AlertEvent> alertHandler;

    /** 指标数据生产者（由 ServerGuardService 注入） */
    private volatile Consumer<MetricsData> metricsHandler;

    /** 最近一次包速率快照的时间戳 */
    private volatile long lastPacketSnapshotTime = System.currentTimeMillis();

    /** 当前秒内的包计数 */
    private final AtomicLong packetCountCurrentSecond = new AtomicLong(0);

    /** 上次秒的包速率 */
    private volatile double packetsPerSecond = 0.0;

    // ─── 玩家快照管理 ──────────────────────────────────

    /** 玩家加入时创建快照 */
    public void registerPlayer(Player player) {
        PlayerSnapshot snapshot = new PlayerSnapshot(player);
        players.put(player.getUniqueId(), snapshot);
        logger.debug("Player registered: {} ({} online)", player.getName(), players.size());
    }

    /** 玩家退出时移除快照 */
    public void removePlayer(UUID uuid) {
        PlayerSnapshot removed = players.remove(uuid);
        if (removed != null) {
            logger.debug("Player removed: {} ({} online)", removed.name, players.size());
        }
    }

    /** 获取单个玩家快照 */
    public PlayerSnapshot getPlayer(UUID uuid) {
        return players.get(uuid);
    }

    /** 获取玩家快照（按名称模糊匹配） */
    public PlayerSnapshot getPlayerByName(String name) {
        return players.values().stream()
            .filter(p -> p.name.equalsIgnoreCase(name))
            .findFirst()
            .orElse(null);
    }

    /** 获取所有在线玩家快照 */
    public Collection<PlayerSnapshot> getAllPlayers() {
        return Collections.unmodifiableCollection(players.values());
    }

    /** 在线玩家数 */
    public int getOnlinePlayerCount() {
        return players.size();
    }

    /** 获取指定 IP 的玩家列表 */
    public List<PlayerSnapshot> getPlayersByIP(String ip) {
        return players.values().stream()
            .filter(p -> p.ip.equals(ip))
            .toList();
    }

    // ─── TPS 与服务器指标 ──────────────────────────────

    /** 获取当前服务器 TPS（1分钟平均） */
    public double getCurrentTps() {
        try {
            // Paper API: Bukkit.getServer().getTPS() 返回 double[3]（1m, 5m, 15m）
            double[] tpsValues = Bukkit.getServer().getTPS();
            return tpsValues.length > 0 ? tpsValues[0] : 20.0;
        } catch (Exception e) {
            return 20.0; // 非 Paper 服务端回退
        }
    }

    /** 获取 TPS 数组 [1m, 5m, 15m] */
    public double[] getTpsArray() {
        try {
            return Bukkit.getServer().getTPS();
        } catch (Exception e) {
            return new double[]{20.0, 20.0, 20.0};
        }
    }

    /** 获取当前包速率（包/秒） */
    public double getPacketsPerSecond() {
        return packetsPerSecond;
    }

    /** 记录一个包事件（由 PacketEventListener 调用） */
    public void recordPacket() {
        packetCountCurrentSecond.incrementAndGet();
    }

    /** 更新包速率快照（每秒调用一次） */
    public void updatePacketRate() {
        long now = System.currentTimeMillis();
        long elapsed = now - lastPacketSnapshotTime;
        if (elapsed > 0) {
            packetsPerSecond = packetCountCurrentSecond.get() * 1000.0 / elapsed;
        }
        packetCountCurrentSecond.set(0);
        lastPacketSnapshotTime = now;
    }

    /** 获取事件计数器值 */
    public long getEventCount(String eventName) {
        AtomicLong counter = eventCounters.get(eventName);
        return counter != null ? counter.get() : 0;
    }

    /** 递增事件计数器 */
    public long incrementEvent(String eventName) {
        return eventCounters.computeIfAbsent(eventName, k -> new AtomicLong(0)).incrementAndGet();
    }

    // ─── 告警与指标推送 ────────────────────────────────

    /** 设置告警处理器（由 ServerGuardService 注入） */
    public void setAlertHandler(Consumer<AlertEvent> handler) {
        this.alertHandler = handler;
    }

    /** 设置指标处理器（由 ServerGuardService 注入） */
    public void setMetricsHandler(Consumer<MetricsData> handler) {
        this.metricsHandler = handler;
    }

    /** 推送一条告警事件到处理管道 */
    public void pushAlert(AlertEvent alert) {
        Consumer<AlertEvent> handler = alertHandler;
        if (handler != null) {
            handler.accept(alert);
        } else {
            logger.warn("No alert handler set — alert dropped: {}", alert.getMessage());
        }
    }

    /** 推送指标数据到处理管道 */
    public void pushMetrics(MetricsData data) {
        Consumer<MetricsData> handler = metricsHandler;
        if (handler != null) {
            handler.accept(data);
        }
    }

    // ─── 便捷告警构造 ──────────────────────────────────

    /** 快速构造并推送一条告警 */
    public void alert(AlertType type, String message, double confidence, String source) {
        AlertEvent event = new AlertEvent();
        event.setType(type);
        event.setMessage(message);
        event.setConfidence(confidence);
        event.setSource(source);
        event.setTimestamp(Instant.now().toEpochMilli());
        pushAlert(event);
    }

    // ─── 构建 MetricsData ───────────────────────────────

    /** 从当前实时状态构建 MetricsData 快照 */
    public MetricsData buildMetricsSnapshot() {
        MetricsData data = new MetricsData();
        data.setTps(getCurrentTps());

        // CPU 和 Memory 通过 JMX 获取（插件模式下仍可使用系统级指标）
        try {
            java.lang.management.OperatingSystemMXBean osBean =
                java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            if (osBean instanceof com.sun.management.OperatingSystemMXBean sunOsBean) {
                data.setCpuUsage(sunOsBean.getCpuLoad() * 100.0);
                long totalMem = Runtime.getRuntime().totalMemory();
                long maxMem = Runtime.getRuntime().maxMemory();
                data.setMemoryUsage((double) totalMem / maxMem * 100.0);
            }
        } catch (Exception ignored) {
            data.setCpuUsage(0);
            data.setMemoryUsage(0);
        }

        data.setOnlinePlayers(players.size());
        data.setConnections(players.size());
        return data;
    }

    // ─── 玩家快照数据结构 ──────────────────────────────

    /**
     * 在线玩家的实时状态快照
     * 包含位置、速度、攻击记录等安全检测所需的关键字段
     */
    public static class PlayerSnapshot {
        public final UUID uuid;
        public final String name;
        public volatile String ip;
        public volatile double x, y, z;
        public volatile String world;
        public volatile float yaw, pitch;
        public volatile double velocityX, velocityY, velocityZ;
        public volatile double lastMoveX, lastMoveY, lastMoveZ;
        public volatile long lastMoveTime;
        public volatile int ping;
        public volatile boolean isOp;
        public volatile boolean isFlying;
        public volatile boolean isSprinting;
        public volatile boolean isSneaking;
        public volatile boolean isInWater;

        /** 最近攻击目标（目标实体名 → 攻击时间戳） */
        public final ConcurrentHashMap<String, Long> recentTargets = new ConcurrentHashMap<>();

        /** 最近攻击角度（用于 KillAura 检测） */
        public final ConcurrentLinkedDeque<Double> recentAttackAngles = new ConcurrentLinkedDeque<>();

        /** 最近攻击距离（用于 Reach 检测） */
        public final ConcurrentLinkedDeque<Double> recentAttackDistances = new ConcurrentLinkedDeque<>();

        /** 最近发送的消息（用于聊天刷屏检测） */
        public final ConcurrentLinkedDeque<String> recentMessages = new ConcurrentLinkedDeque<>();

        /** 最近执行的命令（用于命令滥用检测） */
        public final ConcurrentLinkedDeque<String> recentCommands = new ConcurrentLinkedDeque<>();

        /** 最近破坏的方块位置（用于 Nuker 检测） */
        public final ConcurrentLinkedDeque<String> recentBlockBreaks = new ConcurrentLinkedDeque<>();

        /** 最近放置的方块位置 */
        public final ConcurrentLinkedDeque<String> recentBlockPlaces = new ConcurrentLinkedDeque<>();

        /** 总移动距离（用于 Speed 检测） */
        public volatile double totalDistanceMoved = 0.0;

        /** 登录时间 */
        public final long loginTime;

        public PlayerSnapshot(org.bukkit.entity.Player player) {
            this.uuid = player.getUniqueId();
            this.name = player.getName();
            this.ip = player.getAddress() != null && player.getAddress().getAddress() != null
                ? player.getAddress().getAddress().getHostAddress()
                : "unknown";
            this.world = player.getWorld().getName();
            var loc = player.getLocation();
            this.x = loc.getX();
            this.y = loc.getY();
            this.z = loc.getZ();
            this.yaw = loc.getYaw();
            this.pitch = loc.getPitch();
            this.ping = player.getPing();
            this.isOp = player.isOp();
            this.isFlying = player.isFlying();
            this.isSprinting = player.isSprinting();
            this.isSneaking = player.isSneaking();
            this.isInWater = player.isInWater();
            this.loginTime = System.currentTimeMillis();
            this.lastMoveTime = System.currentTimeMillis();
        }

        /** 更新玩家位置快照（由 PlayerMoveEvent 触发） */
        public void updatePosition(double x, double y, double z, float yaw, float pitch) {
            this.lastMoveX = this.x;
            this.lastMoveY = this.y;
            this.lastMoveZ = this.z;
            this.x = x;
            this.y = y;
            this.z = z;
            this.yaw = yaw;
            this.pitch = pitch;
            this.lastMoveTime = System.currentTimeMillis();
        }

        /** 记录攻击目标（用于 KillAura 多目标检测） */
        public void recordTarget(String targetName) {
            recentTargets.put(targetName, System.currentTimeMillis());
            // 清理 10 秒以外的旧记录
            long cutoff = System.currentTimeMillis() - 10_000;
            recentTargets.entrySet().removeIf(e -> e.getValue() < cutoff);
        }

        /** 获取最近 3 秒内的唯一目标数 */
        public int getRecentTargetCount() {
            long cutoff = System.currentTimeMillis() - 3_000;
            return (int) recentTargets.values().stream().filter(t -> t >= cutoff).count();
        }

        /** 记录攻击角度 */
        public void recordAttackAngle(double angle) {
            recentAttackAngles.add(angle);
            while (recentAttackAngles.size() > 10) {
                recentAttackAngles.removeFirst();
            }
        }

        /** 记录攻击距离 */
        public void recordAttackDistance(double distance) {
            recentAttackDistances.add(distance);
            while (recentAttackDistances.size() > 10) {
                recentAttackDistances.removeFirst();
            }
        }

        /** 检查攻击角度是否过于一致（可能使用 Aimbot） */
        public boolean hasSuspiciousAngleConsistency() {
            if (recentAttackAngles.size() < 5) return false;
            double maxDeviation = 0;
            var it = recentAttackAngles.iterator();
            double prev = it.next();
            while (it.hasNext()) {
                double curr = it.next();
                double diff = Math.abs(curr - prev);
                if (diff > 180) diff = 360 - diff;
                maxDeviation = Math.max(maxDeviation, diff);
                prev = curr;
            }
            return maxDeviation < 5.0; // 小于 5 度偏差视为可疑
        }

        /** 在线时长（毫秒） */
        public long getOnlineTime() {
            return System.currentTimeMillis() - loginTime;
        }

        @Override
        public String toString() {
            return String.format("PlayerSnapshot{%s pos=(%.1f,%.1f,%.1f) world=%s ping=%d}",
                name, x, y, z, world, ping);
        }
    }
}
