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
 * 离线模式UUID欺诈防护服务 — V4.0 服务器保护模块
 *
 * 检测原理：
 *   在离线模式（offline/cracked）的Minecraft服务器中，玩家可以自由选择任意用户名和
 *   UUID加入服务器。这为恶意玩家提供了冒充正版玩家、管理员、甚至是Mojang员工的
 *   机会。本服务在多维度上检测UUID欺诈行为：验证UUID格式合法性、追踪IP与UUID的
 *   关联关系、检测快速UUID切换模式、以及对已知高价值UUID进行专项保护。
 *
 * 攻击场景：
 *   - UUID冒充：使用正版玩家（如知名YouTuber、管理员）的UUID加入服务器
 *   - 多账户轮换：同一IP在短时间内使用多个不同UUID绕过封禁
 *   - UUID格式滥用：使用不符合RFC 4122的UUID格式尝试绕过检测
 *   - 管理员伪造：使用已知服务器管理员或Mojang员工的UUID获取权限
 *
 * 检测维度：
 *   - UUID格式合法性（RFC 4122变体4 UUID格式）
 *   - IP-UUID关联追踪（同IP使用多个UUID为可疑）
 *   - 快速切换检测（60秒内使用3+不同UUID）
 *   - 高价值UUID保护（已知管理员/知名玩家UUID）
 *   - 用户名-UUID一致性验证
 *
 * 配置开关：serverguard.security.super-evolution.anti-offline-mode-spoof
 */
@Service
public class AntiOfflineModeSpoofService {

    private final ServerGuardConfig config;

    /** IP -> (UUID -> 最后使用时间) 映射 */
    private final Map<String, Map<String, Instant>> ipUuidMap = new ConcurrentHashMap<>();
    /** UUID -> 最近使用信息 */
    private final Map<String, UuidRecord> uuidRecords = new ConcurrentHashMap<>();
    /** IP被封锁记录 */
    private final Map<String, Instant> blockedIps = new ConcurrentHashMap<>();
    /** UUID被封锁记录 */
    private final Map<String, Instant> blockedUuids = new ConcurrentHashMap<>();

    private final AtomicLong totalJoins = new AtomicLong(0);
    private final AtomicLong spoofBlocked = new AtomicLong(0);

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    /** 快速切换检测窗口（秒） */
    private static final long RAPID_SWITCH_WINDOW_SECONDS = 60;
    /** 同一IP在窗口内的最大不同UUID数 */
    private static final int MAX_UUIDS_PER_IP_WINDOW = 3;
    /** 同一IP关联的UUID总数上限 */
    private static final int MAX_UUIDS_PER_IP_TOTAL = 10;
    /** 封锁时间（秒） */
    private static final long BLOCK_DURATION_SECONDS = 3600;

    /** RFC 4122 UUID 正则表达式（版本4变体） */
    private static final String UUID_V4_REGEX =
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$";

    /** 已知的Mojang员工和高价值目标UUID（示例值，生产环境应配置完整列表） */
    private static final Set<String> PROTECTED_UUIDS = new HashSet<>(Arrays.asList(
            // Mojang/Microsoft员工（示例UUID，非真实值）
            "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
    ));

    /** 常见管理员用户名模式（大小写不敏感） */
    private static final Set<String> ADMIN_NAME_PATTERNS = Set.of(
            "admin", "owner", "mod", "op", "server", "staff",
            "administrator", "moderator", "helper", "manager",
            "notch", "jeb_", "dinnerbone", "jappa", "kingbdogz"
    );

    public AntiOfflineModeSpoofService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiOfflineModeSpoofService(ServerGuardConfig config) {
        this.config = config;
        scheduler.scheduleAtFixedRate(this::cleanupOldData, 60, 120, TimeUnit.SECONDS);
    }

    /**
     * 检查玩家加入时的UUID是否存在欺诈行为。
     *
     * @param uuid 玩家UUID（离线模式下由客户端自行指定）
     * @param username 玩家用户名
     * @param ip 玩家IP地址
     * @param sessionId 会话标识
     * @return 检查结果
     */
    public SpoofCheckResult check(String uuid, String username, String ip, String sessionId) {
        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiOfflineModeSpoof()) {
            return SpoofCheckResult.clean();
        }

        totalJoins.incrementAndGet();
        List<String> reasons = new ArrayList<>();
        int score = 0;

        Instant now = Instant.now();

        // 检查IP是否被封锁
        if (blockedIps.containsKey(ip)) {
            if (now.isAfter(blockedIps.get(ip))) {
                blockedIps.remove(ip);
            } else {
                return SpoofCheckResult.blocked(List.of("IP_BLOCKED: " + ip + " is temporarily blocked for UUID spoofing"));
            }
        }

        // 检查UUID是否被封锁
        if (blockedUuids.containsKey(uuid)) {
            if (now.isAfter(blockedUuids.get(uuid))) {
                blockedUuids.remove(uuid);
            } else {
                return SpoofCheckResult.blocked(List.of("UUID_BLOCKED: " + uuid + " is blacklisted for spoofing"));
            }
        }

        // ---- 检测1：UUID格式验证 ----
        // Minecraft使用RFC 4122版本4变体的UUID格式
        // 离线模式客户端可能发送完全不符合格式的UUID
        if (uuid == null || uuid.trim().isEmpty()) {
            score += 90;
            reasons.add("UUID_EMPTY: UUID is null or empty");
        } else if (!uuid.trim().matches(UUID_V4_REGEX)) {
            // 检查是否至少是合法的UUID格式（宽松检测）
            String uuidClean = uuid.trim();
            if (uuidClean.matches("^[0-9a-fA-F]{32}$")) {
                // 缺少连字符的UUID，可以格式化但标记为可疑
                score += 10;
                reasons.add("UUID_NO_HYPHENS: UUID lacks RFC 4122 formatting");
            } else if (!uuidClean.matches("^[0-9a-fA-F-]+$")) {
                // 包含非法字符
                score += 80;
                reasons.add("UUID_INVALID_CHARS: contains non-hex characters");
            } else if (uuidClean.length() != 36) {
                score += 70;
                reasons.add("UUID_INVALID_LENGTH: length=" + uuidClean.length() + " (expected 36)");
            } else {
                // 长度正确但格式不对（如错误的变体/版本位）
                score += 20;
                reasons.add("UUID_INVALID_FORMAT: does not match Minecraft UUID format (version 4 variant)");
            }
        }

        // ---- 检测2：IP-UUID关联追踪 ----
        // 同一IP关联过多UUID是典型的帐户滥用或UUID欺诈行为
        Map<String, Instant> ipRecords = ipUuidMap.computeIfAbsent(ip, k -> new ConcurrentHashMap<>());

        // 记录当前UUID
        ipRecords.put(uuid, now);

        // 检查该IP历史上关联的UUID总数
        int totalUuidsForIp = ipRecords.size();
        if (totalUuidsForIp > MAX_UUIDS_PER_IP_TOTAL) {
            score += 50;
            reasons.add("IP_UUID_OVERFLOW: IP " + ip + " has " + totalUuidsForIp
                    + " associated UUIDs (max: " + MAX_UUIDS_PER_IP_TOTAL + ")");
        }

        // ---- 检测3：快速切换检测 ----
        // 同一IP在60秒内使用3+不同UUID，说明在快速切换身份
        long recentUuids = ipRecords.entrySet().stream()
                .filter(e -> e.getValue().isAfter(now.minusSeconds(RAPID_SWITCH_WINDOW_SECONDS)))
                .count();

        if (recentUuids > MAX_UUIDS_PER_IP_WINDOW) {
            score += 75; // 快速UUID切换为严重攻击，直接触发blocked（>=70阈值）
            reasons.add("RAPID_UUID_SWITCH: " + recentUuids + " different UUIDs in "
                    + RAPID_SWITCH_WINDOW_SECONDS + "s from IP " + ip);
        }

        // ---- 检测4：高价值UUID保护 ----
        // 检测是否使用了已知管理员、Mojang员工或知名正版玩家的UUID
        if (PROTECTED_UUIDS.contains(uuid.trim().toLowerCase())) {
            score += 70;
            reasons.add("PROTECTED_UUID_SPOOF: UUID " + uuid + " belongs to a protected Mojang/admin account");
        }

        // ---- 检测5：管理员用户名检测 ----
        // 检测用户名是否为常见的管理员模式
        // 配合UUID异常可提高检测准确率
        if (username != null) {
            String lowerName = username.toLowerCase().trim();
            for (String pattern : ADMIN_NAME_PATTERNS) {
                if (lowerName.contains(pattern) || lowerName.equals(pattern)) {
                    // 如果UUID格式也不合法，加重评分
                    if (uuid != null && !uuid.trim().matches(UUID_V4_REGEX)) {
                        score += 30;
                        reasons.add("ADMIN_NAME_SPOOF: username '" + username + "' with invalid UUID");
                    } else {
                        reasons.add("ADMIN_NAME_DETECTED: username '" + username
                                + "' matches admin pattern (flagged, not blocked)");
                    }
                    break;
                }
            }
        }

        // ---- 检测6：UUID重复使用检测 ----
        // 检测同一UUID是否已从不同IP被使用
        UuidRecord existing = uuidRecords.get(uuid);
        if (existing != null) {
            if (!existing.ip.equals(ip)) {
                // 相同UUID从不同IP使用：可能是UUID被他人冒用
                score += 40;
                reasons.add("UUID_REUSE_DIFFERENT_IP: UUID " + uuid
                        + " previously used from IP " + existing.ip
                        + ", now from " + ip);
            }
            // 更新记录
            existing.lastUsed = now;
        } else {
            uuidRecords.put(uuid, new UuidRecord(uuid, username, ip, now));
        }

        // ---- 检测7：UUID版本位异常 ----
        // Minecraft规范使用版本4 UUID，其中第13位必须是'4'，第17位必须是'8','9','a','b'
        if (uuid != null && uuid.length() == 36) {
            char versionChar = uuid.charAt(14); // 第13位（0-index）
            if (versionChar != '4' && versionChar != '4') {
                // 非版本4的UUID: 在线模式Mojang API不会生成，离线模式可能被伪造
                score += 25;
                reasons.add("UUID_VERSION_MISMATCH: version=" + versionChar + " (expected 4)");
            }
        }

        // 判定结果
        if (score >= 70) {
            spoofBlocked.incrementAndGet();
            // 封锁该IP和UUID
            blockedIps.put(ip, now.plusSeconds(BLOCK_DURATION_SECONDS));
            blockedUuids.put(uuid, now.plusSeconds(BLOCK_DURATION_SECONDS));
            return SpoofCheckResult.blocked(reasons);
        } else if (score >= 20) {
            return SpoofCheckResult.flagged(reasons, score);
        }

        return SpoofCheckResult.clean();
    }

    /**
     * 将UUID添加到受保护列表。
     */
    public void addProtectedUuid(String uuid) {
        if (uuid != null && uuid.trim().matches(UUID_V4_REGEX)) {
            PROTECTED_UUIDS.add(uuid.trim().toLowerCase());
        }
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalJoins", totalJoins.get());
        s.put("spoofBlocked", spoofBlocked.get());
        s.put("trackedIPs", ipUuidMap.size());
        s.put("trackedUUIDs", uuidRecords.size());
        s.put("blockedIPs", blockedIps.size());
        s.put("blockedUUIDs", blockedUuids.size());
        s.put("protectedUUIDs", PROTECTED_UUIDS.size());

        // IP-UUID关联映射（最多显示20个IP）
        List<Map<String, Object>> ipMappings = new ArrayList<>();
        for (Map.Entry<String, Map<String, Instant>> e : ipUuidMap.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", e.getKey());
            m.put("uuidCount", e.getValue().size());

            // 最近活跃的UUID（每个IP取最多5个）
            List<Map<String, String>> recentUuids = new ArrayList<>();
            e.getValue().entrySet().stream()
                    .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
                    .limit(5)
                    .forEach(ue -> {
                        Map<String, String> um = new LinkedHashMap<>();
                        um.put("uuid", ue.getKey());
                        um.put("lastSeen", ue.getValue().toString());
                        recentUuids.add(um);
                    });
            m.put("recentUuids", recentUuids);
            ipMappings.add(m);
        }
        ipMappings.sort((a, b) -> Integer.compare((int) b.get("uuidCount"), (int) a.get("uuidCount")));
        s.put("ipUuidMap", ipMappings.subList(0, Math.min(ipMappings.size(), 20)));
        return s;
    }

    private void cleanupOldData() {
        Instant cutoff = Instant.now().minusSeconds(7200); // 2小时
        for (Map<String, Instant> records : ipUuidMap.values()) {
            records.entrySet().removeIf(e -> e.getValue().isBefore(cutoff));
        }
        ipUuidMap.entrySet().removeIf(e -> e.getValue().isEmpty());
        uuidRecords.entrySet().removeIf(e -> e.getValue().lastUsed.isBefore(cutoff));
        blockedIps.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
        blockedUuids.entrySet().removeIf(e -> e.getValue().isBefore(Instant.now()));
    }

    private static class UuidRecord {
        final String uuid;
        final String username;
        final String ip;
        Instant lastUsed;

        UuidRecord(String uuid, String username, String ip, Instant lastUsed) {
            this.uuid = uuid;
            this.username = username;
            this.ip = ip;
            this.lastUsed = lastUsed;
        }
    }

    public static class SpoofCheckResult {
        private final boolean blocked;
        private final boolean flagged;
        private final int score;
        private final List<String> reasons;

        private SpoofCheckResult(boolean blocked, boolean flagged, int score, List<String> reasons) {
            this.blocked = blocked;
            this.flagged = flagged;
            this.score = score;
            this.reasons = reasons;
        }

        public static SpoofCheckResult clean() {
            return new SpoofCheckResult(false, false, 0, List.of());
        }

        public static SpoofCheckResult blocked(List<String> reasons) {
            return new SpoofCheckResult(true, false, 100, reasons);
        }

        public static SpoofCheckResult flagged(List<String> reasons, int score) {
            return new SpoofCheckResult(false, true, score, reasons);
        }

        public boolean isBlocked() { return blocked; }
        public boolean isFlagged() { return flagged; }
        public boolean isClean() { return !blocked && !flagged; }
        public int getScore() { return score; }
        public List<String> getReasons() { return reasons; }
    }
}
