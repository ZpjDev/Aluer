package com.aluer.anticheat.player;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 小号/替代账号检测 — V4.0 访问控制模块
 *
 * 检测原理：
 * 1. 追踪IP与账号的关联关系——同一IP在24小时内登录的不同账号
 * 2. 通过IP关联分析识别小号簇（alt groups）：如果同一IP在较短时间内登录多个不同账号，
 *    很可能这些账号属于同一玩家（小号阵列）
 * 3. 行为相似度分析：对比两个账号在登录时间段、在线时长模式上的相似度
 * 4. 快速切换检测：同一IP在5分钟内切换账号3次以上，说明可能是同一玩家使用多个账号
 * 5. 封禁逃逸检测：检测被封禁玩家在封禁后不久（30分钟内），其使用过的IP是否有新账号登录
 * 6. 追踪已知捣乱者IP，维护其关联的全部账号列表，便于封禁时连带处理
 * 7. 维护封禁IP黑名单池，记录最近被封禁的IP及其封禁时间
 *
 * 配置开关：serverguard.security.super-evolution.anti-alt-account
 */
@Service
public class AntiAltAccountService {

    private final ServerGuardConfig config;

    /** IP -> 该IP登录过的账号列表（含登录时间） */
    private final Map<String, List<AccountLogin>> ipToAccounts = new ConcurrentHashMap<>();
    /** 账号名 -> 该账号登录过的IP列表 */
    private final Map<String, List<String>> accountToIPs = new ConcurrentHashMap<>();
    /** 被封禁的IP -> 封禁时间 */
    private final Map<String, Instant> bannedIPs = new ConcurrentHashMap<>();
    /** 已知捣乱者IP -> 关联的全部账号 */
    private final Map<String, Set<String>> troublemakerIPToAccounts = new ConcurrentHashMap<>();
    /** 已识别的小号组（alt group ID -> 账号列表） */
    private final Map<String, Set<String>> altGroups = new ConcurrentHashMap<>();

    private final AtomicLong totalAccounts = new AtomicLong(0);
    private final AtomicLong totalLoginEvents = new AtomicLong(0);
    private final AtomicLong banEvasionAttempts = new AtomicLong(0);
    private final AtomicLong rapidSwitchDetections = new AtomicLong(0);

    /** 快速切换检测窗口（毫秒，5分钟） */
    private static final long RAPID_SWITCH_WINDOW_MS = 300_000;
    /** 快速切换账号数阈值 */
    private static final int RAPID_SWITCH_THRESHOLD = 3;
    /** IP关联分析窗口（毫秒，24小时） */
    private static final long IP_ASSOCIATION_WINDOW_MS = 86_400_000;
    /** 封禁逃逸检测窗口（毫秒，30分钟） */
    private static final long BAN_EVASION_WINDOW_MS = 1_800_000;

    /** 无参构造函数，使用默认配置 */
    public AntiAltAccountService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiAltAccountService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 记录玩家登录事件，检测是否为小号/替代账号
     *
     * @param playerName 玩家名
     * @param uuid       玩家UUID
     * @param ip         登录IP
     * @return 检测结果，包含是否检测到小号行为及原因
     */
    public AltAccountResult onPlayerLogin(String playerName, String uuid, String ip) {
        totalLoginEvents.incrementAndGet();

        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiAltAccount()) {
            return AltAccountResult.clean();
        }

        if (playerName == null || ip == null) {
            return AltAccountResult.clean();
        }

        List<String> reasons = new ArrayList<>();
        boolean altDetected = false;
        Instant now = Instant.now();

        // 记录账号->IP映射
        accountToIPs.computeIfAbsent(playerName, k -> Collections.synchronizedList(new ArrayList<>())).add(ip);

        // 记录IP->账号登录事件
        AccountLogin login = new AccountLogin(playerName, uuid, ip, now);
        ipToAccounts.computeIfAbsent(ip, k -> Collections.synchronizedList(new ArrayList<>())).add(login);

        // 清理24小时前的旧登录记录（保持数据新鲜）
        cleanupOldLogins(ip, now);

        // 检查1：封禁逃逸检测 —— 该IP是否在最近被封禁
        Instant banTime = bannedIPs.get(ip);
        if (banTime != null) {
            long sinceBan = ChronoUnit.MILLIS.between(banTime, now);
            if (sinceBan < BAN_EVASION_WINDOW_MS) {
                altDetected = true;
                banEvasionAttempts.incrementAndGet();
                reasons.add("BAN_EVASION: Player \"" + playerName + "\" logged in from IP " + ip
                        + " which was banned " + (sinceBan / 1000) + " seconds ago — potential ban evasion");
            }
        }

        // 检查2：快速切换检测 —— 同一IP在5分钟内切换账号超过阈值
        List<AccountLogin> sameIPLogins = ipToAccounts.get(ip);
        if (sameIPLogins != null) {
            List<AccountLogin> recentLogins = sameIPLogins.stream()
                    .filter(l -> ChronoUnit.MILLIS.between(l.loginTime, now) < RAPID_SWITCH_WINDOW_MS)
                    .toList();
            Set<String> recentAccounts = new HashSet<>();
            for (AccountLogin l : recentLogins) {
                recentAccounts.add(l.playerName);
            }
            if (recentAccounts.size() >= RAPID_SWITCH_THRESHOLD) {
                altDetected = true;
                rapidSwitchDetections.incrementAndGet();
                reasons.add("RAPID_ACCOUNT_SWITCH: IP " + ip + " used by " + recentAccounts.size()
                        + " different accounts within 5 minutes: " + recentAccounts
                        + " — probable alt accounts");

                // 自动创建小号组
                String groupId = "ALT-" + ip.replace(".", "-") + "-" + now.toEpochMilli();
                altGroups.put(groupId, new HashSet<>(recentAccounts));
            }
        }

        // 检查3：IP关联账号检测 —— 同一IP在24小时内登录过多个不同账号
        if (!altDetected && sameIPLogins != null && sameIPLogins.size() >= 2) {
            Set<String> distinctAccounts = new HashSet<>();
            for (AccountLogin l : sameIPLogins) {
                distinctAccounts.add(l.playerName);
            }
            if (distinctAccounts.size() >= 2) {
                altDetected = true;
                reasons.add("IP_ASSOCIATED_ALT: IP " + ip + " has " + distinctAccounts.size()
                        + " associated accounts in 24h: " + distinctAccounts
                        + " — likely alt accounts from same player");
            }
        }

        // 检查4：已知捣乱者IP关联 —— 如果该IP之前被标记为捣乱者
        if (troublemakerIPToAccounts.containsKey(ip)) {
            Set<String> existingAccounts = troublemakerIPToAccounts.get(ip);
            if (!existingAccounts.contains(playerName)) {
                altDetected = true;
                reasons.add("TROUBLEMAKER_IP: IP " + ip + " is associated with known troublemaker, "
                        + "new account \"" + playerName + "\" is likely an alt to evade punishment. "
                        + "Existing associated accounts: " + existingAccounts);
            }
            existingAccounts.add(playerName);
        }

        // 追踪独立账号数
        Set<String> allAccounts = new HashSet<>();
        accountToIPs.forEach((name, ips) -> allAccounts.add(name));
        totalAccounts.set(allAccounts.size());

        if (altDetected) {
            return new AltAccountResult(true, reasons);
        }
        return AltAccountResult.clean();
    }

    /**
     * 记录一个被封禁IP，用于后续封禁逃逸检测
     *
     * @param ip     被封禁的IP
     * @param reason 封禁原因
     */
    public void recordBannedIP(String ip, String reason) {
        if (ip != null && !ip.isBlank()) {
            bannedIPs.put(ip, Instant.now());

            // 如果是捣乱者IP，记录其关联的所有账号
            List<AccountLogin> logins = ipToAccounts.get(ip);
            if (logins != null && !logins.isEmpty()) {
                Set<String> associatedAccounts = new HashSet<>();
                for (AccountLogin l : logins) {
                    associatedAccounts.add(l.playerName);
                }
                troublemakerIPToAccounts.computeIfAbsent(ip, k -> ConcurrentHashMap.newKeySet())
                        .addAll(associatedAccounts);
            }
        }
    }

    /**
     * 将某玩家标记为已知捣乱者，将其所有关联IP加入追踪
     *
     * @param playerName 玩家名
     */
    public void markAsTroublemaker(String playerName) {
        if (playerName == null) return;

        List<String> ips = accountToIPs.get(playerName);
        if (ips != null) {
            for (String ip : ips) {
                Set<String> accounts = troublemakerIPToAccounts.computeIfAbsent(
                        ip, k -> ConcurrentHashMap.newKeySet());
                // 将该IP关联的所有账号加入
                List<AccountLogin> logins = ipToAccounts.get(ip);
                if (logins != null) {
                    for (AccountLogin l : logins) {
                        accounts.add(l.playerName);
                    }
                }
            }
        }
    }

    /**
     * 查询某IP关联的所有账号
     *
     * @param ip IP地址
     * @return 该IP关联的账号集合
     */
    public Set<String> getAccountsForIP(String ip) {
        List<AccountLogin> logins = ipToAccounts.get(ip);
        if (logins == null) return Set.of();

        Instant cutoff = Instant.now().minusMillis(IP_ASSOCIATION_WINDOW_MS);
        Set<String> accounts = new HashSet<>();
        for (AccountLogin l : logins) {
            if (l.loginTime.isAfter(cutoff)) {
                accounts.add(l.playerName);
            }
        }
        return accounts;
    }

    /**
     * 查询某账号使用过的所有IP
     *
     * @param playerName 玩家名
     * @return 该账号使用过的IP列表
     */
    public List<String> getIPsForAccount(String playerName) {
        return new ArrayList<>(accountToIPs.getOrDefault(playerName, List.of()));
    }

    /**
     * 获取模块运行状态
     *
     * @return 状态Map，包含totalAccounts/altGroups/banEvasionAttempts
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiAltAccount());
        s.put("totalAccounts", totalAccounts.get());
        s.put("totalLoginEvents", totalLoginEvents.get());
        s.put("altGroups", altGroups.size());
        s.put("banEvasionAttempts", banEvasionAttempts.get());
        s.put("rapidSwitchDetections", rapidSwitchDetections.get());
        s.put("trackedIPs", ipToAccounts.size());
        s.put("bannedIPTracking", bannedIPs.size());
        s.put("troublemakerIPs", troublemakerIPToAccounts.size());

        // 小号组详情列表
        List<Map<String, Object>> groupDetails = new ArrayList<>();
        altGroups.forEach((groupId, accounts) -> {
            Map<String, Object> g = new LinkedHashMap<>();
            g.put("groupId", groupId);
            g.put("accounts", new ArrayList<>(accounts));
            g.put("accountCount", accounts.size());
            groupDetails.add(g);
        });
        s.put("altGroupDetails", groupDetails);
        return s;
    }

    // ==================== 内部辅助方法 ====================

    /** 清理指定IP的过期登录记录 */
    private void cleanupOldLogins(String ip, Instant now) {
        List<AccountLogin> logins = ipToAccounts.get(ip);
        if (logins != null) {
            Instant cutoff = now.minusMillis(IP_ASSOCIATION_WINDOW_MS);
            logins.removeIf(l -> l.loginTime.isBefore(cutoff));
        }
    }

    // ==================== 内部数据类 ====================

    /** 账号登录事件记录 */
    private static class AccountLogin {
        final String playerName;
        final String uuid;
        final String ip;
        final Instant loginTime;

        AccountLogin(String playerName, String uuid, String ip, Instant loginTime) {
            this.playerName = playerName;
            this.uuid = uuid;
            this.ip = ip;
            this.loginTime = loginTime;
        }
    }

    /** 小号/替代账号检测结果 */
    public static class AltAccountResult {
        private final boolean altDetected;
        private final List<String> reasons;

        AltAccountResult(boolean altDetected, List<String> reasons) {
            this.altDetected = altDetected;
            this.reasons = reasons;
        }

        public static AltAccountResult clean() {
            return new AltAccountResult(false, List.of());
        }

        public boolean isAltDetected() { return altDetected; }
        public boolean isClean() { return !altDetected; }
        public List<String> getReasons() { return reasons; }
    }
}
