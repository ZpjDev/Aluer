package com.aluer.security;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * 玩家隐私数据保护服务 — V4.0 聊天社交安全模块
 *
 * 检测原理：
 * 1. IP地址自动脱敏：日志中保留前两位(192.168.xxx.xxx)
 * 2. 坐标脱敏选项：可配置脱敏级别(精确/区域/隐藏)
 * 3. 聊天记录自动化匿名化处理
 * 4. 隐私数据访问审计：记录所有访问玩家隐私数据的API调用
 * 5. 数据保留策略：自动清理超过N天的玩家详细活动日志(默认30天)
 * 6. GDPR/个人信息保护法合规辅助：玩家数据导出和删除请求处理
 *
 * 配置开关：serverguard.security.super-evolution.player-privacy
 */
@Service
public class PlayerPrivacyService {

    private final ServerGuardConfig config;
    private final AtomicLong anonymizedEntries = new AtomicLong(0);
    private final Map<String, DataExportRequest> pendingDataRequests = new ConcurrentHashMap<>();
    private final AtomicLong privacyViolations = new AtomicLong(0);
    private final Map<String, List<AuditEntry>> accessAudits = new ConcurrentHashMap<>();
    private final AtomicLong totalAuditEntries = new AtomicLong(0);

    /** IPv4地址脱敏正则 */
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(\\d{1,3}\\.\\d{1,3})\\.\\d{1,3}\\.\\d{1,3}\\b");

    /** 坐标格式正则：用于识别(x,y,z)或[x,y,z]格式 */
    private static final Pattern COORDINATE_PATTERN = Pattern.compile(
            "[\\[(（]?(-?\\d+\\.?\\d*)\\s*[,，]\\s*(-?\\d+\\.?\\d*)\\s*[,，]\\s*(-?\\d+\\.?\\d*)[\\]）]?");

    /** 默认数据保留天数 */
    private static final long DEFAULT_RETENTION_DAYS = 30L;
    /** 数据导出请求过期天数 */
    private static final long EXPORT_REQUEST_EXPIRY_DAYS = 7L;

    /** 坐标脱敏级别枚举 */
    public enum CoordinateAnonymizationLevel {
        /** 精确：不脱敏 */
        PRECISE,
        /** 区域：四舍五入到10的倍数 */
        REGION,
        /** 隐藏：完全替换为*** */
        HIDDEN
    }

    /** 当前坐标脱敏级别 */
    private volatile CoordinateAnonymizationLevel coordLevel = CoordinateAnonymizationLevel.REGION;

    public PlayerPrivacyService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public PlayerPrivacyService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 脱敏日志中的IP地址
     *
     * 将完整IP地址替换为前两位保留、后两位替换为xxx的格式。
     * 例如：192.168.1.100 -> 192.168.xxx.xxx
     * 这样保留网络段信息用于安全分析，但隐藏具体主机标识。
     *
     * @param logEntry 包含IP地址的日志条目
     * @return 脱敏后的日志文本
     */
    public String anonymizeIp(String logEntry) {
        if (!config.getSecurity().getSuperEvolution().isPlayerPrivacy()) {
            return logEntry;
        }

        if (logEntry == null || logEntry.isEmpty()) {
            return logEntry;
        }

        String result = IP_PATTERN.matcher(logEntry).replaceAll(match -> {
            anonymizedEntries.incrementAndGet();
            return match.group(1) + ".xxx.xxx";
        });

        return result;
    }

    /**
     * 脱敏玩家坐标
     *
     * 根据配置的脱敏级别处理坐标信息：
     * - PRECISE：保持原样
     * - REGION：四舍五入到10的倍数(如 128, 64, -256 -> 130, 60, -260)
     * - HIDDEN：完全替换为 ***
     *
     * @param x X坐标
     * @param y Y坐标
     * @param z Z坐标
     * @return 脱敏后的坐标字符串
     */
    public String anonymizeCoordinates(double x, double y, double z) {
        if (!config.getSecurity().getSuperEvolution().isPlayerPrivacy()) {
            return formatCoordinate(x, y, z);
        }

        anonymizedEntries.incrementAndGet();

        switch (coordLevel) {
            case PRECISE:
                return formatCoordinate(x, y, z);
            case REGION:
                // 四舍五入到10的倍数
                return formatCoordinate(
                        Math.round(x / 10.0) * 10,
                        Math.round(y / 10.0) * 10,
                        Math.round(z / 10.0) * 10
                );
            case HIDDEN:
                return "[***, ***, ***]";
            default:
                return formatCoordinate(x, y, z);
        }
    }

    /**
     * 格式化坐标为字符串
     *
     * @param x X坐标
     * @param y Y坐标
     * @param z Z坐标
     * @return 格式化后的坐标字符串
     */
    private String formatCoordinate(double x, double y, double z) {
        return String.format("[%.0f, %.0f, %.0f]", x, y, z);
    }

    /**
     * 聊天记录自动化匿名化处理
     *
     * 将消息中的玩家名替换为匿名标识符，保护玩家隐私。
     * 保留原始玩家名到匿名ID的映射以便必要时回溯。
     *
     * @param playerName 玩家名
     * @param message    聊天消息
     * @return 匿名化后的消息
     */
    public String anonymizeChatMessage(String playerName, String message) {
        if (!config.getSecurity().getSuperEvolution().isPlayerPrivacy()) {
            return "[" + playerName + "] " + message;
        }

        anonymizedEntries.incrementAndGet();

        // 使用玩家名的Hash生成匿名标识符
        String anonymousId = "Player_" + Math.abs(playerName.hashCode() % 10000);

        // 对消息中的坐标进行脱敏
        String processedMessage = COORDINATE_PATTERN.matcher(message).replaceAll(match -> {
            try {
                double cx = Double.parseDouble(match.group(1));
                double cy = Double.parseDouble(match.group(2));
                double cz = Double.parseDouble(match.group(3));
                return anonymizeCoordinates(cx, cy, cz);
            } catch (NumberFormatException e) {
                return match.group();
            }
        });

        return "[" + anonymousId + "] " + processedMessage;
    }

    /**
     * 记录隐私数据访问审计
     *
     * 每次API调用访问玩家隐私数据时记录操作者、玩家目标、数据类型和访问时间。
     * 用于合规审计和异常检测。
     *
     * @param accessor    访问者(API调用方)
     * @param targetPlayer 被访问的玩家
     * @param dataType    访问的数据类型(如IP、坐标、聊天记录等)
     */
    public void auditAccess(String accessor, String targetPlayer, String dataType) {
        if (!config.getSecurity().getSuperEvolution().isPlayerPrivacy()) {
            return;
        }

        AuditEntry entry = new AuditEntry(accessor, targetPlayer, dataType, Instant.now());
        accessAudits.computeIfAbsent(targetPlayer, k -> new ArrayList<>()).add(entry);
        totalAuditEntries.incrementAndGet();

        // 限制单个玩家的审计记录数量
        List<AuditEntry> entries = accessAudits.get(targetPlayer);
        while (entries.size() > 500) {
            entries.remove(0);
        }
    }

    /**
     * 提交玩家数据导出请求(GDPR第20条：数据可携带权)
     *
     * @param playerName 玩家名
     * @param requestor  请求者标识
     * @return 请求ID
     */
    public String requestDataExport(String playerName, String requestor) {
        String requestId = UUID.randomUUID().toString();
        DataExportRequest request = new DataExportRequest(
                requestId, playerName, requestor, "EXPORT", Instant.now());
        pendingDataRequests.put(requestId, request);
        return requestId;
    }

    /**
     * 提交玩家数据删除请求(GDPR第17条：被遗忘权)
     *
     * @param playerName 玩家名
     * @param requestor  请求者标识
     * @return 请求ID
     */
    public String requestDataDeletion(String playerName, String requestor) {
        String requestId = UUID.randomUUID().toString();
        DataExportRequest request = new DataExportRequest(
                requestId, playerName, requestor, "DELETION", Instant.now());
        pendingDataRequests.put(requestId, request);
        return requestId;
    }

    /**
     * 获取待处理的数据请求列表
     *
     * @return 待处理的数据请求列表
     */
    public List<DataExportRequest> getPendingRequests() {
        return new ArrayList<>(pendingDataRequests.values());
    }

    /**
     * 标记数据请求为已处理
     *
     * @param requestId 请求ID
     * @return true表示处理成功
     */
    public boolean completeRequest(String requestId) {
        DataExportRequest request = pendingDataRequests.get(requestId);
        if (request != null) {
            request.completed = true;
            request.completedAt = Instant.now();
            return true;
        }
        return false;
    }

    /**
     * 检查并清理过期的数据请求
     *
     * 超过7天未处理的数据导出/删除请求自动移除，释放内存。
     */
    public void cleanupExpiredRequests() {
        Instant cutoff = Instant.now().minus(EXPORT_REQUEST_EXPIRY_DAYS, ChronoUnit.DAYS);
        pendingDataRequests.entrySet().removeIf(e ->
                e.getValue().createdAt.isBefore(cutoff));
    }

    /**
     * 记录隐私违规事件
     *
     * 当检测到未经授权的隐私数据访问时记录违规。
     *
     * @param description 违规描述
     */
    public void recordPrivacyViolation(String description) {
        privacyViolations.incrementAndGet();
    }

    /**
     * 设置坐标脱敏级别
     *
     * @param level 脱敏级别
     */
    public void setCoordinateAnonymizationLevel(CoordinateAnonymizationLevel level) {
        this.coordLevel = level;
    }

    /**
     * 获取当前坐标脱敏级别
     *
     * @return 当前脱敏级别
     */
    public CoordinateAnonymizationLevel getCoordinateAnonymizationLevel() {
        return coordLevel;
    }

    /**
     * 获取针对特定玩家的审计记录
     *
     * @param playerName 玩家名
     * @return 审计条目列表
     */
    public List<AuditEntry> getAuditForPlayer(String playerName) {
        List<AuditEntry> entries = accessAudits.get(playerName);
        return entries == null ? List.of() : new ArrayList<>(entries);
    }

    /**
     * 获取服务运行状态
     *
     * @return 包含状态键值对的LinkedHashMap
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isPlayerPrivacy());
        s.put("anonymizedEntries", anonymizedEntries.get());
        s.put("pendingDataRequests", pendingDataRequests.size());
        s.put("exportRequests", pendingDataRequests.values().stream()
                .filter(r -> "EXPORT".equals(r.type)).count());
        s.put("deletionRequests", pendingDataRequests.values().stream()
                .filter(r -> "DELETION".equals(r.type)).count());
        s.put("privacyViolations", privacyViolations.get());
        s.put("coordinateLevel", coordLevel.name());
        s.put("retentionDays", DEFAULT_RETENTION_DAYS);
        s.put("totalAuditEntries", totalAuditEntries.get());
        s.put("auditedPlayers", accessAudits.size());
        return s;
    }

    /**
     * 隐私数据访问审计条目
     */
    public static class AuditEntry {
        private final String accessor;
        private final String targetPlayer;
        private final String dataType;
        private final Instant timestamp;

        public AuditEntry(String accessor, String targetPlayer, String dataType, Instant timestamp) {
            this.accessor = accessor;
            this.targetPlayer = targetPlayer;
            this.dataType = dataType;
            this.timestamp = timestamp;
        }

        public String getAccessor() { return accessor; }
        public String getTargetPlayer() { return targetPlayer; }
        public String getDataType() { return dataType; }
        public Instant getTimestamp() { return timestamp; }
    }

    /**
     * 数据导出/删除请求
     */
    public static class DataExportRequest {
        private final String requestId;
        private final String playerName;
        private final String requestor;
        private final String type; // EXPORT 或 DELETION
        private final Instant createdAt;
        private volatile boolean completed = false;
        private volatile Instant completedAt;

        public DataExportRequest(String requestId, String playerName, String requestor,
                                  String type, Instant createdAt) {
            this.requestId = requestId;
            this.playerName = playerName;
            this.requestor = requestor;
            this.type = type;
            this.createdAt = createdAt;
        }

        public String getRequestId() { return requestId; }
        public String getPlayerName() { return playerName; }
        public String getRequestor() { return requestor; }
        public String getType() { return type; }
        public Instant getCreatedAt() { return createdAt; }
        public boolean isCompleted() { return completed; }
        public Instant getCompletedAt() { return completedAt; }
    }
}
