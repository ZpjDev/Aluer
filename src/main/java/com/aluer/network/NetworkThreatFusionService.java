package com.aluer.network;

import com.aluer.defense.IntrusionDetectionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

@Service
public class NetworkThreatFusionService {
    private static final Logger logger = LoggerFactory.getLogger(NetworkThreatFusionService.class);

    private static final int EVENT_SAMPLE_SIZE = 200;
    private static final int HIGH_RISK_THRESHOLD = 60;
    private static final int CRITICAL_RISK_THRESHOLD = 80;

    private final DDoSProtectionService ddosProtectionService;
    private final FirewallService firewallService;
    private final IntrusionDetectionService intrusionDetectionService;
    private final NetworkMonitorService networkMonitorService;
    private final TrafficAnalysisService trafficAnalysisService;
    private final PortScanDetectionService portScanDetectionService;
    private final PacketInspectionService packetInspectionService;
    private final IPReputationService ipReputationService;
    private final GeoIPService geoIPService;
    private final RateLimitService rateLimitService;

    private final Map<String, QuarantineRecord> quarantinedIps = new ConcurrentHashMap<>();
    private final Deque<FusionIncident> incidentLog = new ConcurrentLinkedDeque<>();

    public NetworkThreatFusionService(DDoSProtectionService ddosProtectionService,
                                      FirewallService firewallService,
                                      IntrusionDetectionService intrusionDetectionService,
                                      NetworkMonitorService networkMonitorService,
                                      TrafficAnalysisService trafficAnalysisService,
                                      PortScanDetectionService portScanDetectionService,
                                      PacketInspectionService packetInspectionService,
                                      IPReputationService ipReputationService,
                                      GeoIPService geoIPService,
                                      RateLimitService rateLimitService) {
        this.ddosProtectionService = ddosProtectionService;
        this.firewallService = firewallService;
        this.intrusionDetectionService = intrusionDetectionService;
        this.networkMonitorService = networkMonitorService;
        this.trafficAnalysisService = trafficAnalysisService;
        this.portScanDetectionService = portScanDetectionService;
        this.packetInspectionService = packetInspectionService;
        this.ipReputationService = ipReputationService;
        this.geoIPService = geoIPService;
        this.rateLimitService = rateLimitService;
    }

    public Map<String, Object> getPosture() {
        List<ThreatAssessment> assessments = collectThreatAssessments();
        long highRiskCount = assessments.stream()
            .filter(assessment -> assessment.riskScore >= HIGH_RISK_THRESHOLD)
            .count();
        long criticalRiskCount = assessments.stream()
            .filter(assessment -> assessment.riskScore >= CRITICAL_RISK_THRESHOLD)
            .count();

        Map<String, Object> ddosStats = ddosProtectionService.getStats();
        Map<String, Object> intrusionStats = intrusionDetectionService.getStats();
        Map<String, Object> firewallStats = firewallService.getStats();
        Map<String, Object> portScanStats = portScanDetectionService.getStats();
        Map<String, Object> packetStats = packetInspectionService.getStats();
        Map<String, Object> networkStats = networkMonitorService.getGlobalStats();

        int threatPressure = 0;
        threatPressure += toInt(ddosStats.get("blockedIPs")) * 6;
        threatPressure += toInt(intrusionStats.get("activeAlerts")) * 10;
        threatPressure += toInt(portScanStats.get("blockedScanners")) * 8;
        threatPressure += Math.min(20, toInt(packetStats.get("maliciousBlocked")));
        threatPressure += toInt(firewallStats.get("blacklistSize")) * 4;
        threatPressure += quarantinedIps.size() * 8;
        threatPressure += (int) highRiskCount * 5;
        threatPressure += (int) criticalRiskCount * 8;

        int maxObservedRisk = assessments.stream()
            .mapToInt(assessment -> assessment.riskScore)
            .max()
            .orElse(0);

        threatPressure += maxObservedRisk / 3;

        int postureScore = Math.max(0, 100 - Math.min(100, threatPressure));
        String threatLevel = determineThreatLevel(postureScore, maxObservedRisk);

        Map<String, Object> signals = new LinkedHashMap<>();
        signals.put("ddosBlockedIPs", ddosStats.getOrDefault("blockedIPs", 0));
        signals.put("firewallBlacklist", firewallStats.getOrDefault("blacklistSize", 0));
        signals.put("intrusionAlerts", intrusionStats.getOrDefault("activeAlerts", 0));
        signals.put("portScanBlocks", portScanStats.getOrDefault("blockedScanners", 0));
        signals.put("packetBlocks", packetStats.getOrDefault("maliciousBlocked", 0));
        signals.put("activeNetworkSessions", networkStats.getOrDefault("activeSessions", 0));

        Map<String, Object> posture = new LinkedHashMap<>();
        posture.put("postureScore", postureScore);
        posture.put("threatLevel", threatLevel);
        posture.put("highRiskIPs", highRiskCount);
        posture.put("criticalRiskIPs", criticalRiskCount);
        posture.put("quarantinedIPs", quarantinedIps.size());
        posture.put("signals", signals);
        posture.put("topRiskIPs", toAssessmentMaps(assessments, 5));
        posture.put("recommendations", buildRecommendations(postureScore, assessments));
        return posture;
    }

    public Map<String, Object> inspectIP(String ip) {
        ThreatAssessment assessment = assessIp(ip);
        return assessment.toMap();
    }

    public List<Map<String, Object>> getTopRiskIPs(int limit) {
        return toAssessmentMaps(collectThreatAssessments(), limit);
    }

    public List<Map<String, Object>> getRecentIncidents(int limit) {
        List<ThreatAssessment> assessments = collectThreatAssessments();
        Map<String, Integer> currentRisk = new ConcurrentHashMap<>();
        for (ThreatAssessment assessment : assessments) {
            currentRisk.put(assessment.ip, assessment.riskScore);
        }

        List<FusionIncident> incidents = new ArrayList<>(incidentLog);

        for (DDoSProtectionService.AttackEvent event : ddosProtectionService.getAttackLog(EVENT_SAMPLE_SIZE)) {
            incidents.add(new FusionIncident("ddos", event.ip, event.type, event.details, event.timestamp,
                currentRisk.getOrDefault(event.ip, 0)));
        }
        for (PortScanDetectionService.ScanEvent event : portScanDetectionService.getScanLog(EVENT_SAMPLE_SIZE)) {
            incidents.add(new FusionIncident("port-scan", event.ip, event.reason, event.details, event.timestamp,
                currentRisk.getOrDefault(event.ip, 0)));
        }
        for (PacketInspectionService.PacketAlert alert : packetInspectionService.getAlerts(EVENT_SAMPLE_SIZE)) {
            incidents.add(new FusionIncident("packet-inspection", alert.sourceIP, alert.ruleName, alert.details, alert.timestamp,
                currentRisk.getOrDefault(alert.sourceIP, 0)));
        }
        for (IntrusionDetectionService.IntrusionEvent event : intrusionDetectionService.getEvents(EVENT_SAMPLE_SIZE)) {
            if (isActionableSource(event.sourceIP)) {
                incidents.add(new FusionIncident("intrusion", event.sourceIP, event.type, event.details, event.timestamp,
                    currentRisk.getOrDefault(event.sourceIP, 0)));
            }
        }
        for (NetworkMonitorService.NetworkAlert alert : networkMonitorService.getAlerts(EVENT_SAMPLE_SIZE)) {
            incidents.add(new FusionIncident("network-monitor", alert.getIp(), alert.getType(), alert.getDetails(), alert.getTimestamp(),
                currentRisk.getOrDefault(alert.getIp(), 0)));
        }

        incidents.sort(Comparator.comparingLong((FusionIncident incident) -> incident.timestamp).reversed());

        List<Map<String, Object>> result = new ArrayList<>();
        int maxItems = Math.max(1, limit);
        for (FusionIncident incident : incidents) {
            if (result.size() >= maxItems) {
                break;
            }
            result.add(incident.toMap());
        }
        return result;
    }

    public Map<String, Object> quarantineIP(String ip, String actor, String reason) {
        String targetIp = normalizeTarget(ip);
        if (targetIp == null) {
            return invalidTarget("invalid", "IP 不能为空");
        }

        String operator = defaultText(actor, "system");
        String details = defaultText(reason, "Manual quarantine triggered");

        ddosProtectionService.blockIP(targetIp, "THREAT_FUSION_QUARANTINE", details);
        firewallService.addToBlacklist(targetIp);
        ipReputationService.addToBlacklist(targetIp);
        networkMonitorService.addAlert(targetIp, "QUARANTINED", details);

        QuarantineRecord record = quarantinedIps.compute(targetIp, (key, existing) -> {
            if (existing == null) {
                return new QuarantineRecord(targetIp, operator, details);
            }
            existing.actor = operator;
            existing.reason = details;
            existing.lastUpdated = System.currentTimeMillis();
            existing.count++;
            return existing;
        });

        logger.warn("Threat fusion quarantined IP {} by {}: {}", targetIp, operator, details);
        logInternalIncident("quarantine", targetIp, "THREAT_FUSION_QUARANTINE", details, 100);

        Map<String, Object> response = new LinkedHashMap<>(inspectIP(targetIp));
        response.put("status", "quarantined");
        response.put("quarantine", record.toMap());
        return response;
    }

    public Map<String, Object> releaseIP(String ip, String actor, String reason) {
        String targetIp = normalizeTarget(ip);
        if (targetIp == null) {
            return invalidTarget("invalid", "IP 不能为空");
        }

        String operator = defaultText(actor, "system");
        String details = defaultText(reason, "Manual release triggered");

        ddosProtectionService.unblockIP(targetIp);
        firewallService.removeFromBlacklist(targetIp);
        ipReputationService.removeFromBlacklist(targetIp);
        networkMonitorService.addAlert(targetIp, "RELEASED", details);

        QuarantineRecord removed = quarantinedIps.remove(targetIp);
        logger.info("Threat fusion released IP {} by {}: {}", targetIp, operator, details);
        logInternalIncident("release", targetIp, "THREAT_FUSION_RELEASE", details, 0);

        Map<String, Object> response = new LinkedHashMap<>(inspectIP(targetIp));
        response.put("status", removed != null ? "released" : "not-quarantined");
        if (removed != null) {
            response.put("releasedQuarantine", removed.toMap());
        }
        return response;
    }

    private List<ThreatAssessment> collectThreatAssessments() {
        Set<String> candidates = new HashSet<>();

        for (DDoSProtectionService.BlockedIP blockedIP : ddosProtectionService.getAllBlockedIPs()) {
            addCandidate(candidates, blockedIP.ip);
        }
        for (FirewallService.ConnectionState connection : firewallService.getActiveConnections()) {
            addCandidate(candidates, connection.sourceIP);
        }
        for (FirewallService.FirewallLog log : firewallService.getLogs(EVENT_SAMPLE_SIZE)) {
            addCandidate(candidates, log.sourceIP);
        }
        for (NetworkMonitorService.NetworkSession session : networkMonitorService.getAllSessions()) {
            addCandidate(candidates, session.getIp());
        }
        for (NetworkMonitorService.NetworkAlert alert : networkMonitorService.getAlerts(EVENT_SAMPLE_SIZE)) {
            addCandidate(candidates, alert.getIp());
        }
        for (PortScanDetectionService.BlockedScanner scanner : portScanDetectionService.getBlockedScanners()) {
            addCandidate(candidates, scanner.ip);
        }
        for (PortScanDetectionService.ScanEvent event : portScanDetectionService.getScanLog(EVENT_SAMPLE_SIZE)) {
            addCandidate(candidates, event.ip);
        }
        for (PacketInspectionService.PacketAlert alert : packetInspectionService.getAlerts(EVENT_SAMPLE_SIZE)) {
            addCandidate(candidates, alert.sourceIP);
        }
        for (TrafficAnalysisService.TrafficSession session : trafficAnalysisService.getAllSessions()) {
            addCandidate(candidates, session.getIp());
        }
        for (IPReputationService.IPProfile profile : ipReputationService.getAllProfiles()) {
            addCandidate(candidates, profile.ip);
        }
        for (GeoIPService.GeoEvent event : geoIPService.getRecentEvents(EVENT_SAMPLE_SIZE)) {
            addCandidate(candidates, event.ip);
        }
        for (IntrusionDetectionService.IntrusionEvent event : intrusionDetectionService.getEvents(EVENT_SAMPLE_SIZE)) {
            addCandidate(candidates, event.sourceIP);
        }
        candidates.addAll(quarantinedIps.keySet());

        List<ThreatAssessment> assessments = new ArrayList<>();
        for (String candidate : candidates) {
            ThreatAssessment assessment = assessIp(candidate);
            if (assessment.riskScore > 0 || assessment.blocked || assessment.quarantined) {
                assessments.add(assessment);
            }
        }

        assessments.sort(Comparator.comparingInt((ThreatAssessment assessment) -> assessment.riskScore)
            .reversed()
            .thenComparing(assessment -> assessment.ip));
        return assessments;
    }

    private ThreatAssessment assessIp(String ip) {
        ThreatAssessment assessment = new ThreatAssessment(normalizeTarget(ip));
        if (assessment.ip == null) {
            return assessment;
        }

        DDoSProtectionService.BlockedIP ddosBlock = ddosProtectionService.getBlockInfo(assessment.ip);
        if (ddosBlock != null) {
            assessment.addRisk(35, "DDoS 引擎已封禁，原因: " + ddosBlock.reason);
            assessment.blocked = true;
        }

        QuarantineRecord quarantineRecord = quarantinedIps.get(assessment.ip);
        if (quarantineRecord != null) {
            assessment.addRisk(40, "融合防御已隔离该 IP");
            assessment.quarantined = true;
            assessment.blocked = true;
        }

        if (firewallService.isBlacklisted(assessment.ip)) {
            assessment.addRisk(25, "防火墙黑名单命中");
            assessment.blocked = true;
        }

        PortScanDetectionService.BlockedScanner blockedScanner = portScanDetectionService.getBlockInfo(assessment.ip);
        if (blockedScanner != null) {
            assessment.addRisk(30, "端口扫描检测已封禁，原因: " + blockedScanner.reason);
        }

        NetworkMonitorService.NetworkSession session = networkMonitorService.getSession(assessment.ip);
        if (session != null) {
            if (session.getConnectionCount() >= 40) {
                assessment.addRisk(Math.min(20, session.getConnectionCount() / 2),
                    "短时间连接端口过多: " + session.getConnectionCount());
            }

            long totalBytes = session.getTotalBytesIn() + session.getTotalBytesOut();
            if (totalBytes >= 50_000_000L) {
                assessment.addRisk(10, "观测到高流量会话");
            }
        }

        NetworkMonitorService.BandwidthTracker bandwidthTracker = networkMonitorService.getBandwidthTracker(assessment.ip);
        if (bandwidthTracker != null && bandwidthTracker.isHighBandwidth()) {
            assessment.addRisk(15, "带宽窗口突增");
        }

        TrafficAnalysisService.AnomalyScore anomalyScore = trafficAnalysisService.getAnomalyScore(assessment.ip);
        if (anomalyScore != null && anomalyScore.getScore() > 0.2) {
            int contribution = (int) Math.round(anomalyScore.getScore() * 30);
            assessment.addRisk(contribution, String.format(Locale.ROOT,
                "流量异常评分偏高: %.2f", anomalyScore.getScore()));
        }

        int packetAlerts = countPacketAlerts(assessment.ip);
        if (packetAlerts > 0) {
            assessment.addRisk(Math.min(20, packetAlerts * 5), "包检测已触发 " + packetAlerts + " 次告警");
        }

        int intrusionEvents = countIntrusionEvents(assessment.ip);
        if (intrusionEvents > 0) {
            assessment.addRisk(Math.min(25, intrusionEvents * 5), "入侵检测记录到 " + intrusionEvents + " 个相关事件");
        }

        int ddosEvents = countDdosEvents(assessment.ip);
        if (ddosEvents > 0) {
            assessment.addRisk(Math.min(15, ddosEvents * 3), "近期 DDoS/泛洪事件: " + ddosEvents);
        }

        int firewallBlocks = countFirewallBlocks(assessment.ip);
        if (firewallBlocks > 0) {
            assessment.addRisk(Math.min(12, firewallBlocks * 3), "防火墙近期阻断次数: " + firewallBlocks);
        }

        boolean reputationBlacklisted = ipReputationService.isBlacklisted(assessment.ip);
        if (reputationBlacklisted) {
            assessment.addRisk(20, "IP 信誉黑名单命中");
            assessment.blocked = true;
        }

        IPReputationService.IPProfile profile = ipReputationService.getProfile(assessment.ip);
        if (profile != null) {
            double reputationScore = profile.calculateScore();
            assessment.metadata.put("reputationScore", roundToOneDecimal(reputationScore));

            if (profile.blacklisted && !reputationBlacklisted) {
                assessment.addRisk(20, "IP 信誉黑名单命中");
                assessment.blocked = true;
            } else if (reputationScore < 30) {
                assessment.addRisk((int) Math.round(30 - reputationScore),
                    "IP 信誉分过低: " + roundToOneDecimal(reputationScore));
            }
        }

        GeoIPService.GeoLocation geoLocation = geoIPService.getGeoLocation(assessment.ip);
        if (geoLocation != null) {
            assessment.metadata.put("country", geoLocation.country);
            Set<String> blockedCountries = geoIPService.getBlockedCountries();
            Set<String> allowedCountries = geoIPService.getAllowedCountries();

            if (blockedCountries.contains(geoLocation.country)) {
                assessment.addRisk(15, "来源国家已被封锁: " + geoLocation.country);
            } else if (!allowedCountries.isEmpty() && !allowedCountries.contains(geoLocation.country)) {
                assessment.addRisk(10, "来源国家不在白名单中: " + geoLocation.country);
            }
        }

        RateLimitService.RateLimitStats rateLimitStats = rateLimitService.getStats(assessment.ip);
        if (rateLimitStats != null && rateLimitStats.rejections.get() > 0) {
            long rejections = rateLimitStats.rejections.get();
            assessment.addRisk((int) Math.min(10, rejections * 2), "限流拒绝次数: " + rejections);
        }

        assessment.riskScore = Math.min(100, assessment.riskScore);
        assessment.riskLevel = riskLevelFor(assessment.riskScore);
        return assessment;
    }

    private List<Map<String, Object>> toAssessmentMaps(List<ThreatAssessment> assessments, int limit) {
        List<Map<String, Object>> result = new ArrayList<>();
        int maxItems = Math.max(1, limit);
        for (ThreatAssessment assessment : assessments) {
            if (result.size() >= maxItems) {
                break;
            }
            result.add(assessment.toMap());
        }
        return result;
    }

    private List<String> buildRecommendations(int postureScore, List<ThreatAssessment> assessments) {
        List<String> recommendations = new ArrayList<>();

        if (assessments.isEmpty()) {
            recommendations.add("当前网络态势平稳，继续观察连接基线即可。");
            return recommendations;
        }

        if (assessments.stream().anyMatch(assessment -> assessment.riskScore >= CRITICAL_RISK_THRESHOLD)) {
            recommendations.add("优先隔离高风险 IP，并同步检查上游代理、防火墙或云清洗规则。");
        }

        if (portScanDetectionService.getStats().getOrDefault("blockedScanners", 0) instanceof Number blockedScanners
            && blockedScanners.longValue() > 0) {
            recommendations.add("当前存在端口扫描迹象，建议只暴露 Minecraft 与必要的管理入口。");
        }

        Map<String, Object> packetStats = packetInspectionService.getStats();
        if (toInt(packetStats.get("maliciousBlocked")) > 0) {
            recommendations.add("已检测到异常报文，建议复核包检测规则和上游流量清洗策略。");
        }

        if (postureScore < 60) {
            recommendations.add("建议把防火墙切到更严格的连接阈值，并临时提高关键接口限流。");
        }

        if (recommendations.isEmpty()) {
            recommendations.add("风险可控，继续观察高风险 IP 的后续行为。");
        }

        return recommendations.stream().limit(3).toList();
    }

    private String determineThreatLevel(int postureScore, int maxObservedRisk) {
        int compositeRisk = Math.max(maxObservedRisk, 100 - postureScore);
        return riskLevelFor(compositeRisk);
    }

    private String riskLevelFor(int riskScore) {
        if (riskScore >= 80) {
            return "critical";
        }
        if (riskScore >= 60) {
            return "high";
        }
        if (riskScore >= 40) {
            return "elevated";
        }
        if (riskScore >= 20) {
            return "guarded";
        }
        return "low";
    }

    private int countPacketAlerts(String ip) {
        int count = 0;
        for (PacketInspectionService.PacketAlert alert : packetInspectionService.getAlerts(EVENT_SAMPLE_SIZE)) {
            if (ip.equals(alert.sourceIP)) {
                count++;
            }
        }
        return count;
    }

    private int countIntrusionEvents(String ip) {
        int count = 0;
        for (IntrusionDetectionService.IntrusionEvent event : intrusionDetectionService.getEvents(EVENT_SAMPLE_SIZE)) {
            if (ip.equals(event.sourceIP)) {
                count++;
            }
        }
        return count;
    }

    private int countDdosEvents(String ip) {
        int count = 0;
        for (DDoSProtectionService.AttackEvent event : ddosProtectionService.getAttackLog(EVENT_SAMPLE_SIZE)) {
            if (ip.equals(event.ip)) {
                count++;
            }
        }
        return count;
    }

    private int countFirewallBlocks(String ip) {
        int count = 0;
        for (FirewallService.FirewallLog log : firewallService.getLogs(EVENT_SAMPLE_SIZE)) {
            if (ip.equals(log.sourceIP) && log.type.startsWith("BLOCK")) {
                count++;
            }
        }
        return count;
    }

    private void addCandidate(Collection<String> candidates, String source) {
        String normalized = normalizeTarget(source);
        if (normalized != null && isActionableSource(normalized)) {
            candidates.add(normalized);
        }
    }

    private boolean isActionableSource(String source) {
        String lower = source.toLowerCase(Locale.ROOT);
        return !lower.equals("system") && !lower.equals("request") && !lower.equals("unknown");
    }

    private String normalizeTarget(String ip) {
        if (ip == null) {
            return null;
        }
        String normalized = ip.trim();
        return normalized.isEmpty() ? null : normalized;
    }

    private Map<String, Object> invalidTarget(String status, String message) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", status);
        response.put("message", message);
        return response;
    }

    private String defaultText(String value, String fallback) {
        String normalized = normalizeTarget(value);
        return normalized != null ? normalized : fallback;
    }

    private int toInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text) {
            try {
                return Integer.parseInt(text);
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private double roundToOneDecimal(double value) {
        return Math.round(value * 10.0) / 10.0;
    }

    private void logInternalIncident(String source, String ip, String type, String details, int riskScore) {
        FusionIncident incident = new FusionIncident(source, ip, type, details, System.currentTimeMillis(), riskScore);
        incidentLog.addFirst(incident);
        while (incidentLog.size() > 500) {
            incidentLog.removeLast();
        }
    }

    private static final class ThreatAssessment {
        private final String ip;
        private int riskScore;
        private String riskLevel = "low";
        private boolean blocked;
        private boolean quarantined;
        private final List<String> reasons = new ArrayList<>();
        private final Map<String, Object> metadata = new LinkedHashMap<>();

        private ThreatAssessment(String ip) {
            this.ip = ip;
        }

        private void addRisk(int value, String reason) {
            if (value <= 0) {
                return;
            }
            riskScore += value;
            reasons.add(reason);
        }

        private Map<String, Object> toMap() {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("ip", ip);
            data.put("riskScore", Math.min(100, riskScore));
            data.put("riskLevel", riskLevel);
            data.put("blocked", blocked);
            data.put("quarantined", quarantined);
            data.put("reasons", reasons);
            data.put("metadata", metadata);
            return data;
        }
    }

    private static final class QuarantineRecord {
        private final String ip;
        private volatile String actor;
        private volatile String reason;
        private final long createdAt;
        private volatile long lastUpdated;
        private volatile int count = 1;

        private QuarantineRecord(String ip, String actor, String reason) {
            this.ip = ip;
            this.actor = actor;
            this.reason = reason;
            this.createdAt = System.currentTimeMillis();
            this.lastUpdated = createdAt;
        }

        private Map<String, Object> toMap() {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("ip", ip);
            data.put("actor", actor);
            data.put("reason", reason);
            data.put("createdAt", createdAt);
            data.put("lastUpdated", lastUpdated);
            data.put("count", count);
            return data;
        }
    }

    private static final class FusionIncident {
        private final String source;
        private final String ip;
        private final String type;
        private final String details;
        private final long timestamp;
        private final int riskScore;

        private FusionIncident(String source, String ip, String type, String details, long timestamp, int riskScore) {
            this.source = source;
            this.ip = ip;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
            this.riskScore = riskScore;
        }

        private Map<String, Object> toMap() {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("source", source);
            data.put("ip", ip);
            data.put("type", type);
            data.put("details", details);
            data.put("timestamp", timestamp);
            data.put("riskScore", riskScore);
            return data;
        }
    }
}
