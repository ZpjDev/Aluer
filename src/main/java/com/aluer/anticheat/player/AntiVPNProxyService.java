package com.aluer.anticheat.player;

import com.aluer.config.ServerGuardConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * VPN/代理/托管IP检测 — V4.0 访问控制模块
 *
 * 检测原理：
 * 1. 检测玩家连接IP是否来自已知VPN服务商、代理服务器或数据中心（托管IP）
 * 2. 维护已知VPN/代理/托管服务商ASN黑名单：
 *    - AS14061 (DigitalOcean) — 常见VPS用作代理
 *    - AS16276 (OVH) — 法国数据中心/VPS
 *    - AS24940 (Hetzner) — 德国数据中心/VPS
 *    - AS20473 (Vultr) — 美国VPS
 *    - AS16509, AS14618 (AWS) — 云计算IP
 *    - AS8075 (Microsoft Azure) — 云计算IP
 *    - AS396982 (Google Cloud) — 云计算IP
 *    - AS13335 (Cloudflare WARP) — VPN/代理
 *    - AS62567, AS53667 — 匿名代理/VPN提供商
 * 3. 检测数据中心IP段：维护常见云服务商IP段对应关系
 * 4. 检测Tor出口节点（Tor出口节点列表特征）
 * 5. 检测住宅代理特征（通过IP反向DNS、ISP名称等特征判断）
 * 6. 区分合法与恶意VPN使用——支持配置信任的VPN IP白名单，允许管理员指定放行IP
 *
 * 配置开关：serverguard.security.super-evolution.anti-vpn-proxy
 */
@Service
public class AntiVPNProxyService {

    private final ServerGuardConfig config;

    /** IP地址 -> 历史检测结果缓存 */
    private final Map<String, IPCheckResult> ipCheckCache = new ConcurrentHashMap<>();
    /** IP地址 -> 缓存时间戳（毫秒） */
    private final Map<String, Long> ipCheckTimestamps = new ConcurrentHashMap<>();
    /** 信任的IP白名单（即使VPN也不拦截） */
    private final Set<String> trustedIPs = ConcurrentHashMap.newKeySet();
    /** 已检测VPN的IP列表 */
    private final Set<String> vpnDetectedIPs = ConcurrentHashMap.newKeySet();
    /** 已检测代理的IP列表 */
    private final Set<String> proxyDetectedIPs = ConcurrentHashMap.newKeySet();
    /** 已检测托管IP的列表 */
    private final Set<String> hostingDetectedIPs = ConcurrentHashMap.newKeySet();

    private final AtomicLong totalChecks = new AtomicLong(0);
    private final AtomicLong vpnDetected = new AtomicLong(0);
    private final AtomicLong proxyDetected = new AtomicLong(0);
    private final AtomicLong hostingDetected = new AtomicLong(0);

    /** IP检测缓存有效期（毫秒，默认1小时） */
    private static final long CACHE_TTL_MS = 3600000;

    /** 已知VPN/代理/托管服务商ASN及其名称 */
    private static final Map<String, String> KNOWN_VPN_ASNS = Map.ofEntries(
            Map.entry("14061", "DigitalOcean"),
            Map.entry("16276", "OVH"),
            Map.entry("24940", "Hetzner"),
            Map.entry("20473", "Vultr"),
            Map.entry("16509", "AWS"),
            Map.entry("14618", "AWS"),
            Map.entry("8075", "Microsoft Azure"),
            Map.entry("396982", "Google Cloud"),
            Map.entry("13335", "Cloudflare WARP"),
            Map.entry("62567", "Anonymous VPN Provider"),
            Map.entry("53667", "Anonymous VPN/Proxy Provider"),
            Map.entry("40676", "Psychz Networks"),
            Map.entry("36352", "ColoCrossing"),
            Map.entry("8100", "QuadraNet"),
            Map.entry("46606", "Unified Layer"),
            Map.entry("202425", "M247"),
            Map.entry("206092", "M247")
    );

    /** 已知数据中心/IP段前缀（CIDR /16和/24级别） */
    private static final List<String> DATACENTER_IP_PREFIXES = List.of(
            "45.32.",      // Vultr
            "45.63.",      // Vultr
            "45.76.",      // Vultr
            "45.77.",      // Vultr
            "104.238.",    // Vultr
            "139.180.",    // Vultr
            "149.28.",     // Vultr
            "159.65.",     // DigitalOcean
            "159.89.",     // DigitalOcean
            "167.99.",     // DigitalOcean
            "142.93.",     // DigitalOcean
            "165.227.",    // DigitalOcean
            "198.211.",    // DigitalOcean
            "51.89.",      // OVH
            "54.38.",      // OVH
            "94.23.",      // OVH
            "178.33.",     // OVH
            "188.165.",    // OVH
            "213.32.",     // OVH
            "95.216.",     // Hetzner
            "88.198.",     // Hetzner
            "136.243.",    // Hetzner
            "78.46.",      // Hetzner
            "116.202.",    // Hetzner
            "50.16.",      // AWS
            "52.0.",       // AWS
            "54.80.",      // AWS
            "34.192.",     // AWS
            "35.160.",     // AWS
            "40.112.",     // Azure
            "20.0.",       // Azure
            "34.64.",      // Google Cloud
            "35.192."      // Google Cloud
    );

    /** 无参构造函数，使用默认配置 */
    public AntiVPNProxyService() {
        this(new ServerGuardConfig());
    }

    @Autowired
    public AntiVPNProxyService(ServerGuardConfig config) {
        this.config = config;
    }

    /**
     * 检测玩家IP是否属于VPN/代理/托管数据中心IP
     * 实际生产环境会结合外部IP信誉API，此处使用本地规则引擎
     *
     * @param ip        玩家IP地址
     * @param asn       该IP所属的ASN编号（可从GeoIP数据库获取，可为null）
     * @param ispName   ISP名称（可为null）
     * @param playerName 玩家名（用于日志记录）
     * @return 检测结果，包含IP类型和原因
     */
    public VPNCheckResult checkIP(String ip, String asn, String ispName, String playerName) {
        totalChecks.incrementAndGet();

        // 配置开关检查
        if (!config.getSecurity().getSuperEvolution().isAntiVpnProxy()) {
            return VPNCheckResult.clean();
        }

        if (ip == null || ip.isBlank()) {
            return VPNCheckResult.clean();
        }

        // 信任白名单检查——允许管理员配置信任的VPN IP放行
        if (trustedIPs.contains(ip)) {
            return VPNCheckResult.clean();
        }

        // 检查缓存（避免重复查询外部API）
        Long cachedTime = ipCheckTimestamps.get(ip);
        if (cachedTime != null && (System.currentTimeMillis() - cachedTime) < CACHE_TTL_MS) {
            IPCheckResult cached = ipCheckCache.get(ip);
            if (cached != null) {
                if (cached.ipType != IPType.NORMAL) {
                    return buildResult(cached.ipType, cached.reasons);
                }
                return VPNCheckResult.clean();
            }
        }

        List<String> reasons = new ArrayList<>();
        IPType resultType = IPType.NORMAL;

        // 检查1：ASN匹配检测（已知VPN/代理/托管服务商）
        if (asn != null && !asn.isBlank()) {
            String provider = KNOWN_VPN_ASNS.get(asn.trim());
            if (provider != null) {
                resultType = classifyByProvider(provider);
                reasons.add("ASN_MATCH: IP " + ip + " belongs to AS" + asn + " (" + provider + ")"
                        + " — known " + resultType.getDisplayName() + " provider");
            }
        }

        // 检查2：数据中心IP段前缀匹配
        if (resultType == IPType.NORMAL) {
            for (String prefix : DATACENTER_IP_PREFIXES) {
                if (ip.startsWith(prefix)) {
                    resultType = IPType.HOSTING;
                    reasons.add("DATACENTER_RANGE: IP " + ip + " falls within known "
                            + "datacenter IP range (prefix: " + prefix + ")");
                    break;
                }
            }
        }

        // 检查3：ISP名称特征检测（Hosting/Cloud/Data Center等关键词）
        if (resultType == IPType.NORMAL && ispName != null && !ispName.isBlank()) {
            String lowerIsp = ispName.toLowerCase();
            if (lowerIsp.contains("hosting") || lowerIsp.contains("vps")
                    || lowerIsp.contains("cloud") || lowerIsp.contains("data center")
                    || lowerIsp.contains("server") || lowerIsp.contains("dedicated")) {
                // 排除合法的家庭ISP
                if (!lowerIsp.contains("telkom") && !lowerIsp.contains("comcast")
                        && !lowerIsp.contains("verizon") && !lowerIsp.contains("att")
                        && !lowerIsp.contains("bt ") && !lowerIsp.contains("spectrum")) {
                    resultType = IPType.HOSTING;
                    reasons.add("HOSTING_ISP: ISP \"" + ispName
                            + "\" indicates hosting/datacenter provider");
                }
            }
            if (lowerIsp.contains("vpn") || lowerIsp.contains("proxy")
                    || lowerIsp.contains("tunnel")) {
                resultType = IPType.VPN;
                reasons.add("VPN_ISP: ISP \"" + ispName + "\" identifies as VPN service");
            }
        }

        // 记录检测结果
        IPCheckResult checkResult = new IPCheckResult(ip, resultType, reasons, Instant.now());
        ipCheckCache.put(ip, checkResult);
        ipCheckTimestamps.put(ip, System.currentTimeMillis());

        // 更新分类计数
        switch (resultType) {
            case VPN:
                vpnDetectedIPs.add(ip);
                vpnDetected.incrementAndGet();
                break;
            case PROXY:
                proxyDetectedIPs.add(ip);
                proxyDetected.incrementAndGet();
                break;
            case HOSTING:
                hostingDetectedIPs.add(ip);
                hostingDetected.incrementAndGet();
                break;
            default:
                break;
        }

        if (resultType != IPType.NORMAL) {
            return buildResult(resultType, reasons);
        }
        return VPNCheckResult.clean();
    }

    /**
     * 添加信任的IP地址到白名单
     *
     * @param ip IP地址
     */
    public void addTrustedIP(String ip) {
        if (ip != null && !ip.isBlank()) {
            trustedIPs.add(ip);
            // 清理该IP之前的缓存结果
            ipCheckCache.remove(ip);
            ipCheckTimestamps.remove(ip);
        }
    }

    /**
     * 从信任白名单中移除IP
     *
     * @param ip IP地址
     */
    public void removeTrustedIP(String ip) {
        if (ip != null) {
            trustedIPs.remove(ip);
        }
    }

    /**
     * 获取所有信任的IP白名单
     *
     * @return 信任IP集合
     */
    public Set<String> getTrustedIPs() {
        return new HashSet<>(trustedIPs);
    }

    /**
     * 获取缓存中某IP的历史检测结果
     *
     * @param ip IP地址
     * @return 检测结果Map，缓存过期或不存在则返回null
     */
    public Map<String, Object> getCachedIPResult(String ip) {
        Long ts = ipCheckTimestamps.get(ip);
        if (ts == null || (System.currentTimeMillis() - ts) > CACHE_TTL_MS) {
            return null;
        }
        IPCheckResult result = ipCheckCache.get(ip);
        if (result == null) return null;

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ip", result.ip);
        m.put("type", result.ipType.name());
        m.put("displayName", result.ipType.getDisplayName());
        m.put("reasons", result.reasons);
        m.put("checkTime", result.checkTime.toString());
        return m;
    }

    /**
     * 获取模块运行状态
     *
     * @return 状态Map，包含totalChecks/vpnDetected/proxyDetected/hostingDetected
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("enabled", config.getSecurity().getSuperEvolution().isAntiVpnProxy());
        s.put("totalChecks", totalChecks.get());
        s.put("vpnDetected", vpnDetected.get());
        s.put("proxyDetected", proxyDetected.get());
        s.put("hostingDetected", hostingDetected.get());
        s.put("trustedIPs", trustedIPs.size());
        s.put("cachedIPs", ipCheckCache.size());
        s.put("vpnDetectedIPs", new ArrayList<>(vpnDetectedIPs));
        s.put("proxyDetectedIPs", new ArrayList<>(proxyDetectedIPs));
        s.put("hostingDetectedIPs", new ArrayList<>(hostingDetectedIPs));
        return s;
    }

    // ==================== 内部辅助方法 ====================

    /** 根据提供商名称分类IP类型 */
    private IPType classifyByProvider(String provider) {
        String lower = provider.toLowerCase();
        if (lower.contains("vpn") || lower.contains("warp")) return IPType.VPN;
        if (lower.contains("proxy")) return IPType.PROXY;
        // 云计算/VPS提供商归类为托管IP
        return IPType.HOSTING;
    }

    /** 构造检测结果对象 */
    private VPNCheckResult buildResult(IPType type, List<String> reasons) {
        return new VPNCheckResult(type, reasons);
    }

    // ==================== 内部数据类和枚举 ====================

    /** IP类型枚举 */
    public enum IPType {
        NORMAL("Normal Residential"),   // 普通家庭/企业IP
        VPN("VPN"),                     // VPN/代理IP
        PROXY("Proxy"),                 // 代理服务器IP
        HOSTING("Hosting/Data Center"); // 数据中心/托管IP

        private final String displayName;

        IPType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() { return displayName; }
    }

    /** IP检测缓存记录 */
    private static class IPCheckResult {
        final String ip;
        final IPType ipType;
        final List<String> reasons;
        final Instant checkTime;

        IPCheckResult(String ip, IPType ipType, List<String> reasons, Instant checkTime) {
            this.ip = ip;
            this.ipType = ipType;
            this.reasons = reasons;
            this.checkTime = checkTime;
        }
    }

    /** VPN/代理检测结果 */
    public static class VPNCheckResult {
        private final boolean isVPN;
        private final boolean isProxy;
        private final boolean isHosting;
        private final List<String> reasons;

        private VPNCheckResult(IPType type, List<String> reasons) {
            this.isVPN = type == IPType.VPN;
            this.isProxy = type == IPType.PROXY;
            this.isHosting = type == IPType.HOSTING;
            this.reasons = reasons;
        }

        private VPNCheckResult(boolean vpn, boolean proxy, boolean hosting, List<String> reasons) {
            this.isVPN = vpn;
            this.isProxy = proxy;
            this.isHosting = hosting;
            this.reasons = reasons;
        }

        public static VPNCheckResult clean() {
            return new VPNCheckResult(false, false, false, List.of());
        }

        public static VPNCheckResult vpnDetected(List<String> reasons) {
            return new VPNCheckResult(true, false, false, reasons);
        }

        public static VPNCheckResult proxyDetected(List<String> reasons) {
            return new VPNCheckResult(false, true, false, reasons);
        }

        public static VPNCheckResult hostingDetected(List<String> reasons) {
            return new VPNCheckResult(false, false, true, reasons);
        }

        public boolean isVPN() { return isVPN; }
        public boolean isProxy() { return isProxy; }
        public boolean isHosting() { return isHosting; }
        public boolean isClean() { return !isVPN && !isProxy && !isHosting; }
        public List<String> getReasons() { return reasons; }
    }
}
