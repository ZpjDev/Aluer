package com.aluer.security;

import org.springframework.stereotype.Service;

import java.net.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class SSRFProtectionService {

    private final Map<String, List<SSRFEvent>> detections = new ConcurrentHashMap<>();
    private final AtomicLong totalBlocked = new AtomicLong(0);

    private static final Set<String> BLOCKED_SCHEMES = Set.of(
            "file", "gopher", "dict", "ftp", "ldap", "ldaps", "jar", "netdoc", "php", "tftp"
    );

    private static final Set<String> INTERNAL_IPS = Set.of(
            "127.0.0.1", "0.0.0.0", "localhost", "::1", "[::1]",
            "169.254.169.254", "100.64.0.0", "198.18.0.0", "198.19.0.0"
    );

    private static final List<String> INTERNAL_CIDRS = List.of(
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "0.0.0.0/8",
            "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"
    );

    private static final Set<String> METADATA_PATHS = Set.of(
            "/latest/meta-data", "/latest/user-data", "/metadata", "/instance-identity",
            "/computeMetadata/v1", "/iam/security-credentials", "/opc/v1/instance",
            "/latest/dynamic", "/latest/api/token", "/a/b/c/meta-data"
    );

    private static final Set<String> BLOCKED_HOSTS = Set.of(
            "metadata.google.internal", "metadata.tencentyun.com", "100.100.100.200",
            "metadata.alibabacloud.com", "169.254.169.254"
    );

    public SSRFCheckResult checkURL(String url, String sourceIP) {
        if (url == null || url.trim().isEmpty()) return SSRFCheckResult.clean();

        List<String> reasons = new ArrayList<>();

        try {
            URI uri = new URI(url.trim());

            // Check scheme
            String scheme = uri.getScheme();
            if (scheme != null && BLOCKED_SCHEMES.contains(scheme.toLowerCase())) {
                reasons.add("BLOCKED_SCHEME: " + scheme);
            }

            // Check host
            String host = uri.getHost();
            if (host == null) {
                reasons.add("NULL_HOST");
            } else {
                // Direct internal IPs
                if (INTERNAL_IPS.contains(host.toLowerCase())) {
                    reasons.add("INTERNAL_HOST: " + host);
                }

                // Blocked hostnames
                if (BLOCKED_HOSTS.contains(host.toLowerCase())) {
                    reasons.add("BLOCKED_CLOUD_METADATA: " + host);
                }

                // DNS rebinding check: host containing "127.0.0.1" or similar
                try {
                    InetAddress addr = InetAddress.getByName(host);
                    String ip = addr.getHostAddress();
                    if (isInternalIP(ip)) {
                        reasons.add("RESOLVES_TO_INTERNAL: " + host + " -> " + ip);
                    }
                } catch (UnknownHostException ignored) {}

                // IP in hostname
                if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") && isInternalIP(host)) {
                    reasons.add("INTERNAL_IP_DIRECT: " + host);
                }
            }

            // Check path for metadata endpoints
            String path = uri.getPath();
            if (path != null) {
                for (String metaPath : METADATA_PATHS) {
                    if (path.toLowerCase().contains(metaPath.toLowerCase())) {
                        reasons.add("CLOUD_METADATA_PATH: " + path);
                        break;
                    }
                }
            }

            // Check for URL-encoded internal IPs
            String decoded = url.toLowerCase();
            if (decoded.contains("%31%32%37") || decoded.contains("127%2e") || decoded.contains("localhost")) {
                reasons.add("ENCODED_INTERNAL_IP");
            }

            // Decimal/octal IP bypass
            if (host != null && host.matches("\\d{8,12}")) {
                try {
                    long decimal = Long.parseLong(host);
                    String resolved = ((decimal >> 24) & 0xFF) + "." + ((decimal >> 16) & 0xFF) + "."
                            + ((decimal >> 8) & 0xFF) + "." + (decimal & 0xFF);
                    if (isInternalIP(resolved)) {
                        reasons.add("DECIMAL_IP_BYPASS: " + host + " -> " + resolved);
                    }
                } catch (NumberFormatException ignored) {}
            }

        } catch (URISyntaxException e) {
            reasons.add("INVALID_URI: " + e.getMessage());
        }

        if (!reasons.isEmpty()) {
            SSRFEvent event = new SSRFEvent(Instant.now(), sourceIP, url, reasons);
            detections.computeIfAbsent(sourceIP, k -> new ArrayList<>()).add(event);
            totalBlocked.incrementAndGet();
            return SSRFCheckResult.blocked(reasons);
        }

        return SSRFCheckResult.clean();
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("totalBlocked", totalBlocked.get());
        status.put("trackedSources", detections.size());
        List<Map<String, Object>> recent = new ArrayList<>();
        for (Map.Entry<String, List<SSRFEvent>> e : detections.entrySet()) {
            for (SSRFEvent event : e.getValue()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("source", e.getKey());
                m.put("url", event.url.length() > 80 ? event.url.substring(0, 80) : event.url);
                m.put("reasons", event.reasons);
                m.put("time", event.timestamp.toString());
                recent.add(m);
            }
        }
        recent.sort((a, b) -> b.get("time").toString().compareTo(a.get("time").toString()));
        status.put("recentDetections", recent.subList(0, Math.min(recent.size(), 20)));
        return status;
    }

    public long getTotalBlocked() { return totalBlocked.get(); }

    private boolean isInternalIP(String ip) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length != 4) return false;
            int first = Integer.parseInt(parts[0]);
            int second = Integer.parseInt(parts[1]);
            if (first == 10) return true;
            if (first == 127) return true;
            if (first == 169 && second == 254) return true;
            if (first == 172 && second >= 16 && second <= 31) return true;
            if (first == 192 && second == 168) return true;
            if (first == 0) return true;
            if (first >= 224 && first <= 255) return true;
            return false;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static class SSRFEvent {
        final Instant timestamp;
        final String sourceIP;
        final String url;
        final List<String> reasons;

        SSRFEvent(Instant timestamp, String sourceIP, String url, List<String> reasons) {
            this.timestamp = timestamp;
            this.sourceIP = sourceIP;
            this.url = url;
            this.reasons = reasons;
        }
    }

    public static class SSRFCheckResult {
        private final boolean blocked;
        private final List<String> reasons;

        private SSRFCheckResult(boolean blocked, List<String> reasons) {
            this.blocked = blocked;
            this.reasons = reasons;
        }

        public static SSRFCheckResult clean() { return new SSRFCheckResult(false, List.of()); }
        public static SSRFCheckResult blocked(List<String> reasons) { return new SSRFCheckResult(true, reasons); }

        public boolean isBlocked() { return blocked; }
        public List<String> getReasons() { return reasons; }
    }
}
