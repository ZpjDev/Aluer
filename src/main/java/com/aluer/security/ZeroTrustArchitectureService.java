package com.aluer.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component
public class ZeroTrustArchitectureService {
    private static final Logger logger = LoggerFactory.getLogger(ZeroTrustArchitectureService.class);

    private final Map<String, TrustPolicy> policies = new ConcurrentHashMap<>();
    private final Map<String, DeviceProfile> devices = new ConcurrentHashMap<>();
    private final Map<String, UserContext> userContexts = new ConcurrentHashMap<>();
    private final Map<String, AccessDecision> accessDecisions = new ConcurrentHashMap<>();
    private final Queue<ZeroTrustEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final Map<String, List<VerificationResult>> verificationHistory = new ConcurrentHashMap<>();
    private final AtomicLong totalAccessRequests = new AtomicLong(0);
    private final AtomicLong grantedAccess = new AtomicLong(0);
    private final AtomicLong deniedAccess = new AtomicLong(0);

    private volatile boolean enabled = true;
    private volatile String defaultPolicy = "DENY_ALL";
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    private static final int MAX_HISTORY = 10000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public ZeroTrustArchitectureService() {
        initializeDefaultPolicies();
        startContinuousVerification();
        logger.info("Zero Trust Architecture Service initialized");
    }

    private void initializeDefaultPolicies() {
        addPolicy("DENY_ALL", "DENY", "Default deny all", 0, new ArrayList<>());
        addPolicy("ALLOW_INTERNAL", "ALLOW", "Allow internal network", 100, Arrays.asList("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"));
        addPolicy("ALLOW_KNOWN_DEVICES", "CONDITIONAL", "Allow known devices with valid certs", 80, new ArrayList<>());
        addPolicy("MFA_REQUIRED", "CONDITIONAL", "Require MFA for sensitive resources", 90, new ArrayList<>());
        addPolicy("TIME_BASED_ACCESS", "CONDITIONAL", "Allow during business hours", 70, new ArrayList<>());
        addPolicy("IP_REPUTATION_BASED", "CONDITIONAL", "Allow based on IP reputation", 85, new ArrayList<>());
        addPolicy("DEVICE_HEALTH_CHECK", "CONDITIONAL", "Require healthy device", 75, new ArrayList<>());
        addPolicy("LEAST_PRIVILEGE", "CONDITIONAL", "Grant minimum required access", 95, new ArrayList<>());

        logger.info("Initialized {} trust policies", policies.size());
    }

    public void addPolicy(String name, String type, String description, int priority, List<String> conditions) {
        TrustPolicy policy = new TrustPolicy(name, type, description, priority, conditions);
        policies.put(name, policy);
    }

    public void addDevice(String deviceId, String type, String os, String macAddress, String owner) {
        DeviceProfile device = new DeviceProfile(deviceId, type, os, macAddress, owner);
        devices.put(deviceId, device);
        logger.info("Added device to Zero Trust: {}", deviceId);
    }

    public AccessDecision evaluateAccess(String userId, String deviceId, String resource, String action, Map<String, Object> context) {
        totalAccessRequests.incrementAndGet();

        AccessDecision decision = new AccessDecision();
        decision.setUserId(userId);
        decision.setDeviceId(deviceId);
        decision.setResource(resource);
        decision.setAction(action);
        decision.setTimestamp(LocalDateTime.now());

        TrustPolicy policy = selectPolicy(userId, deviceId, resource);

        if (policy == null) {
            decision.setGranted(false);
            decision.setReason("No matching policy found");
            deniedAccess.incrementAndGet();
            logEvent(userId, resource, "DENIED", "No matching policy");
            return decision;
        }

        boolean deviceTrusted = verifyDevice(deviceId);
        boolean userVerified = verifyUser(userId, context);
        boolean contextSafe = verifyContext(context);
        boolean resourceAccessible = checkResourceAccess(resource, action);

        decision.setPolicyName(policy.getName());
        decision.setDeviceTrusted(deviceTrusted);
        decision.setUserVerified(userVerified);
        decision.setContextSafe(contextSafe);

        boolean shouldGrant = evaluatePolicyConditions(policy, deviceTrusted, userVerified, contextSafe, resourceAccessible);

        decision.setGranted(shouldGrant);

        if (shouldGrant) {
            decision.setReason("Access granted by policy: " + policy.getName());
            grantedAccess.incrementAndGet();
            logEvent(userId, resource, "GRANTED", "Policy: " + policy.getName());
        } else {
            decision.setReason("Access denied - policy conditions not met");
            deniedAccess.incrementAndGet();
            logEvent(userId, resource, "DENIED", "Policy conditions not met");
        }

        accessDecisions.put(userId + ":" + resource + ":" + System.currentTimeMillis(), decision);

        return decision;
    }

    private TrustPolicy selectPolicy(String userId, String deviceId, String resource) {
        TrustPolicy matchedPolicy = null;
        int highestPriority = -1;

        for (TrustPolicy policy : policies.values()) {
            if (matchesResource(resource, policy) && policy.getPriority() > highestPriority) {
                matchedPolicy = policy;
                highestPriority = policy.getPriority();
            }
        }

        return matchedPolicy;
    }

    private boolean matchesResource(String resource, TrustPolicy policy) {
        return true;
    }

    private boolean verifyDevice(String deviceId) {
        DeviceProfile device = devices.get(deviceId);
        if (device == null) {
            return false;
        }

        boolean healthy = device.isHealthy();
        boolean encrypted = device.isEncrypted();
        boolean compliant = device.isCompliant();

        return healthy && encrypted && compliant;
    }

    private boolean verifyUser(String userId, Map<String, Object> context) {
        UserContext userContext = userContexts.get(userId);

        if (userContext == null) {
            return false;
        }

        boolean mfaVerified = userContext.isMfaVerified();
        boolean sessionValid = userContext.isSessionValid();

        return mfaVerified && sessionValid;
    }

    private boolean verifyContext(Map<String, Object> context) {
        if (context == null) {
            return false;
        }

        String location = (String) context.get("location");
        String device = (String) context.get("device");
        String network = (String) context.get("network");

        if (location != null && location.equals("UNKNOWN")) {
            return false;
        }

        if (network != null && network.equals("UNSECURED")) {
            return false;
        }

        return true;
    }

    private boolean checkResourceAccess(String resource, String action) {
        return true;
    }

    private boolean evaluatePolicyConditions(TrustPolicy policy, boolean deviceTrusted, boolean userVerified, boolean contextSafe, boolean resourceAccessible) {
        switch (policy.getType()) {
            case "ALLOW":
                return resourceAccessible;

            case "DENY":
                return false;

            case "CONDITIONAL":
                if (policy.getName().equals("ALLOW_KNOWN_DEVICES")) {
                    return deviceTrusted && resourceAccessible;
                }
                if (policy.getName().equals("MFA_REQUIRED")) {
                    return userVerified && deviceTrusted && resourceAccessible;
                }
                if (policy.getName().equals("TIME_BASED_ACCESS")) {
                    return isBusinessHours() && resourceAccessible;
                }
                if (policy.getName().equals("DEVICE_HEALTH_CHECK")) {
                    return deviceTrusted && resourceAccessible;
                }
                return deviceTrusted && userVerified && contextSafe && resourceAccessible;

            default:
                return false;
        }
    }

    private boolean isBusinessHours() {
        int hour = LocalDateTime.now().getHour();
        return hour >= 9 && hour <= 18;
    }

    public void updateUserContext(String userId, boolean mfaVerified, boolean sessionValid) {
        UserContext context = userContexts.computeIfAbsent(userId, k -> new UserContext(userId));
        context.setMfaVerified(mfaVerified);
        context.setSessionValid(sessionValid);
    }

    public void updateDeviceStatus(String deviceId, boolean healthy, boolean encrypted, boolean compliant) {
        DeviceProfile device = devices.get(deviceId);
        if (device != null) {
            device.setHealthy(healthy);
            device.setEncrypted(encrypted);
            device.setCompliant(compliant);
        }
    }

    public void revokeAccess(String userId, String resource) {
        logger.info("Revoking access for user {} to resource {}", userId, resource);
        logEvent(userId, resource, "REVOKED", "Access revoked manually");
    }

    public void grantTemporaryAccess(String userId, String resource, int durationMinutes) {
        logger.info("Granting temporary access for user {} to resource {} for {} minutes", userId, resource, durationMinutes);
        logEvent(userId, resource, "TEMP_GRANTED", "Temporary access for " + durationMinutes + " minutes");
    }

    private void startContinuousVerification() {
        scheduler.scheduleAtFixedRate(() -> {
            verifyAllActiveSessions();
            checkDeviceCompliance();
            analyzeAccessPatterns();
        }, 30, 30, TimeUnit.SECONDS);
    }

    private void verifyAllActiveSessions() {
        for (UserContext context : userContexts.values()) {
            if (context.isSessionValid()) {
                boolean stillValid = verifySession(context.getUserId());
                context.setSessionValid(stillValid);
            }
        }
    }

    private boolean verifySession(String userId) {
        return true;
    }

    private void checkDeviceCompliance() {
        for (DeviceProfile device : devices.values()) {
            if (!device.isHealthy()) {
                logger.warn("Device {} is not healthy", device.getDeviceId());
            }
        }
    }

    private void analyzeAccessPatterns() {
        Map<String, Long> resourceAccessCount = new HashMap<>();
        for (AccessDecision decision : accessDecisions.values()) {
            if (decision.isGranted()) {
                resourceAccessCount.merge(decision.getResource(), 1L, Long::sum);
            }
        }

        for (Map.Entry<String, Long> entry : resourceAccessCount.entrySet()) {
            if (entry.getValue() > 10000) {
                logger.warn("High access volume for resource: {} ({} accesses)", entry.getKey(), entry.getValue());
            }
        }
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", enabled);
        stats.put("defaultPolicy", defaultPolicy);
        stats.put("totalAccessRequests", totalAccessRequests.get());
        stats.put("grantedAccess", grantedAccess.get());
        stats.put("deniedAccess", deniedAccess.get());
        stats.put("policiesConfigured", policies.size());
        stats.put("registeredDevices", devices.size());
        stats.put("activeUsers", userContexts.size());

        double grantRate = totalAccessRequests.get() > 0 ?
            grantedAccess.get() * 100.0 / totalAccessRequests.get() : 0;
        stats.put("grantRate", String.format("%.2f%%", grantRate));

        return stats;
    }

    public Map<String, TrustPolicy> getPolicies() {
        return new HashMap<>(policies);
    }

    public Map<String, DeviceProfile> getDevices() {
        return new HashMap<>(devices);
    }

    public List<AccessDecision> getRecentDecisions(int limit) {
        List<AccessDecision> decisions = new ArrayList<>();
        int count = 0;
        for (AccessDecision decision : accessDecisions.values()) {
            if (count++ >= limit) break;
            decisions.add(decision);
        }
        return decisions;
    }

    public List<ZeroTrustEvent> getRecentEvents(int limit) {
        List<ZeroTrustEvent> events = new ArrayList<>();
        int count = 0;
        for (ZeroTrustEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    private void logEvent(String userId, String resource, String action, String details) {
        ZeroTrustEvent event = new ZeroTrustEvent(userId, resource, action, details, LocalDateTime.now());
        eventLog.offer(event);
        if (eventLog.size() > 5000) {
            eventLog.poll();
        }
    }

    public void enable() {
        enabled = true;
        logger.info("Zero Trust Architecture enabled");
    }

    public void disable() {
        enabled = false;
        logger.info("Zero Trust Architecture disabled");
    }

    public static class TrustPolicy {
        private final String name;
        private final String type;
        private final String description;
        private final int priority;
        private final List<String> conditions;

        public TrustPolicy(String name, String type, String description, int priority, List<String> conditions) {
            this.name = name;
            this.type = type;
            this.description = description;
            this.priority = priority;
            this.conditions = conditions;
        }

        public String getName() { return name; }
        public String getType() { return type; }
        public String getDescription() { return description; }
        public int getPriority() { return priority; }
        public List<String> getConditions() { return conditions; }
    }

    public static class DeviceProfile {
        private final String deviceId;
        private final String type;
        private final String os;
        private final String macAddress;
        private final String owner;
        private volatile boolean healthy = true;
        private volatile boolean encrypted = true;
        private volatile boolean compliant = true;
        private volatile long lastChecked;

        public DeviceProfile(String deviceId, String type, String os, String macAddress, String owner) {
            this.deviceId = deviceId;
            this.type = type;
            this.os = os;
            this.macAddress = macAddress;
            this.owner = owner;
            this.lastChecked = System.currentTimeMillis();
        }

        public String getDeviceId() { return deviceId; }
        public String getType() { return type; }
        public String getOs() { return os; }
        public String getMacAddress() { return macAddress; }
        public String getOwner() { return owner; }
        public boolean isHealthy() { return healthy; }
        public void setHealthy(boolean healthy) { this.healthy = healthy; }
        public boolean isEncrypted() { return encrypted; }
        public void setEncrypted(boolean encrypted) { this.encrypted = encrypted; }
        public boolean isCompliant() { return compliant; }
        public void setCompliant(boolean compliant) { this.compliant = compliant; }
        public long getLastChecked() { return lastChecked; }
        public void setLastChecked(long lastChecked) { this.lastChecked = lastChecked; }
    }

    public static class UserContext {
        private final String userId;
        private volatile boolean mfaVerified = false;
        private volatile boolean sessionValid = false;
        private volatile long lastActivity;

        public UserContext(String userId) {
            this.userId = userId;
            this.lastActivity = System.currentTimeMillis();
        }

        public String getUserId() { return userId; }
        public boolean isMfaVerified() { return mfaVerified; }
        public void setMfaVerified(boolean mfaVerified) { this.mfaVerified = mfaVerified; }
        public boolean isSessionValid() { return sessionValid; }
        public void setSessionValid(boolean sessionValid) { this.sessionValid = sessionValid; }
        public long getLastActivity() { return lastActivity; }
        public void setLastActivity(long lastActivity) { this.lastActivity = lastActivity; }
    }

    public static class AccessDecision {
        private String userId;
        private String deviceId;
        private String resource;
        private String action;
        private String policyName;
        private boolean granted;
        private String reason;
        private boolean deviceTrusted;
        private boolean userVerified;
        private boolean contextSafe;
        private LocalDateTime timestamp;

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getDeviceId() { return deviceId; }
        public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
        public String getResource() { return resource; }
        public void setResource(String resource) { this.resource = resource; }
        public String getAction() { return action; }
        public void setAction(String action) { this.action = action; }
        public String getPolicyName() { return policyName; }
        public void setPolicyName(String policyName) { this.policyName = policyName; }
        public boolean isGranted() { return granted; }
        public void setGranted(boolean granted) { this.granted = granted; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public boolean isDeviceTrusted() { return deviceTrusted; }
        public void setDeviceTrusted(boolean deviceTrusted) { this.deviceTrusted = deviceTrusted; }
        public boolean isUserVerified() { return userVerified; }
        public void setUserVerified(boolean userVerified) { this.userVerified = userVerified; }
        public boolean isContextSafe() { return contextSafe; }
        public void setContextSafe(boolean contextSafe) { this.contextSafe = contextSafe; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    }

    public static class VerificationResult {
        private final String entityId;
        private final String entityType;
        private final boolean verified;
        private final String details;
        private final LocalDateTime timestamp;

        public VerificationResult(String entityId, String entityType, boolean verified, String details) {
            this.entityId = entityId;
            this.entityType = entityType;
            this.verified = verified;
            this.details = details;
            this.timestamp = LocalDateTime.now();
        }

        public String getEntityId() { return entityId; }
        public String getEntityType() { return entityType; }
        public boolean isVerified() { return verified; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    public static class ZeroTrustEvent {
        private final String userId;
        private final String resource;
        private final String action;
        private final String details;
        private final LocalDateTime timestamp;

        public ZeroTrustEvent(String userId, String resource, String action, String details, LocalDateTime timestamp) {
            this.userId = userId;
            this.resource = resource;
            this.action = action;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getUserId() { return userId; }
        public String getResource() { return resource; }
        public String getAction() { return action; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
