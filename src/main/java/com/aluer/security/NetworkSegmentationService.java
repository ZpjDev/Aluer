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

@Component
public class NetworkSegmentationService {
    private static final Logger logger = LoggerFactory.getLogger(NetworkSegmentationService.class);

    private final Map<String, NetworkSegment> segments = new ConcurrentHashMap<>();
    private final Map<String, SegmentPolicy> policies = new ConcurrentHashMap<>();
    private final Map<String, List<String>> segmentConnections = new ConcurrentHashMap<>();
    private final Queue<SegmentationEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final AtomicLong totalSegments = new AtomicLong(0);
    private final AtomicLong violationsDetected = new AtomicLong(0);

    private volatile boolean enabled = true;
    private static final int MAX_EVENTS = 5000;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public NetworkSegmentationService() {
        initializeDefaultSegments();
        initializeDefaultPolicies();
        logger.info("Network Segmentation Service initialized");
    }

    private void initializeDefaultSegments() {
        addSegment("DMZ", "Demilitarized zone for public-facing services", "10.0.1.0/24");
        addSegment("APPLICATION", "Application servers and services", "10.0.2.0/24");
        addSegment("DATABASE", "Database servers and storage", "10.0.3.0/24");
        addSegment("MANAGEMENT", "Management and administrative systems", "10.0.4.0/24");
        addSegment("GUEST", "Guest and visitor networks", "10.0.5.0/24");
        addSegment("IOT", "IoT devices and sensors", "10.0.6.0/24");
        addSegment("SECURE", "Highly sensitive data and systems", "10.0.7.0/24");

        addConnection("DMZ", "APPLICATION");
        addConnection("APPLICATION", "DATABASE");
        addConnection("APPLICATION", "MANAGEMENT");
        addConnection("MANAGEMENT", "DATABASE");
        addConnection("DMZ", "GUEST", false);
        addConnection("IOT", "APPLICATION");

        logger.info("Initialized {} network segments", segments.size());
    }

    private void initializeDefaultPolicies() {
        addPolicy("DENY_ALL", "DENY", "Default deny all traffic between segments", 0);
        addPolicy("ALLOW_DMZ_TO_APP", "ALLOW", "Allow DMZ to Application traffic", 100);
        addPolicy("ALLOW_APP_TO_DB", "ALLOW", "Allow Application to Database", 100);
        addPolicy("ALLOW_MGMT_TO_ALL", "ALLOW", "Allow Management to all segments", 90);
        addPolicy("RESTRICT_GUEST", "RESTRICT", "Restrict guest network", 50);
        addPolicy("RESTRICT_IOT", "RESTRICT", "Restrict IoT devices", 60);
        addPolicy("AUDIT_SECURE", "AUDIT", "Audit all traffic to Secure segment", 80);

        logger.info("Initialized {} segmentation policies", policies.size());
    }

    public void addSegment(String name, String description, String cidr) {
        NetworkSegment segment = new NetworkSegment(name, description, cidr);
        segments.put(name, segment);
        segmentConnections.put(name, new ArrayList<>());
        totalSegments.incrementAndGet();
        logger.info("Added network segment: {} ({})", name, cidr);
    }

    public void addConnection(String from, String to) {
        addConnection(from, to, true);
    }

    public void addConnection(String from, String to, boolean allowed) {
        List<String> fromConnections = segmentConnections.computeIfAbsent(from, k -> new ArrayList<>());
        if (!fromConnections.contains(to)) {
            fromConnections.add(to);
        }

        if (allowed) {
            logEvent(from, to, "CONNECTION_ADDED", "Allowed connection added");
        } else {
            logEvent(from, to, "RESTRICTED_CONNECTION", "Restricted connection added");
        }

        logger.info("Added connection from {} to {}", from, to);
    }

    public void removeConnection(String from, String to) {
        List<String> fromConnections = segmentConnections.get(from);
        if (fromConnections != null) {
            fromConnections.remove(to);
        }
        logEvent(from, to, "CONNECTION_REMOVED", "Connection removed");
        logger.info("Removed connection from {} to {}", from, to);
    }

    public void addPolicy(String name, String type, String description, int priority) {
        SegmentPolicy policy = new SegmentPolicy(name, type, description, priority);
        policies.put(name, policy);
    }

    public boolean checkConnection(String sourceSegment, String destSegment) {
        List<String> allowedDestinations = segmentConnections.get(sourceSegment);

        if (allowedDestinations == null || allowedDestinations.isEmpty()) {
            return false;
        }

        if (allowedDestinations.contains(destSegment)) {
            return true;
        }

        SegmentPolicy policy = findMatchingPolicy(sourceSegment, destSegment);
        if (policy != null) {
            if ("DENY".equals(policy.getType())) {
                violationsDetected.incrementAndGet();
                logEvent(sourceSegment, destSegment, "VIOLATION", "Denied by policy: " + policy.getName());
                return false;
            }
            if ("ALLOW".equals(policy.getType())) {
                return true;
            }
        }

        return false;
    }

    private SegmentPolicy findMatchingPolicy(String source, String dest) {
        SegmentPolicy matched = null;
        int highestPriority = -1;

        for (SegmentPolicy policy : policies.values()) {
            if (matchesPolicy(policy, source, dest) && policy.getPriority() > highestPriority) {
                matched = policy;
                highestPriority = policy.getPriority();
            }
        }

        return matched;
    }

    private boolean matchesPolicy(SegmentPolicy policy, String source, String dest) {
        return true;
    }

    public void enforceMicrosegmentation(String segmentName) {
        NetworkSegment segment = segments.get(segmentName);
        if (segment == null) return;

        segment.setMicrosegmentationEnabled(true);

        List<String> connections = segmentConnections.get(segmentName);
        if (connections != null) {
            for (String dest : new ArrayList<>(connections)) {
                connections.clear();
                connections.add(dest);
            }
        }

        logEvent(segmentName, "ALL", "MICROSEGMENTATION", "Microsegmentation enforced");
        logger.info("Microsegmentation enforced for segment: {}", segmentName);
    }

    public void monitorTraffic(String sourceIP, String destIP) {
        String sourceSegment = identifySegment(sourceIP);
        String destSegment = identifySegment(destIP);

        if (sourceSegment == null || destSegment == null) {
            return;
        }

        if (!checkConnection(sourceSegment, destSegment)) {
            violationsDetected.incrementAndGet();
            logEvent(sourceSegment, destSegment, "UNAUTHORIZED", "Unauthorized traffic detected: " + sourceIP + " -> " + destIP);
            logger.warn("Unauthorized traffic: {} ({}) -> {} ({})", sourceIP, sourceSegment, destIP, destSegment);
        }
    }

    private String identifySegment(String ip) {
        for (NetworkSegment segment : segments.values()) {
            if (ip.startsWith(segment.getCidr().replace("/24", "").replace("10.0.", "10.0.").split("\\.")[0] + ".")) {
                return segment.getName();
            }
        }
        return null;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", enabled);
        stats.put("totalSegments", totalSegments.get());
        stats.put("violationsDetected", violationsDetected.get());
        stats.put("segmentsConfigured", segments.size());
        stats.put("policiesConfigured", policies.size());

        Map<String, Integer> connectionCounts = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : segmentConnections.entrySet()) {
            connectionCounts.put(entry.getKey(), entry.getValue().size());
        }
        stats.put("connectionCounts", connectionCounts);

        return stats;
    }

    public Map<String, NetworkSegment> getSegments() {
        return new HashMap<>(segments);
    }

    public Map<String, SegmentPolicy> getPolicies() {
        return new HashMap<>(policies);
    }

    public Map<String, List<String>> getConnections() {
        return new HashMap<>(segmentConnections);
    }

    public List<SegmentationEvent> getRecentEvents(int limit) {
        List<SegmentationEvent> events = new ArrayList<>();
        int count = 0;
        for (SegmentationEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    private void logEvent(String source, String dest, String action, String details) {
        SegmentationEvent event = new SegmentationEvent(source, dest, action, details, LocalDateTime.now());
        eventLog.offer(event);
        if (eventLog.size() > MAX_EVENTS) {
            eventLog.poll();
        }
    }

    public void enable() {
        enabled = true;
        logger.info("Network segmentation enabled");
    }

    public void disable() {
        enabled = false;
        logger.info("Network segmentation disabled");
    }

    public static class NetworkSegment {
        private final String name;
        private final String description;
        private final String cidr;
        private volatile boolean microsegmentationEnabled = false;

        public NetworkSegment(String name, String description, String cidr) {
            this.name = name;
            this.description = description;
            this.cidr = cidr;
        }

        public String getName() { return name; }
        public String getDescription() { return description; }
        public String getCidr() { return cidr; }
        public boolean isMicrosegmentationEnabled() { return microsegmentationEnabled; }
        public void setMicrosegmentationEnabled(boolean enabled) { this.microsegmentationEnabled = enabled; }
    }

    public static class SegmentPolicy {
        private final String name;
        private final String type;
        private final String description;
        private final int priority;

        public SegmentPolicy(String name, String type, String description, int priority) {
            this.name = name;
            this.type = type;
            this.description = description;
            this.priority = priority;
        }

        public String getName() { return name; }
        public String getType() { return type; }
        public String getDescription() { return description; }
        public int getPriority() { return priority; }
    }

    public static class SegmentationEvent {
        private final String source;
        private final String destination;
        private final String action;
        private final String details;
        private final LocalDateTime timestamp;

        public SegmentationEvent(String source, String destination, String action, String details, LocalDateTime timestamp) {
            this.source = source;
            this.destination = destination;
            this.action = action;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getSource() { return source; }
        public String getDestination() { return destination; }
        public String getAction() { return action; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
