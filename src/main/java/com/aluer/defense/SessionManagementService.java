package com.aluer.defense;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.time.LocalDateTime;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.security.MessageDigest;
import java.util.Base64;

@Component
public class SessionManagementService {
    private static final Logger logger = LoggerFactory.getLogger(SessionManagementService.class);

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<String, SessionMetadata> sessionMetadata = new ConcurrentHashMap<>();
    private final Queue<SessionEvent> eventLog = new ConcurrentLinkedQueue<>();
    private final Map<String, List<String>> userSessions = new ConcurrentHashMap<>();
    private final AtomicLong totalSessionsCreated = new AtomicLong(0);
    private final AtomicLong totalSessionsExpired = new AtomicLong(0);
    private final AtomicLong totalSessionsInvalidated = new AtomicLong(0);

    private static final int DEFAULT_SESSION_TIMEOUT_MINUTES = 30;
    private static final int MAX_SESSIONS_PER_USER = 5;
    private static final int SESSION_CLEANUP_INTERVAL_MINUTES = 5;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public SessionManagementService() {
        logger.info("Session Management Service initialized");
    }

    public Session createSession(String username, String ipAddress, String userAgent) {
        if (userSessions.containsKey(username)) {
            List<String> existing = userSessions.get(username);
            if (existing.size() >= MAX_SESSIONS_PER_USER) {
                logger.warn("User {} has reached maximum session limit", username);
                return null;
            }
        }

        String sessionId = generateSessionId(username);

        Session session = new Session(sessionId, username, ipAddress, userAgent);
        sessions.put(sessionId, session);

        SessionMetadata metadata = new SessionMetadata(username, ipAddress);
        sessionMetadata.put(sessionId, metadata);

        userSessions.computeIfAbsent(username, k -> new ArrayList<>()).add(sessionId);

        totalSessionsCreated.incrementAndGet();
        logEvent(sessionId, username, ipAddress, "CREATED", "New session created");

        logger.info("Created session for user: {} from IP: {}", username, ipAddress);
        return session;
    }

    public Session getSession(String sessionId) {
        Session session = sessions.get(sessionId);
        if (session != null && !session.isExpired()) {
            session.updateLastActivity();
            return session;
        }
        return null;
    }

    public boolean validateSession(String sessionId) {
        Session session = getSession(sessionId);
        return session != null;
    }

    public boolean invalidateSession(String sessionId) {
        Session session = sessions.remove(sessionId);
        if (session != null) {
            SessionMetadata metadata = sessionMetadata.remove(sessionId);

            List<String> userSessionList = userSessions.get(session.getUsername());
            if (userSessionList != null) {
                userSessionList.remove(sessionId);
                if (userSessionList.isEmpty()) {
                    userSessions.remove(session.getUsername());
                }
            }

            totalSessionsInvalidated.incrementAndGet();
            logEvent(sessionId, session.getUsername(), session.getIpAddress(), "INVALIDATED", "Session invalidated");

            logger.info("Invalidated session: {} for user: {}", sessionId, session.getUsername());
            return true;
        }
        return false;
    }

    public boolean extendSession(String sessionId, int additionalMinutes) {
        Session session = sessions.get(sessionId);
        if (session != null) {
            session.extendTimeout(additionalMinutes);
            logEvent(sessionId, session.getUsername(), session.getIpAddress(), "EXTENDED", "Session extended by " + additionalMinutes + " minutes");
            return true;
        }
        return false;
    }

    public void refreshSession(String sessionId) {
        Session session = sessions.get(sessionId);
        if (session != null) {
            session.updateLastActivity();
            SessionMetadata metadata = sessionMetadata.get(sessionId);
            if (metadata != null) {
                metadata.incrementActivityCount();
            }
        }
    }

    public List<Session> getUserSessions(String username) {
        List<String> sessionIds = userSessions.get(username);
        if (sessionIds == null) {
            return Collections.emptyList();
        }

        List<Session> userSessionsList = new ArrayList<>();
        for (String sessionId : sessionIds) {
            Session session = sessions.get(sessionId);
            if (session != null && !session.isExpired()) {
                userSessionsList.add(session);
            }
        }
        return userSessionsList;
    }

    public int invalidateUserSessions(String username) {
        List<String> sessionIds = userSessions.remove(username);
        if (sessionIds == null) {
            return 0;
        }

        int count = 0;
        for (String sessionId : sessionIds) {
            Session session = sessions.remove(sessionId);
            sessionMetadata.remove(sessionId);
            if (session != null) {
                count++;
                totalSessionsInvalidated.incrementAndGet();
            }
        }

        logger.info("Invalidated {} sessions for user: {}", count, username);
        return count;
    }

    public void cleanupExpiredSessions() {
        long now = System.currentTimeMillis();
        int expiredCount = 0;

        List<String> expiredSessionIds = new ArrayList<>();
        for (Map.Entry<String, Session> entry : sessions.entrySet()) {
            if (entry.getValue().isExpired()) {
                expiredSessionIds.add(entry.getKey());
            }
        }

        for (String sessionId : expiredSessionIds) {
            Session session = sessions.remove(sessionId);
            if (session != null) {
                SessionMetadata metadata = sessionMetadata.remove(sessionId);

                List<String> userSessionList = userSessions.get(session.getUsername());
                if (userSessionList != null) {
                    userSessionList.remove(sessionId);
                    if (userSessionList.isEmpty()) {
                        userSessions.remove(session.getUsername());
                    }
                }

                expiredCount++;
                totalSessionsExpired.incrementAndGet();
                logEvent(sessionId, session.getUsername(), session.getIpAddress(), "EXPIRED", "Session expired");
            }
        }

        if (expiredCount > 0) {
            logger.info("Cleaned up {} expired sessions", expiredCount);
        }
    }

    private String generateSessionId(String username) {
        try {
            String data = username + System.currentTimeMillis() + UUID.randomUUID().toString();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(data.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            return UUID.randomUUID().toString();
        }
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("activeSessions", sessions.size());
        stats.put("totalSessionsCreated", totalSessionsCreated.get());
        stats.put("totalSessionsExpired", totalSessionsExpired.get());
        stats.put("totalSessionsInvalidated", totalSessionsInvalidated.get());
        stats.put("uniqueUsers", userSessions.size());

        long now = System.currentTimeMillis();
        long activeCount = sessions.values().stream()
            .filter(s -> !s.isExpired())
            .count();
        stats.put("currentlyActive", activeCount);

        return stats;
    }

    public List<SessionEvent> getRecentEvents(int limit) {
        List<SessionEvent> events = new ArrayList<>();
        int count = 0;
        for (SessionEvent event : eventLog) {
            if (count++ >= limit) break;
            events.add(event);
        }
        return events;
    }

    public Map<String, Session> getAllActiveSessions() {
        Map<String, Session> active = new HashMap<>();
        for (Map.Entry<String, Session> entry : sessions.entrySet()) {
            if (!entry.getValue().isExpired()) {
                active.put(entry.getKey(), entry.getValue());
            }
        }
        return active;
    }

    public List<Session> getSessionsByIP(String ipAddress) {
        List<Session> result = new ArrayList<>();
        for (Session session : sessions.values()) {
            if (session.getIpAddress().equals(ipAddress) && !session.isExpired()) {
                result.add(session);
            }
        }
        return result;
    }

    private void logEvent(String sessionId, String username, String ipAddress, String eventType, String details) {
        SessionEvent event = new SessionEvent(sessionId, username, ipAddress, eventType, details, LocalDateTime.now());
        eventLog.offer(event);

        if (eventLog.size() > 5000) {
            eventLog.poll();
        }
    }

    public void setDefaultSessionTimeout(int minutes) {
        logger.info("Default session timeout set to {} minutes", minutes);
    }

    public static class Session {
        private final String sessionId;
        private final String username;
        private final String ipAddress;
        private final String userAgent;
        private final long createdAt;
        private volatile long lastActivityAt;
        private volatile long expiresAt;
        private volatile Map<String, Object> attributes = new ConcurrentHashMap<>();

        public Session(String sessionId, String username, String ipAddress, String userAgent) {
            this.sessionId = sessionId;
            this.username = username;
            this.ipAddress = ipAddress;
            this.userAgent = userAgent;
            this.createdAt = System.currentTimeMillis();
            this.lastActivityAt = createdAt;
            this.expiresAt = createdAt + (DEFAULT_SESSION_TIMEOUT_MINUTES * 60 * 1000L);
        }

        public void updateLastActivity() {
            this.lastActivityAt = System.currentTimeMillis();
        }

        public void extendTimeout(int additionalMinutes) {
            this.expiresAt = Math.max(expiresAt, System.currentTimeMillis()) + (additionalMinutes * 60 * 1000L);
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }

        public long getIdleTime() {
            return System.currentTimeMillis() - lastActivityAt;
        }

        public String getSessionId() { return sessionId; }
        public String getUsername() { return username; }
        public String getIpAddress() { return ipAddress; }
        public String getUserAgent() { return userAgent; }
        public long getCreatedAt() { return createdAt; }
        public long getLastActivityAt() { return lastActivityAt; }
        public long getExpiresAt() { return expiresAt; }
        public Map<String, Object> getAttributes() { return attributes; }

        public void setAttribute(String key, Object value) {
            attributes.put(key, value);
        }

        public Object getAttribute(String key) {
            return attributes.get(key);
        }
    }

    public static class SessionMetadata {
        private final String username;
        private final String originalIP;
        private volatile long activityCount;
        private volatile String lastActivity;
        private volatile long lastActivityTimestamp;

        public SessionMetadata(String username, String originalIP) {
            this.username = username;
            this.originalIP = originalIP;
            this.activityCount = 0;
            this.lastActivity = "session_created";
            this.lastActivityTimestamp = System.currentTimeMillis();
        }

        public void incrementActivityCount() {
            activityCount++;
            lastActivityTimestamp = System.currentTimeMillis();
        }

        public String getUsername() { return username; }
        public String getOriginalIP() { return originalIP; }
        public long getActivityCount() { return activityCount; }
        public String getLastActivity() { return lastActivity; }
        public void setLastActivity(String activity) { this.lastActivity = activity; }
        public long getLastActivityTimestamp() { return lastActivityTimestamp; }
    }

    public static class SessionEvent {
        private final String sessionId;
        private final String username;
        private final String ipAddress;
        private final String eventType;
        private final String details;
        private final LocalDateTime timestamp;

        public SessionEvent(String sessionId, String username, String ipAddress, String eventType, String details, LocalDateTime timestamp) {
            this.sessionId = sessionId;
            this.username = username;
            this.ipAddress = ipAddress;
            this.eventType = eventType;
            this.details = details;
            this.timestamp = timestamp;
        }

        public String getSessionId() { return sessionId; }
        public String getUsername() { return username; }
        public String getIpAddress() { return ipAddress; }
        public String getEventType() { return eventType; }
        public String getDetails() { return details; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}
