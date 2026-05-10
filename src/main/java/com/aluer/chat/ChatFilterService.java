package com.aluer.chat;

import com.aluer.config.ServerGuardConfig;
import com.aluer.service.RconClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class ChatFilterService {
    private static final Logger logger = LoggerFactory.getLogger(ChatFilterService.class);
    
    private final ServerGuardConfig config;
    private final RconClient rconClient;
    private final Map<String, PlayerChatRecord> chatRecords = new ConcurrentHashMap<>();
    private final Map<String, ViolationRecord> violations = new ConcurrentHashMap<>();
    
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern URL_PATTERN = Pattern.compile("(https?://|www\\.)[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+", Pattern.CASE_INSENSITIVE);
    
    private static final String[] PROFANITY_WORDS = {
        "fuck", "shit", "damn", "bitch", "ass", "bastard", "crap", "piss", "dick", "cock",
        "pussy", "cunt", "whore", "slut", "retard", "nigger", "faggot", "nigga"
    };
    
    private static final String[] ADVERTISING_PATTERNS = {
        "server", "play\\.mc", "\\.mine", "craft", "join", "ip:", "vote", "store",
        "shop", "buy", "sell", "free", "giveaway", "discord"
    };
    
    private static final String[] ILLEGAL_COMMANDS = {
        "/op", "/deop", "/sudo", "/lp", "/luckperms", "/pl", "/plugins", "/ver",
        "/icanhasbukkit", "/suicide", "/stop", "/restart", "/reload", "/pl"
    };

    public ChatFilterService(ServerGuardConfig config, RconClient rconClient) {
        this.config = config;
        this.rconClient = rconClient;
    }
    
    public FilterResult filterMessage(String playerName, String message) {
        if (!config.getChatFilter().isEnabled()) {
            return new FilterResult(true, message);
        }
        
        FilterResult result = new FilterResult(true, message);
        String lowerMessage = message.toLowerCase();
        
        if (config.getChatFilter().isBlockIp()) {
            Matcher ipMatcher = IP_PATTERN.matcher(message);
            if (ipMatcher.find()) {
                result.block("IP address detected");
                return result;
            }
        }
        
        if (config.getChatFilter().isBlockProfanity()) {
            for (String word : PROFANITY_WORDS) {
                if (lowerMessage.contains(word)) {
                    result.block("Profanity detected: " + word);
                    recordViolation(playerName, "PROFANITY");
                    return result;
                }
            }
            
            for (String word : config.getChatFilter().getCustomWords()) {
                if (lowerMessage.contains(word.toLowerCase())) {
                    result.block("Custom blocked word: " + word);
                    recordViolation(playerName, "CUSTOM");
                    return result;
                }
            }
        }
        
        if (config.getChatFilter().isBlockAdvertising()) {
            if (isAdvertising(lowerMessage)) {
                result.block("Advertising detected");
                recordViolation(playerName, "ADVERTISING");
                return result;
            }
        }
        
        if (config.getChatFilter().isBlockIllegal()) {
            for (String cmd : ILLEGAL_COMMANDS) {
                if (lowerMessage.matches(".*" + cmd + ".*")) {
                    result.block("Illegal command attempt: " + cmd);
                    recordViolation(playerName, "ILLEGAL_COMMAND");
                    return result;
                }
            }
        }
        
        if (config.getChatFilter().isBlockSpam()) {
            if (isSpam(playerName, message)) {
                result.block("Spam detected");
                recordViolation(playerName, "SPAM");
                return result;
            }
        }
        
        recordChat(playerName, message);
        
        return result;
    }
    
    private boolean isAdvertising(String message) {
        int matchCount = 0;
        for (String pattern : ADVERTISING_PATTERNS) {
            if (message.matches(".*" + pattern + ".*")) {
                matchCount++;
            }
        }
        
        URL_PATTERN.matcher(message);
        
        return matchCount >= 2 || URL_PATTERN.matcher(message).find();
    }
    
    private boolean isSpam(String playerName, String message) {
        PlayerChatRecord record = chatRecords.get(playerName);
        
        if (record == null) {
            record = new PlayerChatRecord(playerName);
            chatRecords.put(playerName, record);
        }
        
        int threshold = config.getChatFilter().getSpamThreshold();
        int window = config.getChatFilter().getSpamWindowSeconds();
        
        return record.isSpamming(message, threshold, window);
    }
    
    private void recordChat(String playerName, String message) {
        PlayerChatRecord record = chatRecords.computeIfAbsent(playerName, k -> new PlayerChatRecord(playerName));
        record.addMessage(message);
    }
    
    private void recordViolation(String playerName, String type) {
        ViolationRecord record = violations.computeIfAbsent(playerName, k -> new ViolationRecord(playerName));
        record.addViolation(type);
        
        handleViolation(playerName, record);
    }
    
    private void handleViolation(String playerName, ViolationRecord record) {
        int violationCount = record.getViolationCount();
        
        if (config.getChatFilter().isMuteOnViolation()) {
            int muteDuration = config.getChatFilter().getMuteDurationMinutes();
            rconClient.executeCommand("tempmute " + playerName + " " + muteDuration + "m Auto-muted by chat filter");
            logger.info("Auto-muted player {} for {} minutes", playerName, muteDuration);
        }
        
        if (config.getChatFilter().isKickOnRepeat()) {
            int maxViolations = config.getChatFilter().getMaxViolationsBeforeKick();
            
            if (violationCount >= maxViolations) {
                rconClient.kickPlayer(playerName, "Chat filter: Multiple violations");
                logger.warn("Kicked player {} for repeated chat violations", playerName);
                
                record.clearViolations();
            }
        }
    }
    
    public List<ViolationRecord> getTopViolators(int limit) {
        return violations.values().stream()
            .sorted((a, b) -> Integer.compare(b.getViolationCount(), a.getViolationCount()))
            .limit(limit)
            .toList();
    }
    
    public ViolationRecord getPlayerViolations(String playerName) {
        return violations.get(playerName);
    }
    
    public void clearPlayerViolations(String playerName) {
        violations.remove(playerName);
    }

    public List<String> getBlockedWords() {
        List<String> words = new ArrayList<>();
        words.addAll(Arrays.asList(PROFANITY_WORDS));
        words.addAll(Arrays.asList(ADVERTISING_PATTERNS));
        return words;
    }

    public static class FilterResult {
        private boolean allowed;
        private String originalMessage;
        private String filteredMessage;
        private String reason;
        
        public FilterResult(boolean allowed, String message) {
            this.allowed = allowed;
            this.originalMessage = message;
            this.filteredMessage = message;
        }
        
        public void block(String reason) {
            this.allowed = false;
            this.reason = reason;
            this.filteredMessage = "***";
        }
        
        public void replace(String from, String to) {
            this.filteredMessage = this.filteredMessage.replace(from, to);
        }
        
        public boolean isAllowed() { return allowed; }
        public String getOriginalMessage() { return originalMessage; }
        public String getFilteredMessage() { return filteredMessage; }
        public String getReason() { return reason; }
    }
    
    public static class PlayerChatRecord {
        private final String playerName;
        private final Deque<ChatMessage> recentMessages = new ArrayDeque<>();
        
        public PlayerChatRecord(String playerName) {
            this.playerName = playerName;
        }
        
        public void addMessage(String message) {
            recentMessages.add(new ChatMessage(message));
            
            while (recentMessages.size() > 20) {
                recentMessages.removeFirst();
            }
        }
        
        public boolean isSpamming(String message, int threshold, int windowSeconds) {
            LocalDateTime cutoff = LocalDateTime.now().minusSeconds(windowSeconds);
            
            long count = recentMessages.stream()
                .filter(m -> m.getTimestamp().isAfter(cutoff))
                .count();
            
            return count >= threshold;
        }
        
        public String getPlayerName() { return playerName; }
    }
    
    public static class ChatMessage {
        private final String content;
        private final LocalDateTime timestamp;
        
        public ChatMessage(String content) {
            this.content = content;
            this.timestamp = LocalDateTime.now();
        }
        
        public String getContent() { return content; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    public static class ViolationRecord {
        private final String playerName;
        private final Map<String, Integer> violationTypes = new HashMap<>();
        private final List<LocalDateTime> violationTimes = new ArrayList<>();
        private int totalViolations = 0;
        
        public ViolationRecord(String playerName) {
            this.playerName = playerName;
        }
        
        public void addViolation(String type) {
            violationTypes.merge(type, 1, Integer::sum);
            violationTimes.add(LocalDateTime.now());
            totalViolations++;
            
            while (violationTimes.size() > 100) {
                violationTimes.remove(0);
            }
        }
        
        public void clearViolations() {
            violationTypes.clear();
            violationTimes.clear();
            totalViolations = 0;
        }
        
        public String getPlayerName() { return playerName; }
        public int getViolationCount() { return totalViolations; }
        public Map<String, Integer> getViolationTypes() { return violationTypes; }
        public List<LocalDateTime> getViolationTimes() { return violationTimes; }
    }
}
