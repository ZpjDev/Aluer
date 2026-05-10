package com.aluer.security;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class JwtAuthService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final long DEFAULT_TTL_SECONDS = 3600;
    private static final long MAX_TTL_SECONDS = 86400;

    private final String secret;
    private final Map<String, TokenEntry> tokenStore = new ConcurrentHashMap<>();
    private final Map<String, List<String>> userTokens = new ConcurrentHashMap<>();
    private final Map<String, Instant> revokedTokens = new ConcurrentHashMap<>();

    public JwtAuthService() {
        byte[] keyBytes = new byte[64];
        SECURE_RANDOM.nextBytes(keyBytes);
        this.secret = Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes);
    }

    public String createToken(String subject, Map<String, Object> claims, long ttlSeconds) {
        long effectiveTtl = Math.min(ttlSeconds > 0 ? ttlSeconds : DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS);
        long now = Instant.now().getEpochSecond();
        long exp = now + effectiveTtl;
        String jti = generateJti();

        StringBuilder payload = new StringBuilder();
        payload.append("sub=").append(subject).append("&");
        payload.append("iat=").append(now).append("&");
        payload.append("exp=").append(exp).append("&");
        payload.append("jti=").append(jti);

        if (claims != null) {
            for (Map.Entry<String, Object> e : claims.entrySet()) {
                payload.append("&").append(e.getKey()).append("=").append(e.getValue());
            }
        }

        String payloadEncoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));
        String signature = hmacSha256(payloadEncoded, secret);

        String token = payloadEncoded + "." + signature;

        TokenEntry entry = new TokenEntry(subject, jti, Instant.ofEpochSecond(now), Instant.ofEpochSecond(exp), claims);
        tokenStore.put(jti, entry);
        userTokens.computeIfAbsent(subject, k -> new ArrayList<>()).add(jti);

        return token;
    }

    public String createToken(String subject) {
        return createToken(subject, null, DEFAULT_TTL_SECONDS);
    }

    public TokenValidationResult validateToken(String token) {
        if (token == null || !token.contains(".")) {
            return TokenValidationResult.invalid("Malformed token");
        }

        String[] parts = token.split("\\.", 2);
        String payloadEncoded = parts[0];
        String providedSignature = parts[1];

        String expectedSignature = hmacSha256(payloadEncoded, secret);
        if (!constantTimeEquals(expectedSignature, providedSignature)) {
            return TokenValidationResult.invalid("Signature mismatch");
        }

        String payload;
        try {
            payload = new String(Base64.getUrlDecoder().decode(payloadEncoded), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return TokenValidationResult.invalid("Invalid base64 payload");
        }

        Map<String, String> parsed = parsePayload(payload);
        String jti = parsed.get("jti");
        if (jti == null) {
            return TokenValidationResult.invalid("Missing jti");
        }
        if (revokedTokens.containsKey(jti)) {
            return TokenValidationResult.invalid("Token revoked");
        }

        long exp = Long.parseLong(parsed.getOrDefault("exp", "0"));
        if (Instant.now().getEpochSecond() > exp) {
            return TokenValidationResult.invalid("Token expired");
        }

        String subject = parsed.get("sub");
        Map<String, Object> claims = new HashMap<>(parsed);
        claims.remove("sub");
        claims.remove("iat");
        claims.remove("exp");
        claims.remove("jti");

        return TokenValidationResult.valid(subject, jti, claims);
    }

    public void revokeToken(String jti) {
        revokedTokens.put(jti, Instant.now());
        tokenStore.remove(jti);
    }

    public void revokeAllUserTokens(String subject) {
        List<String> tokens = userTokens.remove(subject);
        if (tokens != null) {
            for (String jti : tokens) {
                revokedTokens.put(jti, Instant.now());
                tokenStore.remove(jti);
            }
        }
    }

    public int getActiveTokenCount() {
        return tokenStore.size();
    }

    public int getRevokedTokenCount() {
        return revokedTokens.size();
    }

    public void cleanupExpired() {
        Instant now = Instant.now();
        tokenStore.entrySet().removeIf(e -> e.getValue().expiresAt.isBefore(now));
        revokedTokens.entrySet().removeIf(e -> e.getValue().plusSeconds(DEFAULT_TTL_SECONDS * 2).isBefore(now));
    }

    private String generateJti() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 failed", e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private Map<String, String> parsePayload(String payload) {
        Map<String, String> map = new LinkedHashMap<>();
        for (String pair : payload.split("&")) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                map.put(pair.substring(0, idx), pair.substring(idx + 1));
            }
        }
        return map;
    }

    public static class TokenEntry {
        public final String subject;
        public final String jti;
        public final Instant issuedAt;
        public final Instant expiresAt;
        public final Map<String, Object> claims;

        TokenEntry(String subject, String jti, Instant issuedAt, Instant expiresAt, Map<String, Object> claims) {
            this.subject = subject;
            this.jti = jti;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.claims = claims != null ? new HashMap<>(claims) : new HashMap<>();
        }
    }

    public static class TokenValidationResult {
        private final boolean valid;
        private final String reason;
        private final String subject;
        private final String jti;
        private final Map<String, Object> claims;

        private TokenValidationResult(boolean valid, String reason, String subject, String jti, Map<String, Object> claims) {
            this.valid = valid;
            this.reason = reason;
            this.subject = subject;
            this.jti = jti;
            this.claims = claims;
        }

        public static TokenValidationResult valid(String subject, String jti, Map<String, Object> claims) {
            return new TokenValidationResult(true, null, subject, jti, claims);
        }

        public static TokenValidationResult invalid(String reason) {
            return new TokenValidationResult(false, reason, null, null, null);
        }

        public boolean isValid() { return valid; }
        public String getReason() { return reason; }
        public String getSubject() { return subject; }
        public String getJti() { return jti; }
        public Map<String, Object> getClaims() { return claims; }
    }
}
