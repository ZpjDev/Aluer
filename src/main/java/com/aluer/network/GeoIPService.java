package com.aluer.network;

import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.*;

@Service
public class GeoIPService {

    private final Map<String, GeoLocation> geoCache = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> countryIPs = new ConcurrentHashMap<>();
    private final Set<String> allowedCountries = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedCountries = ConcurrentHashMap.newKeySet();
    private final Queue<GeoEvent> events = new ConcurrentLinkedQueue<>();

    private static final long CACHE_DURATION = 86400000;

    public GeoIPService() {
        initializeDefaultCountries();
    }

    private void initializeDefaultCountries() {
        allowedCountries.add("CN");
        allowedCountries.add("US");
        allowedCountries.add("JP");
        allowedCountries.add("KR");
        allowedCountries.add("SG");
    }

    public boolean checkCountry(String ip, String countryCode) {
        if (blockedCountries.contains(countryCode)) {
            logEvent(ip, countryCode, "BLOCKED");
            return false;
        }

        if (!allowedCountries.isEmpty() && !allowedCountries.contains(countryCode)) {
            logEvent(ip, countryCode, "NOT_ALLOWED");
            return false;
        }

        return true;
    }

    public void setGeoLocation(String ip, String country, String city, double lat, double lon) {
        GeoLocation geo = new GeoLocation(ip, country, city, lat, lon, System.currentTimeMillis());
        geoCache.put(ip, geo);

        countryIPs.computeIfAbsent(country, k -> ConcurrentHashMap.newKeySet()).add(ip);
    }

    public GeoLocation getGeoLocation(String ip) {
        return geoCache.get(ip);
    }

    public void addAllowedCountry(String country) {
        allowedCountries.add(country);
    }

    public void removeAllowedCountry(String country) {
        allowedCountries.remove(country);
    }

    public void addBlockedCountry(String country) {
        blockedCountries.add(country);
    }

    public void removeBlockedCountry(String country) {
        blockedCountries.remove(country);
    }

    public Set<String> getAllowedCountries() {
        return new HashSet<>(allowedCountries);
    }

    public Set<String> getBlockedCountries() {
        return new HashSet<>(blockedCountries);
    }

    private void logEvent(String ip, String country, String status) {
        events.offer(new GeoEvent(ip, country, status, System.currentTimeMillis()));
    }

    public List<GeoEvent> getRecentEvents(int limit) {
        List<GeoEvent> result = new ArrayList<>();
        int count = 0;
        for (GeoEvent event : events) {
            if (count++ >= limit) break;
            result.add(event);
        }
        return result;
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("cachedLocations", geoCache.size());
        stats.put("allowedCountries", allowedCountries.size());
        stats.put("blockedCountries", blockedCountries.size());
        return stats;
    }

    public static class GeoLocation {
        public final String ip;
        public final String country;
        public final String city;
        public final double latitude;
        public final double longitude;
        public final long timestamp;

        public GeoLocation(String ip, String country, String city, double lat, double lon, long timestamp) {
            this.ip = ip;
            this.country = country;
            this.city = city;
            this.latitude = lat;
            this.longitude = lon;
            this.timestamp = timestamp;
        }
    }

    public static class GeoEvent {
        public final String ip;
        public final String country;
        public final String status;
        public final long timestamp;

        public GeoEvent(String ip, String country, String status, long timestamp) {
            this.ip = ip;
            this.country = country;
            this.status = status;
            this.timestamp = timestamp;
        }
    }
}
