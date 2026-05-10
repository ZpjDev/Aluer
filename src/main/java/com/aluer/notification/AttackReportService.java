package com.aluer.notification;

import com.aluer.model.AlertEvent;
import com.aluer.model.MetricsData;
import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;

@Service
public class AttackReportService {
    private static final Logger logger = LoggerFactory.getLogger(AttackReportService.class);
    private final Gson gson = new Gson();
    private final ConcurrentLinkedDeque<Map<String, Object>> recentAttacks = new ConcurrentLinkedDeque<>();

    @Value("${serverguard.report.dir:./reports}")
    private String reportDir;

    public void recordAttack(AlertEvent alert, String sourceIp, String details) {
        Map<String, Object> record = new java.util.LinkedHashMap<>();
        record.put("timestamp", System.currentTimeMillis());
        record.put("type", alert.getType().name());
        record.put("sourceIp", sourceIp);
        record.put("confidence", alert.getConfidence());
        record.put("message", alert.getMessage());
        record.put("details", details);
        recentAttacks.addFirst(record);
        while (recentAttacks.size() > 500) {
            recentAttacks.pollLast();
        }
    }

    public List<Map<String, Object>> getRecentAttacks(int limit) {
        List<Map<String, Object>> result = new ArrayList<>();
        int count = 0;
        for (Map<String, Object> attack : recentAttacks) {
            if (count++ >= limit) break;
            result.add(attack);
        }
        return result;
    }

    public String generateHtmlReport() {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html lang=\"zh-CN\"><head>");
        html.append("<meta charset=\"UTF-8\">");
        html.append("<title>Aluer ServerGuard Attack Report</title>");
        html.append("<style>");
        html.append("body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a1628;color:#e2e8f0;padding:24px;}");
        html.append("h1{color:#63e7c2;border-bottom:2px solid #1a365d;padding-bottom:12px;}");
        html.append("table{width:100%;border-collapse:collapse;margin-top:16px;}");
        html.append("th{background:#1a365d;padding:12px;text-align:left;}");
        html.append("td{padding:10px 12px;border-bottom:1px solid #1e3a5f;}");
        html.append(".critical{color:#ff7f96;}.high{color:#ffc86b;}.medium{color:#60cbff;}");
        html.append(".timestamp{color:#8fa7c2;font-size:0.85em;}");
        html.append("</style></head><body>");
        html.append("<h1>Aluer ServerGuard — Attack Report</h1>");
        html.append("<p class=\"timestamp\">Generated: ").append(formatTimestamp(System.currentTimeMillis())).append("</p>");

        html.append("<table><thead><tr>");
        html.append("<th>Time</th><th>Type</th><th>Source IP</th><th>Confidence</th><th>Message</th>");
        html.append("</tr></thead><tbody>");

        for (Map<String, Object> attack : recentAttacks) {
            double confidence = toDouble(attack.get("confidence"));
            String cssClass = confidence > 0.8 ? "critical" : confidence > 0.5 ? "high" : "medium";
            html.append("<tr class=\"").append(cssClass).append("\">");
            html.append("<td>").append(formatTimestamp(toLong(attack.get("timestamp")))).append("</td>");
            html.append("<td>").append(attack.get("type")).append("</td>");
            html.append("<td>").append(attack.get("sourceIp")).append("</td>");
            html.append("<td>").append(String.format("%.0f%%", confidence * 100)).append("</td>");
            html.append("<td>").append(attack.get("message")).append("</td>");
            html.append("</tr>");
        }
        html.append("</tbody></table></body></html>");
        return html.toString();
    }

    public File saveHtmlReport() throws IOException {
        Files.createDirectories(Path.of(reportDir));
        String filename = "attack-report-" + DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
            .withZone(ZoneId.systemDefault()).format(Instant.now()) + ".html";
        File file = new File(reportDir, filename);
        try (FileWriter writer = new FileWriter(file, StandardCharsets.UTF_8)) {
            writer.write(generateHtmlReport());
        }
        logger.info("Attack report saved: {}", file.getAbsolutePath());
        return file;
    }

    private String formatTimestamp(long millis) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault())
            .format(Instant.ofEpochMilli(millis));
    }

    private double toDouble(Object value) {
        if (value instanceof Number n) return n.doubleValue();
        return 0.0;
    }

    private long toLong(Object value) {
        if (value instanceof Number n) return n.longValue();
        return 0L;
    }
}
