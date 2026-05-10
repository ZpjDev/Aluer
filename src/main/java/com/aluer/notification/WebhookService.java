package com.aluer.notification;

import com.aluer.model.AlertEvent;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

@Service
public class WebhookService {
    private static final Logger logger = LoggerFactory.getLogger(WebhookService.class);
    private final Gson gson = new Gson();

    @Value("${serverguard.webhook.discord-url:}")
    private String discordWebhookUrl;

    @Value("${serverguard.webhook.slack-url:}")
    private String slackWebhookUrl;

    @Value("${serverguard.webhook.enabled:false}")
    private boolean enabled;

    public CompletableFuture<Boolean> sendDiscordAlert(AlertEvent alert) {
        if (!enabled || discordWebhookUrl.isEmpty()) {
            return CompletableFuture.completedFuture(false);
        }

        return CompletableFuture.supplyAsync(() -> {
            try {
                JsonObject embed = new JsonObject();
                embed.addProperty("title", alert.getType().getTitle());
                embed.addProperty("description", alert.getMessage());
                embed.addProperty("color", alert.getConfidence() > 0.8 ? 0xFF0000 :
                    alert.getConfidence() > 0.5 ? 0xFFA500 : 0xFFFF00);

                JsonObject footer = new JsonObject();
                footer.addProperty("text", "Aluer ServerGuard | " + alert.getType().name());
                embed.add("footer", footer);

                JsonObject payload = new JsonObject();
                com.google.gson.JsonArray embeds = new com.google.gson.JsonArray();
                embeds.add(embed);
                payload.add("embeds", embeds);

                sendWebhook(discordWebhookUrl, payload);
                logger.debug("Discord webhook sent for alert: {}", alert.getType());
                return true;
            } catch (Exception e) {
                logger.error("Discord webhook failed: {}", e.getMessage());
                return false;
            }
        });
    }

    public CompletableFuture<Boolean> sendCustomMessage(String title, String message, String level) {
        if (!enabled) {
            return CompletableFuture.completedFuture(false);
        }

        return CompletableFuture.supplyAsync(() -> {
            int color = "critical".equals(level) ? 0xFF0000 :
                "warning".equals(level) ? 0xFFA500 : 0x00FF00;

            JsonObject embed = new JsonObject();
            embed.addProperty("title", title);
            embed.addProperty("description", message);
            embed.addProperty("color", color);

            JsonObject payload = new JsonObject();
            com.google.gson.JsonArray embeds = new com.google.gson.JsonArray();
            embeds.add(embed);
            payload.add("embeds", embeds);

            boolean sent = false;
            if (!discordWebhookUrl.isEmpty()) {
                sent = sendWebhook(discordWebhookUrl, payload);
            }
            if (!slackWebhookUrl.isEmpty()) {
                JsonObject slackPayload = new JsonObject();
                slackPayload.addProperty("text", "*" + title + "*\n" + message);
                sent |= sendWebhook(slackWebhookUrl, slackPayload);
            }
            return sent;
        });
    }

    private boolean sendWebhook(String webhookUrl, JsonObject payload) {
        try {
            URL url = URI.create(webhookUrl).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setDoOutput(true);

            byte[] body = gson.toJson(payload).getBytes(StandardCharsets.UTF_8);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }

            int status = conn.getResponseCode();
            return status >= 200 && status < 300;
        } catch (Exception e) {
            logger.debug("Webhook send failed: {}", e.getMessage());
            return false;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }
}
