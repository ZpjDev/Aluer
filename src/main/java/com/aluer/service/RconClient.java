package com.aluer.service;

import com.aluer.config.ServerGuardConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class RconClient {
    private static final Logger logger = LoggerFactory.getLogger(RconClient.class);
    
    private static final int RCON_PACKET_ID = 42;
    private static final int RCON_AUTH = 3;
    private static final int RCON_EXEC_COMMAND = 2;
    private static final int RCON_RESPONSE = 0;
    
    private final ServerGuardConfig config;
    private java.nio.channels.SocketChannel channel;
    private boolean authenticated = false;
    
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    public RconClient(ServerGuardConfig config) {
        this.config = config;
    }

    public boolean connect() {
        if (!config.getMinecraft().getRcon().isEnabled()) {
            logger.debug("RCON is disabled");
            return false;
        }
        
        try {
            if (channel != null && channel.isOpen()) {
                return authenticated;
            }
            
            ServerGuardConfig.RconConfig rcon = config.getMinecraft().getRcon();
            channel = java.nio.channels.SocketChannel.open();
            channel.socket().connect(new InetSocketAddress(rcon.getHost(), rcon.getPort()), 5000);
            channel.socket().setSoTimeout(5000);
            
            String password = rcon.getPassword();
            if (password == null || password.isEmpty()) {
                logger.warn("RCON password not configured");
                return false;
            }
            
            boolean auth = sendAuth(password);
            if (auth) {
                authenticated = true;
                logger.info("RCON connected successfully");
                return true;
            } else {
                logger.error("RCON authentication failed");
                close();
                return false;
            }
            
        } catch (IOException e) {
            logger.error("RCON connection failed: {}", e.getMessage());
            close();
            return false;
        }
    }

    private boolean sendAuth(String password) throws IOException {
        sendPacket(RCON_AUTH, password);
        ByteBuffer response = readPacket();
        if (response != null) {
            int id = response.getInt(4);
            return id == RCON_PACKET_ID;
        }
        return false;
    }

    public String executeCommand(String command) {
        if (!connect()) {
            logger.warn("RCON not connected, attempting fallback to system command");
            return executeSystemCommand(command);
        }
        
        try {
            sendPacket(RCON_EXEC_COMMAND, command);
            ByteBuffer response = readPacket();
            
            if (response != null) {
                String result = extractString(response);
                logger.debug("RCON command '{}' -> {}", command, result);
                return result;
            }
        } catch (IOException e) {
            logger.error("RCON command failed: {}", e.getMessage());
            authenticated = false;
            return executeSystemCommand(command);
        }
        
        return executeSystemCommand(command);
    }

    private String executeSystemCommand(String command) {
        try {
            ProcessBuilder pb;
            if (command.startsWith("ban-ip") || command.startsWith("pardon-ip")) {
                pb = new ProcessBuilder("sudo", "rcon-cli", command);
            } else {
                pb = new ProcessBuilder("rcon-cli", command);
            }
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String result = new String(p.getInputStream().readAllBytes());
            p.waitFor(5, TimeUnit.SECONDS);
            return result.trim();
        } catch (Exception e) {
            logger.error("System command failed: {}", e.getMessage());
            return "FAILED: " + e.getMessage();
        }
    }

    public boolean banIp(String ip) {
        logger.info("Auto-ban IP: {}", ip);
        String result = executeCommand("ban-ip " + ip);
        return result != null && !result.contains("Unknown");
    }

    public boolean banPlayer(String playerName) {
        logger.info("Auto-ban player: {}", playerName);
        String result = executeCommand("ban " + playerName);
        return result != null && !result.contains("Unknown");
    }

    public boolean kickPlayer(String playerName, String reason) {
        logger.info("Kick player: {} - {}", playerName, reason);
        String result = executeCommand("kick " + playerName + " " + reason);
        return result != null;
    }

    public boolean killAllMobs() {
        logger.info("Kill all mobs");
        String result = executeCommand("kill @e[type=!player]");
        return result != null;
    }

    public boolean clearLag() {
        logger.info("Clear lag (removing entities)");
        executeCommand("kill @e[type=item]");
        executeCommand("kill @e[type=experience_orb]");
        executeCommand("kill @e[type=!player]");
        return true;
    }

    public boolean setSpawnRate(int rate) {
        logger.info("Set spawn rate to: {}", rate);
        executeCommand("spawner set spawnrate " + rate);
        return true;
    }

    public boolean enableWhitelist() {
        logger.info("Enable whitelist");
        return executeCommand("whitelist on") != null;
    }

    public boolean disableWhitelist() {
        logger.info("Disable whitelist");
        return executeCommand("whitelist off") != null;
    }

    public boolean restartServer() {
        logger.warn("Triggering server restart via systemctl");
        try {
            ProcessBuilder pb = new ProcessBuilder("sudo", "systemctl", "restart", config.getMinecraft().getServiceName());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(30, TimeUnit.SECONDS);
            return p.exitValue() == 0;
        } catch (Exception e) {
            logger.error("Server restart failed: {}", e.getMessage());
            return false;
        }
    }

    public boolean setWorldBorder(int size) {
        logger.info("Set world border to: {}", size);
        String result = executeCommand("worldborder set " + size);
        return result != null;
    }

    public boolean stopServer() {
        logger.warn("Stopping server");
        return executeCommand("stop") != null;
    }

    public String getOnlinePlayers() {
        return executeCommand("list");
    }

    public String getTps() {
        return executeCommand("tps");
    }

    public String getMemory() {
        return executeCommand("memory");
    }

    public String extractIpFromMessage(String message) {
        if (message == null) return null;
        Matcher matcher = IP_PATTERN.matcher(message);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }

    private void sendPacket(int type, String payload) throws IOException {
        byte[] payloadBytes = payload.getBytes("UTF-8");
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + payloadBytes.length + 2);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(4 + payloadBytes.length + 2);
        buffer.putInt(RCON_PACKET_ID);
        buffer.putInt(type);
        buffer.put(payloadBytes);
        buffer.put((byte) 0);
        buffer.flip();
        channel.write(buffer);
    }

    private ByteBuffer readPacket() throws IOException {
        ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
        sizeBuffer.order(ByteOrder.LITTLE_ENDIAN);
        
        int read = channel.read(sizeBuffer);
        if (read < 4) return null;
        
        sizeBuffer.flip();
        int size = sizeBuffer.getInt();
        
        ByteBuffer packet = ByteBuffer.allocate(size);
        packet.order(ByteOrder.LITTLE_ENDIAN);
        
        while (packet.hasRemaining()) {
            int r = channel.read(packet);
            if (r < 0) break;
        }
        
        packet.flip();
        return packet;
    }

    private String extractString(ByteBuffer buffer) {
        byte[] bytes = new byte[buffer.remaining() - 12];
        buffer.position(12);
        buffer.get(bytes);
        
        int nullIndex = 0;
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == 0) {
                nullIndex = i;
                break;
            }
        }
        
        return new String(bytes, 0, nullIndex, java.nio.charset.StandardCharsets.UTF_8).trim();
    }

    public void close() {
        try {
            if (channel != null && channel.isOpen()) {
                channel.close();
            }
        } catch (IOException e) {
            logger.debug("Error closing RCON: {}", e.getMessage());
        }
        authenticated = false;
    }

    public boolean isConnected() {
        return channel != null && channel.isOpen() && authenticated;
    }
}
