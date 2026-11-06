package com.coolauth.managers;

import com.coolauth.CoolAuth;
import com.coolauth.storage.AuthStorage;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RecoveryManager {

    private final CoolAuth plugin;
    private final AuthStorage storage;

    private final Map<String, RecoveryRequest> activeRequests = new ConcurrentHashMap<>();
    private final Map<UUID, Long> cooldowns = new ConcurrentHashMap<>();
    private final Set<UUID> approvedRecoveries = ConcurrentHashMap.newKeySet();

    private final File dataFile;
    private FileConfiguration dataConfig;

    private final int cooldownSeconds;
    private final int codeExpirySeconds;
    private final String webhookUrl;
    private final String embedColor;
    private final String embedTitle;

    public record RecoveryRequest(
            UUID uuid,
            String playerName,
            String ip,
            String reason,
            String details,
            long timestamp,
            long expiry
    ) {}

    public RecoveryManager(CoolAuth plugin, AuthStorage storage) {
        this.plugin = plugin;
        this.storage = storage;

        this.cooldownSeconds = plugin.getConfig().getInt("recovery.cooldown", 3600);
        this.codeExpirySeconds = plugin.getConfig().getInt("recovery.code_expiry", 86400);
        this.webhookUrl = plugin.getConfig().getString("recovery.discord_webhook", "");
        this.embedColor = plugin.getConfig().getString("recovery.embed_color", "#3498db");
        this.embedTitle = plugin.getConfig().getString("recovery.embed_title", "🔐 Password Recovery Request");

        this.dataFile = new File(plugin.getDataFolder(), "recovery_data.yml");
        loadRecoveryData();

        // Cleanup expired requests periodically
        Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, this::cleanupExpiredRequests, 20 * 60, 20 * 60 * 5);
    }

    private void loadRecoveryData() {
        if (!dataFile.exists()) {
            try {
                dataFile.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        dataConfig = YamlConfiguration.loadConfiguration(dataFile);

        // Load active requests
        if (dataConfig.contains("requests")) {
            for (String code : dataConfig.getConfigurationSection("requests").getKeys(false)) {
                String path = "requests." + code;
                UUID uuid = UUID.fromString(dataConfig.getString(path + ".uuid"));
                String playerName = dataConfig.getString(path + ".player_name");
                String ip = dataConfig.getString(path + ".ip");
                String reason = dataConfig.getString(path + ".reason");
                String details = dataConfig.getString(path + ".details");
                long timestamp = dataConfig.getLong(path + ".timestamp");
                long expiry = dataConfig.getLong(path + ".expiry");

                if (System.currentTimeMillis() < expiry) {
                    activeRequests.put(code, new RecoveryRequest(uuid, playerName, ip, reason, details, timestamp, expiry));
                }
            }
        }

        // Load approved recoveries
        if (dataConfig.contains("approved")) {
            for (String uuidStr : dataConfig.getStringList("approved")) {
                approvedRecoveries.add(UUID.fromString(uuidStr));
            }
        }

        plugin.getLogger().info("Loaded " + activeRequests.size() + " pending recovery requests.");
    }

    public void saveRecoveryData() {
        dataConfig.set("requests", null);
        for (Map.Entry<String, RecoveryRequest> entry : activeRequests.entrySet()) {
            String code = entry.getKey();
            RecoveryRequest req = entry.getValue();
            String path = "requests." + code;
            dataConfig.set(path + ".uuid", req.uuid.toString());
            dataConfig.set(path + ".player_name", req.playerName);
            dataConfig.set(path + ".ip", req.ip);
            dataConfig.set(path + ".reason", req.reason);
            dataConfig.set(path + ".details", req.details);
            dataConfig.set(path + ".timestamp", req.timestamp);
            dataConfig.set(path + ".expiry", req.expiry);
        }

        List<String> approvedList = new ArrayList<>();
        for (UUID uuid : approvedRecoveries) {
            approvedList.add(uuid.toString());
        }
        dataConfig.set("approved", approvedList);

        try {
            dataConfig.save(dataFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public long getCooldownRemaining(UUID uuid) {
        if (!cooldowns.containsKey(uuid)) return 0;
        long remaining = (cooldowns.get(uuid) - System.currentTimeMillis()) / 1000;
        return Math.max(0, remaining);
    }

    public void submitRequest(Player player, String reason, String details) {
        String code = generateCode();
        long now = System.currentTimeMillis();
        long expiry = now + (codeExpirySeconds * 1000L);

        String ip = player.getAddress().getAddress().getHostAddress();
        RecoveryRequest request = new RecoveryRequest(
                player.getUniqueId(),
                player.getName(),
                ip,
                reason,
                details,
                now,
                expiry
        );

        activeRequests.put(code, request);
        cooldowns.put(player.getUniqueId(), now + (cooldownSeconds * 1000L));

        saveRecoveryData();

        // Send webhook
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> sendWebhook(code, request));

        player.sendMessage(plugin.color(plugin.getPrefix() +
                plugin.getMessage("recovery_submitted").replace("%code%", code)));
    }

    private String generateCode() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder code = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < 8; i++) {
            code.append(chars.charAt(random.nextInt(chars.length())));
        }

        if (activeRequests.containsKey(code.toString())) {
            return generateCode();
        }

        return code.toString();
    }

    private void sendWebhook(String code, RecoveryRequest request) {
        if (webhookUrl.isEmpty() || webhookUrl.equals("https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE")) {
            plugin.getLogger().warning("Discord webhook not configured! Recovery request saved locally.");
            return;
        }

        try {
            URL url = new URL(webhookUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String timestamp = sdf.format(new Date(request.timestamp));
            String expiryStr = sdf.format(new Date(request.expiry));

            int colorDecimal = Integer.parseInt(embedColor.replace("#", ""), 16);

            String json = """
                {
                    "embeds": [{
                        "title": "%s",
                        "color": %d,
                        "fields": [
                            {"name": "📋 Code", "value": "`%s`", "inline": true},
                            {"name": "👤 Player", "value": "%s", "inline": true},
                            {"name": "🔑 UUID", "value": "`%s`", "inline": false},
                            {"name": "🌐 IP Address", "value": "||%s||", "inline": true},
                            {"name": "📝 Reason", "value": "%s", "inline": false},
                            {"name": "💬 Details", "value": "%s", "inline": false},
                            {"name": "⏰ Requested", "value": "%s", "inline": true},
                            {"name": "⏳ Expires", "value": "%s", "inline": true}
                        ],
                        "footer": {"text": "Use /coolauth approve %s or /coolauth deny %s"}
                    }]
                }
                """.formatted(
                    embedTitle,
                    colorDecimal,
                    code,
                    escapeJson(request.playerName),
                    request.uuid.toString(),
                    request.ip,
                    escapeJson(request.reason),
                    escapeJson(request.details),
                    timestamp,
                    expiryStr,
                    code,
                    code
            );

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = conn.getResponseCode();
            if (responseCode != 200 && responseCode != 204) {
                plugin.getLogger().warning("Failed to send webhook. Response code: " + responseCode);
            }

            conn.disconnect();
        } catch (Exception e) {
            plugin.getLogger().warning("Failed to send recovery webhook: " + e.getMessage());
        }
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    public RecoveryRequest getRequest(String code) {
        return activeRequests.get(code);
    }

    public List<String> getActiveRecoveryCodes() {
        return new ArrayList<>(activeRequests.keySet());
    }

    public void approveRequest(String code) {
        RecoveryRequest request = activeRequests.remove(code);
        if (request == null) return;

        storage.removeUser(request.uuid);
        plugin.getAuthManager().removeSession(request.uuid);
        approvedRecoveries.add(request.uuid);

        Player player = Bukkit.getPlayer(request.uuid);
        if (player != null && player.isOnline()) {
            approvedRecoveries.remove(request.uuid);
            plugin.getAuthManager().setAuthenticated(request.uuid, false);
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("recovery_approved")));
        }

        saveRecoveryData();
    }

    public void denyRequest(String code) {
        RecoveryRequest request = activeRequests.remove(code);
        if (request == null) return;

        Player player = Bukkit.getPlayer(request.uuid);
        if (player != null && player.isOnline()) {
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("recovery_denied")));
        }

        saveRecoveryData();
    }

    public boolean hasApprovedRecovery(UUID uuid) {
        return approvedRecoveries.contains(uuid);
    }

    public void clearApprovedRecovery(UUID uuid) {
        approvedRecoveries.remove(uuid);
        saveRecoveryData();
    }

    private void cleanupExpiredRequests() {
        long now = System.currentTimeMillis();
        activeRequests.entrySet().removeIf(entry -> now > entry.getValue().expiry);
        cooldowns.entrySet().removeIf(entry -> now > entry.getValue());
        saveRecoveryData();
    }
  }
