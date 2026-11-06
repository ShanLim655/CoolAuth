package com.coolauth.managers;

import com.coolauth.CoolAuth;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitRunnable;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class AuthManager {

    private final CoolAuth plugin;

    private final Set<UUID> authenticatedPlayers = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Integer> timeoutTasks = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> loginAttempts = new ConcurrentHashMap<>();
    private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();
    private final File sessionsFile;
    private final FileConfiguration sessionsConfig;

    // Recovery chat input
    private final Set<UUID> awaitingRecoveryInput = ConcurrentHashMap.newKeySet();
    private final Map<UUID, String> pendingRecoveryReason = new ConcurrentHashMap<>();

    private final int timeoutSeconds;
    private final int maxAttempts;
    private final int sessionMinutes;

    public record Session(String ip, String username, long expiryTime) {}

    public AuthManager(CoolAuth plugin) {
        this.plugin = plugin;
        this.timeoutSeconds = plugin.getConfig().getInt("security.auth_timeout", 30);
        this.maxAttempts = plugin.getConfig().getInt("security.max_login_attempts", 3);
        int configuredSessionMinutes = plugin.getConfig().getInt("security.session_timeout", 240);
        // 220 was the bundled default before the four-hour session feature.
        if (configuredSessionMinutes == 220) {
            configuredSessionMinutes = 240;
            plugin.getConfig().set("security.session_timeout", configuredSessionMinutes);
            plugin.saveConfig();
        }
        this.sessionMinutes = Math.max(0, configuredSessionMinutes);
        this.sessionsFile = new File(plugin.getDataFolder(), "sessions.yml");
        this.sessionsConfig = YamlConfiguration.loadConfiguration(sessionsFile);
        loadSessions();
        new BukkitRunnable() {
            @Override public void run() { expireSessions(); }
        }.runTaskTimer(plugin, 20L * 60L, 20L * 60L);
    }

    private void loadSessions() {
        long now = System.currentTimeMillis();
        for (String key : sessionsConfig.getKeys(false)) {
            try {
                UUID uuid = UUID.fromString(key);
                String ip = sessionsConfig.getString(key + ".ip");
                String username = sessionsConfig.getString(key + ".username");
                long expiry = sessionsConfig.getLong(key + ".expires", 0L);
                if (ip != null && username != null && expiry > now) {
                    sessions.put(uuid, new Session(ip, username, expiry));
                } else {
                    sessionsConfig.set(key, null);
                }
            } catch (IllegalArgumentException ignored) {
                sessionsConfig.set(key, null);
            }
        }
        saveSessions();
    }

    private void saveSessions() {
        try {
            sessionsConfig.save(sessionsFile);
        } catch (IOException e) {
            plugin.getLogger().severe("Unable to save authentication sessions: " + e.getMessage());
        }
    }

    private void expireSessions() {
        long now = System.currentTimeMillis();
        boolean changed = sessions.entrySet().removeIf(entry -> entry.getValue().expiryTime() <= now);
        if (changed) {
            for (String key : sessionsConfig.getKeys(false)) {
                try {
                    if (!sessions.containsKey(UUID.fromString(key))) sessionsConfig.set(key, null);
                } catch (IllegalArgumentException ignored) {
                    sessionsConfig.set(key, null);
                }
            }
            saveSessions();
        }
    }

    // --- Authentication State ---

    public boolean isAuthenticated(UUID uuid) {
        return authenticatedPlayers.contains(uuid);
    }

    public boolean isAuthenticated(Player player) {
        return isAuthenticated(player.getUniqueId());
    }

    public void setAuthenticated(UUID uuid, boolean authenticated) {
        if (authenticated) {
            authenticatedPlayers.add(uuid);
        } else {
            authenticatedPlayers.remove(uuid);
        }
    }

    // --- Login Attempts ---

    public int incrementLoginAttempts(UUID uuid) {
        int attempts = loginAttempts.getOrDefault(uuid, 0) + 1;
        loginAttempts.put(uuid, attempts);
        return attempts;
    }

    public void resetLoginAttempts(UUID uuid) {
        loginAttempts.remove(uuid);
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    // --- Sessions ---

    public boolean hasValidSession(Player player) {
        UUID uuid = player.getUniqueId();
        if (!sessions.containsKey(uuid)) return false;

        Session session = sessions.get(uuid);
        String currentIp = player.getAddress().getAddress().getHostAddress();

        if (System.currentTimeMillis() < session.expiryTime()
                && session.ip().equals(currentIp)
                && session.username().equals(player.getName())) {
            return true;
        }

        removeSession(uuid);
        return false;
    }

    public void createSession(Player player) {
        if (sessionMinutes <= 0) return;

        long expiry = System.currentTimeMillis() + (sessionMinutes * 60_000L);
        String ip = player.getAddress().getAddress().getHostAddress();
        UUID uuid = player.getUniqueId();
        Session session = new Session(ip, player.getName(), expiry);
        sessions.put(uuid, session);
        sessionsConfig.set(uuid + ".ip", ip);
        sessionsConfig.set(uuid + ".username", player.getName());
        sessionsConfig.set(uuid + ".expires", expiry);
        saveSessions();
    }

    public void removeSession(UUID uuid) {
        Runnable revoke = () -> {
            sessions.remove(uuid);
            sessionsConfig.set(uuid.toString(), null);
            saveSessions();
        };
        if (Bukkit.isPrimaryThread()) revoke.run();
        else Bukkit.getScheduler().runTask(plugin, revoke);
    }

    // --- Timeout Tasks ---

    public void startTimeoutTask(Player player) {
        UUID uuid = player.getUniqueId();

        int taskId = new BukkitRunnable() {
            @Override
            public void run() {
                if (player.isOnline() && !isAuthenticated(uuid)) {
                    player.kickPlayer(plugin.color(plugin.getMessage("kick_timeout")));
                }
                timeoutTasks.remove(uuid);
            }
        }.runTaskLater(plugin, timeoutSeconds * 20L).getTaskId();

        timeoutTasks.put(uuid, taskId);
    }

    public void cancelTimeoutTask(UUID uuid) {
        if (timeoutTasks.containsKey(uuid)) {
            Bukkit.getScheduler().cancelTask(timeoutTasks.remove(uuid));
        }
    }

    // --- Finish Authentication ---

    public void finishAuth(Player player, boolean sessionResumed) {
        Bukkit.getScheduler().runTask(plugin, () -> {
            UUID uuid = player.getUniqueId();

            authenticatedPlayers.add(uuid);
            resetLoginAttempts(uuid);
            cancelTimeoutTask(uuid);

            player.removePotionEffect(PotionEffectType.BLINDNESS);
            player.resetTitle();

            // A restored session keeps its original expiry; reconnecting must not
            // extend the four-hour trust window indefinitely.
            if (!sessionResumed) createSession(player);

            if (sessionResumed) {
                player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("session_restored")));
            } else {
                Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> plugin.getStorage().updatePlayerInfo(player));
                player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("success")));
            }
        });
    }

    // --- Recovery Input ---

    public boolean isAwaitingRecoveryInput(UUID uuid) {
        return awaitingRecoveryInput.contains(uuid);
    }

    public void setAwaitingRecoveryInput(UUID uuid, boolean awaiting) {
        if (awaiting) {
            awaitingRecoveryInput.add(uuid);
        } else {
            awaitingRecoveryInput.remove(uuid);
        }
    }

    public void setPendingRecoveryReason(UUID uuid, String reason) {
        pendingRecoveryReason.put(uuid, reason);
    }

    public String getPendingRecoveryReason(UUID uuid) {
        return pendingRecoveryReason.remove(uuid);
    }

    // --- Cleanup ---

    public void cleanupPlayer(UUID uuid) {
        authenticatedPlayers.remove(uuid);
        awaitingRecoveryInput.remove(uuid);
        pendingRecoveryReason.remove(uuid);
        cancelTimeoutTask(uuid);
    }

    public void shutdown() {
        timeoutTasks.values().forEach(Bukkit.getScheduler()::cancelTask);
        timeoutTasks.clear();
        saveSessions();
    }
}
