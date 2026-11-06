package com.coolauth.listeners;

import com.coolauth.CoolAuth;
import com.coolauth.managers.AuthManager;
import com.coolauth.managers.PasswordValidator;
import com.coolauth.managers.RecoveryManager;
import net.md_5.bungee.api.ChatMessageType;
import net.md_5.bungee.api.chat.TextComponent;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitRunnable;

import java.util.List;
import java.util.UUID;

public class AuthListener implements Listener {

    private final CoolAuth plugin;
    private final AuthManager authManager;
    private final RecoveryManager recoveryManager;

    public AuthListener(CoolAuth plugin) {
        this.plugin = plugin;
        this.authManager = plugin.getAuthManager();
        this.recoveryManager = plugin.getRecoveryManager();
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        String ip = player.getAddress().getAddress().getHostAddress();
        UUID uuid = player.getUniqueId();

        // Check banned IP
        if (plugin.getBannedIps().contains(ip)) {
            player.kickPlayer(plugin.color(plugin.getMessage("kick_banned")));
            return;
        }

        // Check for approved recovery
        if (recoveryManager.hasApprovedRecovery(uuid)) {
            recoveryManager.clearApprovedRecovery(uuid);
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("recovery_approved")));
        }

        // Check session
        if (authManager.hasValidSession(player)) {
            authManager.finishAuth(player, true);
            return;
        }

        // Clear auth state
        authManager.setAuthenticated(uuid, false);

        // Apply blindness
        player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, Integer.MAX_VALUE, 255, false, false));

        // Check if registered (async)
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            boolean isRegistered = plugin.getStorage().isRegistered(uuid);
            
            // Run on main thread for player interactions
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (!player.isOnline()) return;
                
                if (isRegistered) {
                    showLoginScreen(player);
                } else {
                    showRegisterScreen(player);
                }
                
                // Start action bar task
                startActionBarTask(player, isRegistered);
            });
        });

        // Start timeout
        authManager.startTimeoutTask(player);
    }

    private void showRegisterScreen(Player player) {
        // Show title
        String title = plugin.getConfig().getString("join_screen.register.title", "&b&lWelcome, %player%!")
                .replace("%player%", player.getName());
        String subtitle = plugin.getConfig().getString("join_screen.register.subtitle", "&7New here? Create an account below");
        
        player.sendTitle(
                plugin.color(title),
                plugin.color(subtitle),
                10, 2000, 20
        );
        
        // Send detailed instructions in chat
        if (plugin.getConfig().getBoolean("join_screen.send_chat_instructions", true)) {
            List<String> instructions = plugin.getConfig().getStringList("messages.register_instructions");
            
            PasswordValidator validator = plugin.getPasswordValidator();
            String requirements = buildRequirementsString(validator);
            
            for (String line : instructions) {
                String formatted = line
                        .replace("%min%", String.valueOf(validator.getMinLength()))
                        .replace("%max%", String.valueOf(validator.getMaxLength()))
                        .replace("%requirements%", requirements);
                player.sendMessage(plugin.color(formatted));
            }
        }
    }

    private void showLoginScreen(Player player) {
        // Show title
        String title = plugin.getConfig().getString("join_screen.login.title", "&b&lWelcome, %player%!")
                .replace("%player%", player.getName());
        String subtitle = plugin.getConfig().getString("join_screen.login.subtitle", "&7Please login to continue");
        
        player.sendTitle(
                plugin.color(title),
                plugin.color(subtitle),
                10, 2000, 20
        );
        
        // Send detailed instructions in chat
        if (plugin.getConfig().getBoolean("join_screen.send_chat_instructions", true)) {
            List<String> instructions = plugin.getConfig().getStringList("messages.login_instructions");
            
            for (String line : instructions) {
                player.sendMessage(plugin.color(line));
            }
        }
    }

    private String buildRequirementsString(PasswordValidator validator) {
        StringBuilder sb = new StringBuilder();
        
        if (validator.isRequireUppercase()) {
            sb.append("&fUppercase (A-Z)&7, ");
        }
        if (validator.isRequireLowercase()) {
            sb.append("&fLowercase (a-z)&7, ");
        }
        if (validator.isRequireNumbers()) {
            sb.append("&fNumber (0-9)&7, ");
        }
        if (validator.isRequireSpecial()) {
            sb.append("&fSpecial char&7, ");
        }
        
        String result = sb.toString();
        if (result.endsWith(", ")) {
            result = result.substring(0, result.length() - 2);
        }
        
        return result.isEmpty() ? "&7None" : result;
    }

    private void startActionBarTask(Player player, boolean isRegistered) {
        String actionBarMessage = isRegistered 
                ? plugin.getConfig().getString("join_screen.actionbar_login", "&e/login <password>")
                : plugin.getConfig().getString("join_screen.actionbar_register", "&e/register <password> <password>");
        
        new BukkitRunnable() {
            @Override
            public void run() {
                if (!player.isOnline() || authManager.isAuthenticated(player)) {
                    cancel();
                    return;
                }
                
                player.spigot().sendMessage(
                        ChatMessageType.ACTION_BAR,
                        TextComponent.fromLegacyText(plugin.color(actionBarMessage))
                );
            }
        }.runTaskTimer(plugin, 0L, 40L); // Every 2 seconds
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        authManager.cleanupPlayer(event.getPlayer().getUniqueId());
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onChatRecovery(AsyncPlayerChatEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();

        if (!authManager.isAwaitingRecoveryInput(uuid)) return;

        event.setCancelled(true);
        String input = event.getMessage().trim();

        if (input.equalsIgnoreCase("cancel")) {
            authManager.setAwaitingRecoveryInput(uuid, false);
            authManager.setPendingRecoveryReason(uuid, null);
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("recovery_cancelled")));
            return;
        }

        String reason = authManager.getPendingRecoveryReason(uuid);
        authManager.setAwaitingRecoveryInput(uuid, false);

        recoveryManager.submitRequest(player, reason, input);
    }
                                                 }
