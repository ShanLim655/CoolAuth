package com.coolauth.commands;

import com.coolauth.CoolAuth;
import com.coolauth.managers.AuthManager;
import com.coolauth.managers.PasswordValidator;
import com.coolauth.managers.RecoveryManager;
import com.coolauth.storage.AuthStorage;
import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.util.*;
import java.util.stream.Collectors;

public class AdminCommands implements CommandExecutor, TabCompleter {

    private final CoolAuth plugin;
    private final AuthStorage storage;
    private final AuthManager authManager;
    private final PasswordValidator passwordValidator;

    public AdminCommands(CoolAuth plugin) {
        this.plugin = plugin;
        this.storage = plugin.getStorage();
        this.authManager = plugin.getAuthManager();
        this.passwordValidator = plugin.getPasswordValidator();
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!sender.hasPermission("coolauth.admin")) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cNo permission."));
            return true;
        }

        if (args.length == 0) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("admin_usage")));
            return true;
        }

        String sub = args[0].toLowerCase();

        switch (sub) {
            case "reload" -> handleReload(sender);
            case "unregister" -> handleUnregister(sender, args);
            case "setpass" -> handleSetPass(sender, args);
            case "info" -> handleInfo(sender, args);
            case "forcelogin" -> handleForceLogin(sender, args);
            case "forceregister" -> handleForceRegister(sender, args);
            case "banip" -> handleBanIp(sender, args);
            case "unbanip" -> handleUnbanIp(sender, args);
            case "approve" -> handleApprove(sender, args);
            case "deny" -> handleDeny(sender, args);
            case "lookup" -> handleLookup(sender, args);
            default -> sender.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("admin_usage")));
        }

        return true;
    }

    private void handleReload(CommandSender sender) {
        plugin.reload();
        sender.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("admin_reloaded")));
    }

    private void handleUnregister(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth unregister <player>"));
            return;
        }

        String targetName = args[1];

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            OfflinePlayer target = Bukkit.getOfflinePlayer(targetName);
            UUID targetUUID = target.getUniqueId();

            if (!storage.isRegistered(targetUUID)) {
                sender.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("admin_fail")));
                return;
            }

            storage.removeUser(targetUUID);
            authManager.removeSession(targetUUID);
            sender.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("admin_success")));

            if (target.isOnline()) {
                Bukkit.getScheduler().runTask(plugin, () -> {
                    authManager.setAuthenticated(targetUUID, false);
                    target.getPlayer().kickPlayer(plugin.color("&cYour account has been unregistered by an admin."));
                });
            }
        });
    }

    private void handleSetPass(CommandSender sender, String[] args) {
        if (args.length < 3) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth setpass <player> <newpassword>"));
            return;
        }

        String targetName = args[1];
        String newPassword = args[2];

        // Validate password
        String validationError = passwordValidator.validate(newPassword);
        if (validationError != null) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + validationError));
            return;
        }

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            OfflinePlayer target = Bukkit.getOfflinePlayer(targetName);
            UUID targetUUID = target.getUniqueId();

            if (!storage.isRegistered(targetUUID)) {
                sender.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("admin_fail")));
                return;
            }

            storage.updatePassword(targetUUID, newPassword);
            authManager.removeSession(targetUUID);
            sender.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("admin_success")));
        });
    }

    private void handleInfo(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth info <player>"));
            return;
        }

        String targetName = args[1];

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            OfflinePlayer target = Bukkit.getOfflinePlayer(targetName);
            UUID targetUUID = target.getUniqueId();

            if (!storage.isRegistered(targetUUID)) {
                sender.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("admin_fail")));
                return;
            }

            Map<String, String> info = storage.getPlayerInfo(targetUUID);

            sender.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("admin_player_info")));
            sender.sendMessage(plugin.color("&7Player: &e" + targetName));
            sender.sendMessage(plugin.color("&7UUID: &e" + targetUUID));
            sender.sendMessage(plugin.color("&7Last IP: &e" + info.getOrDefault("ip", "Unknown")));
            sender.sendMessage(plugin.color("&7Last Location: &e" + info.getOrDefault("location", "Unknown")));
            sender.sendMessage(plugin.color("&7Currently Online: &e" + (target.isOnline() ? "Yes" : "No")));
            sender.sendMessage(plugin.color("&7Authenticated: &e" + (authManager.isAuthenticated(targetUUID) ? "Yes" : "No")));
        });
    }

    private void handleForceLogin(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth forcelogin <player>"));
            return;
        }

        Player target = Bukkit.getPlayer(args[1]);
        if (target == null) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cPlayer not online."));
            return;
        }

        if (authManager.isAuthenticated(target)) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cPlayer is already logged in."));
            return;
        }

        authManager.finishAuth(target, false);
        sender.sendMessage(plugin.color(plugin.getPrefix() +
                plugin.getMessage("admin_force_login").replace("%player%", target.getName())));
    }

    private void handleForceRegister(CommandSender sender, String[] args) {
        if (args.length < 3) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth forceregister <player> <password>"));
            return;
        }

        String targetName = args[1];
        String password = args[2];

        // Validate password
        String validationError = passwordValidator.validate(password);
        if (validationError != null) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + validationError));
            return;
        }

        OfflinePlayer target = Bukkit.getOfflinePlayer(targetName);
        UUID targetUUID = target.getUniqueId();

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            if (storage.isRegistered(targetUUID)) {
                sender.sendMessage(plugin.color(plugin.getPrefix() +
                        plugin.getMessage("admin_already_registered").replace("%player%", targetName)));
                return;
            }

            if (target.isOnline()) {
                storage.savePlayer(target.getPlayer(), password);
            } else {
                storage.saveOfflinePlayer(targetUUID, targetName, password);
            }

            sender.sendMessage(plugin.color(plugin.getPrefix() +
                    plugin.getMessage("admin_force_register").replace("%player%", targetName)));
        });
    }

    private void handleBanIp(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth banip <ip>"));
            return;
        }

        String ip = args[1];
        List<String> bannedIps = plugin.getBannedIps();

        if (bannedIps.contains(ip)) {
            sender.sendMessage(plugin.color(plugin.getPrefix() +
                    plugin.getMessage("admin_ip_already_banned").replace("%ip%", ip)));
            return;
        }

        bannedIps.add(ip);
        plugin.saveBannedIps();

        sender.sendMessage(plugin.color(plugin.getPrefix() +
                plugin.getMessage("admin_ip_banned").replace("%ip%", ip)));

        // Kick players with this IP
        for (Player player : Bukkit.getOnlinePlayers()) {
            if (player.getAddress().getAddress().getHostAddress().equals(ip)) {
                player.kickPlayer(plugin.color(plugin.getMessage("kick_banned")));
            }
        }
    }

    private void handleUnbanIp(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth unbanip <ip>"));
            return;
        }

        String ip = args[1];
        List<String> bannedIps = plugin.getBannedIps();

        if (!bannedIps.contains(ip)) {
            sender.sendMessage(plugin.color(plugin.getPrefix() +
                    plugin.getMessage("admin_ip_not_banned").replace("%ip%", ip)));
            return;
        }

        bannedIps.remove(ip);
        plugin.saveBannedIps();

        sender.sendMessage(plugin.color(plugin.getPrefix() +
                plugin.getMessage("admin_ip_unbanned").replace("%ip%", ip)));
    }

    private void handleApprove(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth approve <code>"));
            return;
        }

        String code = args[1].toUpperCase();
        RecoveryManager recoveryManager = plugin.getRecoveryManager();

        RecoveryManager.RecoveryRequest request = recoveryManager.getRequest(code);
        if (request == null) {
            sender.sendMessage(plugin.color(plugin.getPrefix() +
                    plugin.getMessage("admin_recovery_not_found").replace("%code%", code)));
            return;
        }

        recoveryManager.approveRequest(code);
        sender.sendMessage(plugin.color(plugin.getPrefix() +
                plugin.getMessage("admin_recovery_approved").replace("%code%", code)));
    }

    private void handleDeny(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth deny <code>"));
            return;
        }

        String code = args[1].toUpperCase();
        RecoveryManager recoveryManager = plugin.getRecoveryManager();

        RecoveryManager.RecoveryRequest request = recoveryManager.getRequest(code);
        if (request == null) {
            sender.sendMessage(plugin.color(plugin.getPrefix() +
                    plugin.getMessage("admin_recovery_not_found").replace("%code%", code)));
            return;
        }

        recoveryManager.denyRequest(code);
        sender.sendMessage(plugin.color(plugin.getPrefix() +
                plugin.getMessage("admin_recovery_denied").replace("%code%", code)));
    }

    private void handleLookup(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(plugin.color(plugin.getPrefix() + "&cUsage: /coolauth lookup <ip>"));
            return;
        }

        String ip = args[1];

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            List<String> players = storage.getPlayersByIp(ip);

            if (players.isEmpty()) {
                sender.sendMessage(plugin.color(plugin.getPrefix() +
                        plugin.getMessage("admin_lookup_none").replace("%ip%", ip)));
                return;
            }

            sender.sendMessage(plugin.color(plugin.getPrefix() +
                    plugin.getMessage("admin_lookup_header").replace("%ip%", ip)));

            for (String playerName : players) {
                sender.sendMessage(plugin.color(plugin.getMessage("admin_lookup_entry").replace("%player%", playerName)));
            }
        });
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command cmd, String alias, String[] args) {
        if (!sender.hasPermission("coolauth.admin")) return Collections.emptyList();

        if (args.length == 1) {
            List<String> subs = Arrays.asList("reload", "unregister", "setpass", "info", "forcelogin", "forceregister", "banip", "unbanip", "approve", "deny", "lookup");
            return subs.stream()
                    .filter(s -> s.toLowerCase().startsWith(args[0].toLowerCase()))
                    .collect(Collectors.toList());
        }

        if (args.length == 2) {
            String sub = args[0].toLowerCase();

            if (Arrays.asList("unregister", "setpass", "info", "forcelogin", "forceregister").contains(sub)) {
                return Bukkit.getOnlinePlayers().stream()
                        .map(Player::getName)
                        .filter(n -> n.toLowerCase().startsWith(args[1].toLowerCase()))
                        .collect(Collectors.toList());
            }

            if (sub.equals("unbanip")) {
                return plugin.getBannedIps().stream()
                        .filter(ip -> ip.startsWith(args[1]))
                        .collect(Collectors.toList());
            }

            if (sub.equals("approve") || sub.equals("deny")) {
                return plugin.getRecoveryManager().getActiveRecoveryCodes().stream()
                        .filter(c -> c.toUpperCase().startsWith(args[1].toUpperCase()))
                        .collect(Collectors.toList());
            }
        }

        return Collections.emptyList();
    }
                                                }
