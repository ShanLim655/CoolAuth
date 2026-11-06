package com.coolauth.commands;

import com.coolauth.CoolAuth;
import com.coolauth.managers.AuthManager;
import com.coolauth.managers.PasswordValidator;
import com.coolauth.storage.AuthStorage;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public class AuthCommands implements CommandExecutor {

    private final CoolAuth plugin;
    private final AuthStorage storage;
    private final AuthManager authManager;
    private final PasswordValidator passwordValidator;

    public AuthCommands(CoolAuth plugin) {
        this.plugin = plugin;
        this.storage = plugin.getStorage();
        this.authManager = plugin.getAuthManager();
        this.passwordValidator = plugin.getPasswordValidator();
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("Only players can use auth commands.");
            return true;
        }

        String cmdName = cmd.getName().toLowerCase();

        return switch (cmdName) {
            case "register" -> handleRegister(player, args);
            case "login" -> handleLogin(player, args);
            case "changepassword" -> handleChangePassword(player, args);
            default -> false;
        };
    }

    private boolean handleRegister(Player player, String[] args) {
        if (authManager.isAuthenticated(player)) {
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("already_logged_in")));
            return true;
        }

        // Require 2 arguments: password and confirm password
        if (args.length != 2) {
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("register_usage")));
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("register_example")));
            return true;
        }

        String password = args[0];
        String confirmPassword = args[1];

        // Check if passwords match
        if (!password.equals(confirmPassword)) {
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("passwords_dont_match")));
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("register_example")));
            return true;
        }

        // Validate password strength
        String validationError = passwordValidator.validate(password);
        if (validationError != null) {
            player.sendMessage(plugin.color(plugin.getPrefix() + validationError));
            return true;
        }

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            if (storage.isRegistered(player.getUniqueId())) {
                player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("already_registered")));
                return;
            }

            storage.savePlayer(player, password);
            authManager.finishAuth(player, false);
        });

        return true;
    }

    private boolean handleLogin(Player player, String[] args) {
        if (authManager.isAuthenticated(player)) {
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("already_logged_in")));
            return true;
        }

        if (args.length != 1) {
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("login_usage")));
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("login_example")));
            return true;
        }

        String password = args[0];

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            if (!storage.isRegistered(player.getUniqueId())) {
                player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("not_registered")));
                return;
            }

            if (storage.checkPassword(player.getUniqueId(), password)) {
                authManager.finishAuth(player, false);
            } else {
                handleFailedLogin(player);
            }
        });

        return true;
    }

    private boolean handleChangePassword(Player player, String[] args) {
        if (!authManager.isAuthenticated(player)) {
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("not_registered")));
            return true;
        }

        // Require 3 arguments: old password, new password, confirm new password
        if (args.length != 3) {
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("changepass_usage")));
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("changepass_example")));
            return true;
        }

        String oldPassword = args[0];
        String newPassword = args[1];
        String confirmNewPassword = args[2];

        // Check if new passwords match
        if (!newPassword.equals(confirmNewPassword)) {
            player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("passwords_dont_match")));
            return true;
        }

        // Validate new password strength
        String validationError = passwordValidator.validate(newPassword);
        if (validationError != null) {
            player.sendMessage(plugin.color(plugin.getPrefix() + validationError));
            return true;
        }

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            if (storage.checkPassword(player.getUniqueId(), oldPassword)) {
                storage.updatePassword(player.getUniqueId(), newPassword);
                player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("pass_changed")));
            } else {
                player.sendMessage(plugin.color(plugin.getPrefix() + plugin.getMessage("wrong_password")));
            }
        });

        return true;
    }

    private void handleFailedLogin(Player player) {
        Bukkit.getScheduler().runTask(plugin, () -> {
            int attempts = authManager.incrementLoginAttempts(player.getUniqueId());
            int maxAttempts = authManager.getMaxAttempts();

            if (attempts >= maxAttempts) {
                player.kickPlayer(plugin.color(plugin.getMessage("max_attempts")));
            } else {
                player.sendMessage(plugin.color(plugin.getPrefix() +
                        plugin.getMessage("wrong_password") + " &7(" + attempts + "/" + maxAttempts + ")"));
            }
        });
    }
}
