<?php

if (!defined('ABSPATH')) exit;

final class Secure_Guard_Recovery_CLI {
    public static function register(): void {
        if (defined('WP_CLI') && WP_CLI) WP_CLI::add_command('secure-guard safe-mode', [self::class, 'command']);
    }

    public static function command(array $args, array $assoc): void {
        $action = $args[0] ?? 'status';
        if ($action === 'enable') {
            $minutes = max(1, (int) ($assoc['minutes'] ?? 60));
            update_option('secure_guard_safe_mode_until', time() + $minutes * MINUTE_IN_SECONDS, false);
            WP_CLI::success("Safe mode enabled for {$minutes} minute(s).");
            return;
        }
        if ($action === 'disable') {
            delete_option('secure_guard_safe_mode_until');
            WP_CLI::success('Safe mode disabled.');
            return;
        }
        WP_CLI::log(Secure_Guard_Config::is_safe_mode() ? 'enabled' : 'disabled');
    }
}
