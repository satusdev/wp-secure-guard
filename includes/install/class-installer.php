<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Installer {
    public static function activate(): void {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $charset_collate = $wpdb->get_charset_collate();
        $tokens_table = $wpdb->prefix . 'sg_tokens';
        $logs_table = $wpdb->prefix . 'sg_logs';
        $rate_limits_table = $wpdb->prefix . 'sg_rate_limits';

        $sql_tokens = "CREATE TABLE {$tokens_table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            name VARCHAR(190) NOT NULL,
            token_hash CHAR(64) NOT NULL,
            scope TEXT NOT NULL,
            allowed_endpoints TEXT NULL,
            allowed_ips TEXT NULL,
            rate_limit_per_minute INT UNSIGNED NULL,
            expires_at DATETIME NULL,
            last_used_at DATETIME NULL,
            created_at DATETIME NOT NULL,
            revoked_at DATETIME NULL,
            PRIMARY KEY (id),
            UNIQUE KEY token_hash (token_hash)
        ) {$charset_collate};";

        $sql_logs = "CREATE TABLE {$logs_table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(64) NOT NULL,
            endpoint VARCHAR(255) NOT NULL,
            method VARCHAR(12) NOT NULL,
            result VARCHAR(32) NOT NULL,
            reason VARCHAR(190) NOT NULL,
            context LONGTEXT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY endpoint (endpoint),
            KEY created_at (created_at)
        ) {$charset_collate};";

        $sql_rate = "CREATE TABLE {$rate_limits_table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            subject VARCHAR(255) NOT NULL,
            window_started_at DATETIME NOT NULL,
            hit_count INT UNSIGNED NOT NULL,
            blocked_until DATETIME NULL,
            PRIMARY KEY (id),
            UNIQUE KEY subject (subject)
        ) {$charset_collate};";

        dbDelta($sql_tokens);
        dbDelta($sql_logs);
        dbDelta($sql_rate);

        if (!get_option(Secure_Guard_Config::OPTION_KEY)) {
            update_option(Secure_Guard_Config::OPTION_KEY, Secure_Guard_Config::defaults(), false);
        }
        update_option(Secure_Guard_Config::DB_VERSION_OPTION, Secure_Guard_Config::DB_VERSION, false);
    }
}
