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
        $jwt_denylist_table = $wpdb->prefix . 'sg_jwt_denylist';

        $sql_tokens = "CREATE TABLE {$tokens_table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            name VARCHAR(190) NOT NULL,
            token_type VARCHAR(16) NOT NULL DEFAULT 'jwt',
            token_hash TEXT NULL,
            jti VARCHAR(64) NULL,
            kid VARCHAR(64) NULL,
            scope TEXT NOT NULL,
            allowed_endpoints TEXT NULL,
            allowed_ips TEXT NULL,
            rate_limit_per_minute INT UNSIGNED NULL,
            expires_at DATETIME NULL,
            last_used_at DATETIME NULL,
            created_at DATETIME NOT NULL,
            revoked_at DATETIME NULL,
            PRIMARY KEY (id),
            KEY token_type (token_type),
            UNIQUE KEY jti (jti),
            KEY revoked_at (revoked_at),
            KEY expires_at (expires_at)
        ) {$charset_collate};";

        $sql_logs = "CREATE TABLE {$logs_table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(64) NOT NULL,
            endpoint VARCHAR(255) NOT NULL,
            method VARCHAR(12) NOT NULL,
            result VARCHAR(32) NOT NULL,
            reason VARCHAR(190) NOT NULL,
            attack_cluster VARCHAR(32) NULL,
            country_code CHAR(2) NULL,
            context LONGTEXT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY endpoint (endpoint),
            KEY created_at (created_at),
            KEY result (result),
            KEY reason (reason),
            KEY attack_cluster (attack_cluster)
        ) {$charset_collate};";

        $sql_rate = "CREATE TABLE {$rate_limits_table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            subject VARCHAR(255) NOT NULL,
            window_started_at DATETIME NOT NULL,
            hit_count INT UNSIGNED NOT NULL,
            reputation_score INT UNSIGNED NOT NULL DEFAULT 0,
            blocked_until DATETIME NULL,
            PRIMARY KEY (id),
            UNIQUE KEY subject (subject),
            KEY blocked_until (blocked_until),
            KEY reputation_score (reputation_score)
        ) {$charset_collate};";

        $sql_jwt_denylist = "CREATE TABLE {$jwt_denylist_table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            jti VARCHAR(64) NOT NULL,
            revoked_until DATETIME NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY jti (jti),
            KEY revoked_until (revoked_until)
        ) {$charset_collate};";

        dbDelta($sql_tokens);
        dbDelta($sql_logs);
        dbDelta($sql_rate);
        dbDelta($sql_jwt_denylist);

        self::ensure_column($logs_table, 'attack_cluster', 'ALTER TABLE ' . $logs_table . ' ADD COLUMN attack_cluster VARCHAR(32) NULL AFTER reason');
        self::ensure_column($logs_table, 'country_code', 'ALTER TABLE ' . $logs_table . ' ADD COLUMN country_code CHAR(2) NULL AFTER attack_cluster');
        self::ensure_column($rate_limits_table, 'reputation_score', 'ALTER TABLE ' . $rate_limits_table . ' ADD COLUMN reputation_score INT UNSIGNED NOT NULL DEFAULT 0 AFTER hit_count');

        // Phase 1 Migration: Add missing indices that dbDelta might have missed or syntax-rejected.
        if (!self::index_exists($logs_table, 'ip')) {
            $wpdb->query("ALTER TABLE {$logs_table} ADD INDEX ip (ip)");
        }
        if (!self::index_exists($logs_table, 'attack_cluster')) {
            $wpdb->query("ALTER TABLE {$logs_table} ADD INDEX attack_cluster (attack_cluster)");
        }
        if (!self::index_exists($rate_limits_table, 'reputation_score')) {
            $wpdb->query("ALTER TABLE {$rate_limits_table} ADD INDEX reputation_score (reputation_score)");
        }

        // Migrate existing installs: widen token_hash from CHAR(64) to TEXT and drop the old UNIQUE index.
        if (self::index_exists($tokens_table, 'token_hash')) {
            $wpdb->query("ALTER TABLE {$tokens_table} DROP INDEX token_hash");
        }
        
        $wpdb->query("ALTER TABLE {$tokens_table} MODIFY COLUMN token_hash TEXT NULL");
        // phpcs:enable

        $wpdb->query("UPDATE {$tokens_table} SET revoked_at = UTC_TIMESTAMP() WHERE token_type = 'static' AND revoked_at IS NULL");

        if (!get_option(Secure_Guard_Config::OPTION_KEY)) {
            update_option(Secure_Guard_Config::OPTION_KEY, Secure_Guard_Config::defaults(), false);
        }
        update_option(Secure_Guard_Config::DB_VERSION_OPTION, Secure_Guard_Config::DB_VERSION, false);

        self::deploy_watchdog();
        Secure_Guard_WP_Hardening::write_htaccess_protection();
    }

    public static function deploy_watchdog(): void {
        $settings = Secure_Guard_Config::get_settings();
        $mu_path = $settings['mu_plugin_path'] ?? Secure_Guard_Config::get_mu_plugin_dir();
        
        if (!is_dir($mu_path)) {
            wp_mkdir_p($mu_path);
        }

        $watchdog_file = $mu_path . '/secure-guard-watchdog.php';
        $plugin_path = SECURE_GUARD_DIR;

        $content = "<?php
/**
 * Secure Guard Watchdog (MU-Plugin)
 * Automatically deployed by Secure Guard.
 * Enforces core security rules even if the main plugin is deactivated.
 */

if (!defined('ABSPATH')) exit;

// Bypass for WP-CLI and CLI environments
if (defined('WP_CLI') && WP_CLI) return;
if (php_sapi_name() === 'cli') return;

// 1. Lockdown Check (High Performance)


\$watchdog_lock_state = get_transient('sg_lock_state');
if (!is_array(\$watchdog_lock_state)) {
    \$watchdog_lock_state = get_option('secure_guard_lock_state');
}
if (is_array(\$watchdog_lock_state) && !empty(\$watchdog_lock_state['expires']) && (int) \$watchdog_lock_state['expires'] <= time()) {
    delete_transient('sg_lock_state');
    delete_option('secure_guard_lock_state');
    \$watchdog_lock_state = false;
}

if (\$watchdog_lock_state) {
    // If lockdown is active, we only allow requests that might be login/admin 
    // We can't use is_user_logged_in() yet, but we can check cookie existence
    \$has_auth_cookie = false;
    foreach (\$_COOKIE as \$name => \$val) {
        if (str_starts_with(\$name, 'wordpress_logged_in_')) {
            \$has_auth_cookie = true;
            break;
        }
    }
    
    // Also allow wp-login.php so admins CAN log in
    \$is_login_page = str_contains(\$_SERVER['SCRIPT_NAME'] ?? '', 'wp-login.php');

    if (!\$has_auth_cookie && !\$is_login_page) {
        status_header(503);
        die('Site is under emergency maintenance. Please try again later.');
    }
}

// 2. Main Plugin Reactivation (Optional)
// if (defined('WP_ADMIN')) { ... }

// 3. Minimal Enforcement Engine
if (file_exists('{$plugin_path}includes/class-config.php')) {
    require_once '{$plugin_path}includes/class-config.php';
    require_once '{$plugin_path}includes/security/class-ip-whitelist.php';
    require_once '{$plugin_path}includes/data/class-rate-limit-repository.php';

    \$watchdog_settings = Secure_Guard_Config::get_settings();
    \$watchdog_whitelist = new Secure_Guard_IP_Whitelist(\$watchdog_settings);
    \$watchdog_ip = \$watchdog_whitelist->get_request_ip();
    
    if (!\$watchdog_whitelist->is_allowed(\$watchdog_ip)) {
        // A. Hard Transient Block
        \$watchdog_block_key = 'sg_iblk_' . substr(md5('ip-block:' . \$watchdog_ip), 0, 16);
        if (get_transient(\$watchdog_block_key)) {
             status_header(403);
             die('Forbidden by Secure Guard (IP Blocked)');
        }

        // B. Reputation Score Block (Check DB directly for efficiency)
        global \$wpdb;
        \$rep_score = (int) \$wpdb->get_var(\$wpdb->prepare(
            \"SELECT reputation_score FROM {\$wpdb->prefix}sg_rate_limits WHERE subject = %s\",
            'rep:' . \$watchdog_ip
        ));

        \$block_threshold = (int) (\$watchdog_settings['reputation_block_score'] ?? 100);
        if (\$rep_score >= \$block_threshold) {
            status_header(403);
            die('Forbidden by Secure Guard (High Risk Reputation)');
        }
    }
}
";

        file_put_contents($watchdog_file, $content);
    }

    private static function column_exists(string $table, string $column): bool {
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare("SHOW COLUMNS FROM {$table} LIKE %s", $column));
        return !empty($row);
    }

    private static function ensure_column(string $table, string $column, string $alter_sql): void {
        global $wpdb;
        if (!self::column_exists($table, $column)) {
            $wpdb->query($alter_sql);
        }
    }

    private static function index_exists(string $table, string $index): bool {
        global $wpdb;
        $results = $wpdb->get_results($wpdb->prepare("SHOW INDEX FROM {$table} WHERE Key_name = %s", $index));
        return !empty($results);
    }
}
