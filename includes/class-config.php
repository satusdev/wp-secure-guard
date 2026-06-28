<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Config {
    public const OPTION_KEY = 'secure_guard_settings';
    public const DB_VERSION_OPTION = 'secure_guard_db_version';
    public const PLUGIN_VERSION_OPTION = 'secure_guard_plugin_version';
    public const DB_VERSION = '2.0.0';

    /**
     * Permitted scope values. Enforced at token creation and edit time.
     * The full_api_access scope grants access to sensitive endpoints (users, settings, plugins).
     */
    public const VALID_SCOPES = [
        'read_posts',
        'write_posts',
        'read_media',
        'write_media',
        'read_users',
        'write_users',
        'read_settings',
        'full_api_access',
    ];

    /**
     * Maps setting keys to environment variable names.
     * Compatible with Bedrock phpdotenv (.env files), Apache SetEnv, and system env.
     *
     * Priority: PHP constant > env var > database setting > default.
     *
     * Bedrock .env example:
     *   SECURE_GUARD_JWT_SECRET=your-long-random-secret-here
     *   SECURE_GUARD_JWT_ISSUER=https://example.com/
     *   SECURE_GUARD_JWT_AUDIENCE=https://example.com/
     *
     * Setting issuer and audience to the same value across all environments means
     * tokens survive a staging-to-production database clone without re-signing.
     */
    public const ENV_VARS = [
        'jwt_secret'   => 'SECURE_GUARD_JWT_SECRET',
        'jwt_issuer'   => 'SECURE_GUARD_JWT_ISSUER',
        'jwt_audience' => 'SECURE_GUARD_JWT_AUDIENCE',
        'safe_mode'    => 'SECURE_GUARD_SAFE_MODE',
    ];

    /**
     * Returns the trimmed env var value for the given setting key, or '' if not set.
     * Checks $_ENV first (populated by phpdotenv/Bedrock), then getenv() (system env).
     */
    public static function get_env_value(string $key): string {
        $env_var = self::ENV_VARS[$key] ?? '';
        if ($env_var === '') {
            return '';
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $val = $_ENV[$env_var] ?? false;
        if ($val === false) {
            $val = getenv($env_var);
        }

        return is_string($val) && trim($val) !== '' ? trim($val) : '';
    }

    /**
     * Returns true if an active environment variable override exists for this setting key.
     */
    public static function is_env_overridden(string $key): bool {
        return self::get_env_value($key) !== '';
    }

    public static function defaults(): array {
        $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $fallback_url = $scheme . '://' . $host . '/';
        $jwt_url = function_exists('home_url') ? home_url('/') : $fallback_url;

        return [
            'rest_lock_enabled' => 1,
            'block_sensitive_endpoints' => 1,
            'block_user_enumeration' => 1,
            'block_xmlrpc' => 1,
            'login_protection_enabled' => 1,
            'login_short_threshold' => 5,
            'login_medium_threshold' => 10,
            'login_hard_block_threshold' => 20,
            'bot_rate_limit_enabled' => 1,
            'bot_rate_limit_per_minute' => 120,
            'bot_block_minutes' => 15,
            'scan_404_threshold' => 30,
            'block_public_wp_cron' => 1,
            'hide_wp_info' => 1,
            'admin_area_protection_enabled' => 1,
            'admin_ip_whitelist' => '',
            'trusted_proxy_ips' => '',
            'file_integrity_enabled' => 1,
            'ip_whitelist' => '',
            'rate_limit_per_minute' => 200,
            'allowed_roles' => ['administrator'],
            'jwt_secret' => '',
            'jwt_issuer' => $jwt_url,
            'jwt_audience' => $jwt_url,
            'jwt_ttl_minutes' => 60,
            'jwt_clock_skew_seconds' => 30,
            'bind_jwt_to_ip' => 0,
            'bind_jwt_to_ua' => 0,
            // unsafe-inline and unsafe-eval are included in script-src by default to prevent breaking core
            // WordPress capabilities, page builders (Elementor, Divi), and common plugins.
            'csp' => "default-src 'self' https: data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: blob:; font-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'",
            'referrer_policy' => 'strict-origin-when-cross-origin',
            'permissions_policy' => 'camera=(), microphone=(), geolocation=()',
            'enable_coop' => 1,
            'enable_corp' => 1,
            'enable_hsts' => 1,
            'hsts_max_age' => 31536000,
            'log_retention_days' => 30,
            'log_allowed_requests' => 0,
            'email_alerts_enabled' => 0,
            'alert_on_hard_block' => 1,
            'alert_on_integrity' => 1,
            'alert_on_token_expiry_days' => 3,
            'rest_strict_mode' => 0,
            'disable_emojis' => 1,
            'disable_oembeds' => 1,
            'disable_file_editor' => 1,
            'hide_login_errors' => 1,
            'block_bad_bots' => 1,
            'allowed_rest_namespaces' => 'contact-form-7/v1',
            'login_ban_hours' => 2,
            'reputation_enabled' => 1,
            'reputation_throttle_score' => 20,
            'reputation_challenge_score' => 50,
            'reputation_block_score' => 100,
            'reputation_block_minutes' => 60,
            'reputation_decay_per_day' => 10,
            'progressive_throttle_enabled' => 1,
            'lock_state_enabled' => 1,
            'lockdown_velocity_threshold' => 500,
            'lockdown_message' => 'This site is temporarily down for maintenance. Please check back later.',
            'lockdown_status_code' => 503,
            'self_protection_enabled' => 1,
            'bot_fingerprint_enabled' => 1,
            'burst_limit' => 30,
            'burst_window_seconds' => 2,
            'endpoint_sensitivity_enabled' => 1,
            'mu_plugin_path' => WP_CONTENT_DIR . '/mu-plugins',
            'allowed_bot_user_agents' => "UptimeRobot\nPingdom\nBetterStack\nNodePing",
        ];
    }

    public static function get_settings(): array {
        $stored = get_option(self::OPTION_KEY, []);
        if (!is_array($stored)) {
            $stored = [];
        }

        $settings = wp_parse_args($stored, self::defaults());
        $settings['rate_limit_per_minute'] = max(1, (int) $settings['rate_limit_per_minute']);
        $settings['bot_rate_limit_per_minute'] = max(1, (int) $settings['bot_rate_limit_per_minute']);
        $settings['bot_block_minutes'] = max(1, (int) $settings['bot_block_minutes']);
        $settings['scan_404_threshold'] = max(1, (int) $settings['scan_404_threshold']);
        $settings['login_short_threshold'] = max(1, (int) $settings['login_short_threshold']);
        $settings['login_medium_threshold'] = max((int) $settings['login_short_threshold'], (int) $settings['login_medium_threshold']);
        $settings['login_hard_block_threshold'] = max((int) $settings['login_medium_threshold'], (int) $settings['login_hard_block_threshold']);
        $settings['hsts_max_age'] = max(0, (int) $settings['hsts_max_age']);
        $settings['log_retention_days'] = max(1, (int) $settings['log_retention_days']);
        $settings['log_allowed_requests'] = !empty($settings['log_allowed_requests']) ? 1 : 0;
        $settings['rest_strict_mode'] = !empty($settings['rest_strict_mode']) ? 1 : 0;
        $settings['disable_emojis'] = !empty($settings['disable_emojis']) ? 1 : 0;
        $settings['disable_oembeds'] = !empty($settings['disable_oembeds']) ? 1 : 0;
        $settings['disable_file_editor'] = !empty($settings['disable_file_editor']) ? 1 : 0;
        $settings['hide_login_errors'] = !empty($settings['hide_login_errors']) ? 1 : 0;
        $settings['block_bad_bots'] = !empty($settings['block_bad_bots']) ? 1 : 0;
        $settings['allowed_roles'] = is_array($settings['allowed_roles']) ? $settings['allowed_roles'] : ['administrator'];
        $settings['jwt_ttl_minutes'] = max(1, (int) $settings['jwt_ttl_minutes']);
        $settings['jwt_clock_skew_seconds'] = max(0, (int) $settings['jwt_clock_skew_seconds']);
        $settings['jwt_issuer'] = trim((string) $settings['jwt_issuer']) !== '' ? (string) $settings['jwt_issuer'] : home_url('/');
        $settings['jwt_audience'] = trim((string) $settings['jwt_audience']) !== '' ? (string) $settings['jwt_audience'] : home_url('/');
        $settings['alert_on_token_expiry_days'] = max(0, (int) $settings['alert_on_token_expiry_days']);
        $settings['lockdown_velocity_threshold'] = max(1, (int) ($settings['lockdown_velocity_threshold'] ?? 500));
        $settings['lockdown_message'] = sanitize_text_field((string) ($settings['lockdown_message'] ?? 'This site is temporarily down for maintenance. Please check back later.'));
        $settings['lockdown_status_code'] = max(100, min(599, (int) ($settings['lockdown_status_code'] ?? 503)));
        $settings['reputation_decay_per_day'] = max(1, (int) ($settings['reputation_decay_per_day'] ?? 10));
        $settings['reputation_block_minutes'] = max(1, (int) ($settings['reputation_block_minutes'] ?? 60));
        $settings['bind_jwt_to_ip'] = !empty($settings['bind_jwt_to_ip']) ? 1 : 0;
        $settings['bind_jwt_to_ua'] = !empty($settings['bind_jwt_to_ua']) ? 1 : 0;

        if (isset($settings['csp']) && trim((string) $settings['csp']) === "default-src 'self'") {
            $settings['csp'] = '';
        }

        // Migrate older installs with the restrictive default CSP to the new layout-safe default CSP.
        $old_default_csp = "default-src 'self' https: data: blob:; script-src 'self' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: blob:; font-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'";
        if (isset($stored['csp']) && trim((string) $stored['csp']) === $old_default_csp) {
            $defaults = self::defaults();
            $stored['csp'] = $defaults['csp'];
            update_option(self::OPTION_KEY, $stored, false);
            $settings['csp'] = $stored['csp'];
        }

        // Apply environment variable overrides. Env vars take precedence over the database-stored
        // settings but yield to PHP constants (handled per-setting where applicable).
        // Compatible with Bedrock phpdotenv, Apache SetEnv, and system environment variables.
        foreach (self::ENV_VARS as $setting_key => $_env_var) {
            $env_val = self::get_env_value($setting_key);
            if ($env_val !== '') {
                $settings[$setting_key] = $env_val;
            }
        }

        // Override stale mu_plugin_path (e.g. from staging clones) if it's outside the current site's content directory
        if (isset($settings['mu_plugin_path'])) {
            $normalized_mu_path = str_replace('\\', '/', $settings['mu_plugin_path']);
            $normalized_content_dir = str_replace('\\', '/', self::get_content_dir());
            if (!str_starts_with($normalized_mu_path, $normalized_content_dir)) {
                $settings['mu_plugin_path'] = self::get_mu_plugin_dir();
            }
        }

        return $settings;
    }

    public static function save_settings(array $input): array {
        $defaults = self::defaults();

        $allowed_roles = [];
        if (isset($input['allowed_roles']) && is_array($input['allowed_roles'])) {
            $editable_roles = array_keys(wp_roles()->roles);
            foreach ($input['allowed_roles'] as $role) {
                $role = sanitize_key((string) $role);
                if (in_array($role, $editable_roles, true)) {
                    $allowed_roles[] = $role;
                }
            }
        }
        if ($allowed_roles === []) {
            $allowed_roles = ['administrator'];
        }

        $settings = [
            'rest_lock_enabled' => !empty($input['rest_lock_enabled']) ? 1 : 0,
            'block_sensitive_endpoints' => !empty($input['block_sensitive_endpoints']) ? 1 : 0,
            'block_user_enumeration' => !empty($input['block_user_enumeration']) ? 1 : 0,
            'block_xmlrpc' => !empty($input['block_xmlrpc']) ? 1 : 0,
            'login_protection_enabled' => !empty($input['login_protection_enabled']) ? 1 : 0,
            'login_short_threshold' => max(1, (int) ($input['login_short_threshold'] ?? $defaults['login_short_threshold'])),
            'login_medium_threshold' => max(1, (int) ($input['login_medium_threshold'] ?? $defaults['login_medium_threshold'])),
            'login_hard_block_threshold' => max(1, (int) ($input['login_hard_block_threshold'] ?? $defaults['login_hard_block_threshold'])),
            'bot_rate_limit_enabled' => !empty($input['bot_rate_limit_enabled']) ? 1 : 0,
            'bot_rate_limit_per_minute' => max(1, (int) ($input['bot_rate_limit_per_minute'] ?? $defaults['bot_rate_limit_per_minute'])),
            'bot_block_minutes' => max(1, (int) ($input['bot_block_minutes'] ?? $defaults['bot_block_minutes'])),
            'scan_404_threshold' => max(1, (int) ($input['scan_404_threshold'] ?? $defaults['scan_404_threshold'])),
            'block_public_wp_cron' => !empty($input['block_public_wp_cron']) ? 1 : 0,
            'hide_wp_info' => !empty($input['hide_wp_info']) ? 1 : 0,
            'admin_area_protection_enabled' => !empty($input['admin_area_protection_enabled']) ? 1 : 0,
            'admin_ip_whitelist' => sanitize_textarea_field((string) ($input['admin_ip_whitelist'] ?? '')),
            'trusted_proxy_ips' => sanitize_textarea_field((string) ($input['trusted_proxy_ips'] ?? '')),
            'file_integrity_enabled' => !empty($input['file_integrity_enabled']) ? 1 : 0,
            'ip_whitelist' => sanitize_textarea_field((string) ($input['ip_whitelist'] ?? '')),
            'rate_limit_per_minute' => max(1, (int) ($input['rate_limit_per_minute'] ?? $defaults['rate_limit_per_minute'])),
            'allowed_roles' => $allowed_roles,
            'jwt_secret' => sanitize_text_field((string) ($input['jwt_secret'] ?? $defaults['jwt_secret'])),
            'jwt_issuer' => esc_url_raw((string) ($input['jwt_issuer'] ?? $defaults['jwt_issuer'])),
            'jwt_audience' => esc_url_raw((string) ($input['jwt_audience'] ?? $defaults['jwt_audience'])),
            'jwt_ttl_minutes' => max(1, (int) ($input['jwt_ttl_minutes'] ?? $defaults['jwt_ttl_minutes'])),
            'jwt_clock_skew_seconds' => max(0, (int) ($input['jwt_clock_skew_seconds'] ?? $defaults['jwt_clock_skew_seconds'])),
            'bind_jwt_to_ip' => !empty($input['bind_jwt_to_ip']) ? 1 : 0,
            'bind_jwt_to_ua' => !empty($input['bind_jwt_to_ua']) ? 1 : 0,
            'csp' => wp_strip_all_tags((string) ($input['csp'] ?? $defaults['csp'])),
            'referrer_policy' => sanitize_text_field((string) ($input['referrer_policy'] ?? $defaults['referrer_policy'])),
            'permissions_policy' => wp_strip_all_tags((string) ($input['permissions_policy'] ?? $defaults['permissions_policy'])),
            'enable_coop' => !empty($input['enable_coop']) ? 1 : 0,
            'enable_corp' => !empty($input['enable_corp']) ? 1 : 0,
            'enable_hsts' => !empty($input['enable_hsts']) ? 1 : 0,
            'hsts_max_age' => max(0, (int) ($input['hsts_max_age'] ?? $defaults['hsts_max_age'])),
            'log_retention_days' => max(1, (int) ($input['log_retention_days'] ?? $defaults['log_retention_days'])),
            'log_allowed_requests' => !empty($input['log_allowed_requests']) ? 1 : 0,
            'email_alerts_enabled' => !empty($input['email_alerts_enabled']) ? 1 : 0,
            'alert_on_hard_block' => !empty($input['alert_on_hard_block']) ? 1 : 0,
            'alert_on_integrity' => !empty($input['alert_on_integrity']) ? 1 : 0,
            'alert_on_token_expiry_days' => max(0, (int) ($input['alert_on_token_expiry_days'] ?? $defaults['alert_on_token_expiry_days'])),
            'rest_strict_mode' => !empty($input['rest_strict_mode']) ? 1 : 0,
            'disable_emojis' => !empty($input['disable_emojis']) ? 1 : 0,
            'disable_oembeds' => !empty($input['disable_oembeds']) ? 1 : 0,
            'disable_file_editor' => !empty($input['disable_file_editor']) ? 1 : 0,
            'hide_login_errors' => !empty($input['hide_login_errors']) ? 1 : 0,
            'block_bad_bots' => !empty($input['block_bad_bots']) ? 1 : 0,
            'allowed_rest_namespaces' => sanitize_textarea_field((string) ($input['allowed_rest_namespaces'] ?? $defaults['allowed_rest_namespaces'])),
            'login_ban_hours' => max(1, (int) ($input['login_ban_hours'] ?? $defaults['login_ban_hours'])),
            'reputation_enabled' => !empty($input['reputation_enabled']) ? 1 : 0,
            'reputation_throttle_score' => max(1, (int) ($input['reputation_throttle_score'] ?? $defaults['reputation_throttle_score'])),
            'reputation_challenge_score' => max(1, (int) ($input['reputation_challenge_score'] ?? $defaults['reputation_challenge_score'])),
            'reputation_block_score' => max(1, (int) ($input['reputation_block_score'] ?? $defaults['reputation_block_score'])),
            'reputation_block_minutes' => max(1, (int) ($input['reputation_block_minutes'] ?? $defaults['reputation_block_minutes'])),
            'reputation_decay_per_day' => max(1, (int) ($input['reputation_decay_per_day'] ?? $defaults['reputation_decay_per_day'])),
            'progressive_throttle_enabled' => !empty($input['progressive_throttle_enabled']) ? 1 : 0,
            'lock_state_enabled' => !empty($input['lock_state_enabled']) ? 1 : 0,
            'lockdown_velocity_threshold' => max(1, (int) ($input['lockdown_velocity_threshold'] ?? $defaults['lockdown_velocity_threshold'])),
            'lockdown_message' => sanitize_text_field((string) ($input['lockdown_message'] ?? $defaults['lockdown_message'])),
            'lockdown_status_code' => max(100, min(599, (int) ($input['lockdown_status_code'] ?? $defaults['lockdown_status_code']))),
            'self_protection_enabled' => !empty($input['self_protection_enabled']) ? 1 : 0,
            'bot_fingerprint_enabled' => !empty($input['bot_fingerprint_enabled']) ? 1 : 0,
            'burst_limit' => max(1, (int) ($input['burst_limit'] ?? $defaults['burst_limit'])),
            'burst_window_seconds' => max(1, (int) ($input['burst_window_seconds'] ?? $defaults['burst_window_seconds'])),
            'endpoint_sensitivity_enabled' => !empty($input['endpoint_sensitivity_enabled']) ? 1 : 0,
            'mu_plugin_path' => sanitize_text_field((string) ($input['mu_plugin_path'] ?? $defaults['mu_plugin_path'])),
            'allowed_bot_user_agents' => sanitize_textarea_field((string) ($input['allowed_bot_user_agents'] ?? $defaults['allowed_bot_user_agents'])),
        ];

        $settings['login_medium_threshold'] = max($settings['login_short_threshold'], $settings['login_medium_threshold']);
        $settings['login_hard_block_threshold'] = max($settings['login_medium_threshold'], $settings['login_hard_block_threshold']);

        // Do not persist env-var-managed settings to the database.
        // The env value takes precedence at runtime via get_settings(). Preserving the existing
        // DB value intact means it serves as a fallback if the env var is later removed.
        $currently_stored = (array) get_option(self::OPTION_KEY, []);
        foreach (array_keys(self::ENV_VARS) as $env_managed_key) {
            if (self::get_env_value($env_managed_key) !== '') {
                if (array_key_exists($env_managed_key, $currently_stored)) {
                    $settings[$env_managed_key] = $currently_stored[$env_managed_key];
                } else {
                    unset($settings[$env_managed_key]);
                }
            }
        }

        // If the MU-Plugin path or JWT secret changed, redeploy the watchdog to ensure it has the latest context.
        if (($settings['mu_plugin_path'] !== ($currently_stored['mu_plugin_path'] ?? '')) || 
            ($settings['jwt_secret'] !== ($currently_stored['jwt_secret'] ?? ''))) {
            Secure_Guard_Installer::deploy_watchdog();
        }

        if (!empty($settings['hide_wp_info']) && class_exists('Secure_Guard_WP_Hardening')) {
            Secure_Guard_WP_Hardening::write_htaccess_protection();
            update_option('secure_guard_htaccess_hardened', 1, false);
        } else {
            delete_option('secure_guard_htaccess_hardened');
        }

        return $settings;
    }

    /**
     * Remove stale security state for every IP covered by the trusted list.
     * Authentication is unaffected; this only prevents an old ban from taking
     * precedence after an administrator explicitly trusts an address or CIDR.
     */
    public static function reconcile_trusted_ips($old_value, $new_value): void {
        if (!is_array($new_value) || !class_exists('Secure_Guard_IP_Whitelist')) {
            return;
        }

        $raw_list = trim((string) ($new_value['ip_whitelist'] ?? ''));
        if ($raw_list === '') {
            return;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'sg_rate_limits';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $subjects = $wpdb->get_col(
            "SELECT subject FROM {$table} WHERE subject LIKE 'ip-block:%' OR subject LIKE 'login-block:%' OR subject LIKE 'rep:%'"
        ) ?: [];
        $whitelist = new Secure_Guard_IP_Whitelist($new_value);

        foreach ($subjects as $subject) {
            $separator = strpos((string) $subject, ':');
            $ip = $separator === false ? '' : substr((string) $subject, $separator + 1);
            if ($ip === '' || !$whitelist->check_list($ip, $raw_list)) {
                continue;
            }

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($table, ['subject' => (string) $subject], ['%s']);
            delete_transient('sg_iblk_' . substr(md5('ip-block:' . $ip), 0, 16));
            delete_transient('secure_guard_login_fails_' . md5($ip));
            delete_transient('secure_guard_404_scans_' . md5($ip));
        }

        delete_transient('sg_dashboard_stats');
    }

    public static function get_content_dir(): string {
        return defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
    }

    public static function is_safe_mode(): bool {
        if (defined('SECURE_GUARD_SAFE_MODE') && SECURE_GUARD_SAFE_MODE) return true;
        $env = strtolower(self::get_env_value('safe_mode'));
        if (in_array($env, ['1', 'true', 'yes', 'on'], true)) return true;
        $until = (int) get_option('secure_guard_safe_mode_until', 0);
        if ($until > time()) return true;
        if ($until > 0) delete_option('secure_guard_safe_mode_until');
        return false;
    }

    public static function get_mu_plugin_dir(): string {
        return defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : self::get_content_dir() . '/mu-plugins';
    }

    public static function get_debug_log_path(): string {
        return self::get_content_dir() . '/debug.log';
    }

    public static function get_htaccess_path(): string {
        return self::get_content_dir() . '/.htaccess';
    }

    public static function get_root_htaccess_path(): string {
        $root = ABSPATH;
        if (str_ends_with(rtrim(ABSPATH, '/\\'), '/wp')) {
            $root = dirname(ABSPATH) . '/';
        }
        return $root . '.htaccess';
    }
}
