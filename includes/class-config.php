<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Config {
    public const OPTION_KEY = 'secure_guard_settings';
    public const DB_VERSION_OPTION = 'secure_guard_db_version';
    public const DB_VERSION = '1.3.0';

    public static function defaults(): array {
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
            'bot_rate_limit_per_minute' => 60,
            'bot_block_minutes' => 15,
            'scan_404_threshold' => 20,
            'block_public_wp_cron' => 1,
            'hide_wp_info' => 1,
            'admin_area_protection_enabled' => 1,
            'admin_ip_whitelist' => '',
            'trusted_proxy_ips' => '',
            'file_integrity_enabled' => 1,
            'ip_whitelist' => '',
            'rate_limit_per_minute' => 100,
            'allowed_roles' => ['administrator'],
            'jwt_secret' => '',
            'jwt_issuer' => home_url('/'),
            'jwt_audience' => home_url('/'),
            'jwt_ttl_minutes' => 60,
            'jwt_clock_skew_seconds' => 30,
            'csp' => "default-src 'self' https: data: blob:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: blob:; font-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'",
            'referrer_policy' => 'strict-origin-when-cross-origin',
            'permissions_policy' => 'camera=(), microphone=(), geolocation=()',
            'enable_coop' => 1,
            'enable_corp' => 1,
            'enable_hsts' => 1,
            'hsts_max_age' => 31536000,
            'log_retention_days' => 30,
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
        $settings['allowed_roles'] = is_array($settings['allowed_roles']) ? $settings['allowed_roles'] : ['administrator'];
        $settings['jwt_ttl_minutes'] = max(1, (int) $settings['jwt_ttl_minutes']);
        $settings['jwt_clock_skew_seconds'] = max(0, (int) $settings['jwt_clock_skew_seconds']);
        $settings['jwt_issuer'] = trim((string) $settings['jwt_issuer']) !== '' ? (string) $settings['jwt_issuer'] : home_url('/');
        $settings['jwt_audience'] = trim((string) $settings['jwt_audience']) !== '' ? (string) $settings['jwt_audience'] : home_url('/');

        if (isset($settings['csp']) && trim((string) $settings['csp']) === "default-src 'self'") {
            $settings['csp'] = '';
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
            'csp' => sanitize_text_field((string) ($input['csp'] ?? $defaults['csp'])),
            'referrer_policy' => sanitize_text_field((string) ($input['referrer_policy'] ?? $defaults['referrer_policy'])),
            'permissions_policy' => sanitize_text_field((string) ($input['permissions_policy'] ?? $defaults['permissions_policy'])),
            'enable_coop' => !empty($input['enable_coop']) ? 1 : 0,
            'enable_corp' => !empty($input['enable_corp']) ? 1 : 0,
            'enable_hsts' => !empty($input['enable_hsts']) ? 1 : 0,
            'hsts_max_age' => max(0, (int) ($input['hsts_max_age'] ?? $defaults['hsts_max_age'])),
            'log_retention_days' => max(1, (int) ($input['log_retention_days'] ?? $defaults['log_retention_days'])),
        ];

        $settings['login_medium_threshold'] = max($settings['login_short_threshold'], $settings['login_medium_threshold']);
        $settings['login_hard_block_threshold'] = max($settings['login_medium_threshold'], $settings['login_hard_block_threshold']);

        return $settings;
    }
}
