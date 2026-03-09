<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Config {
    public const OPTION_KEY = 'secure_guard_settings';
    public const DB_VERSION_OPTION = 'secure_guard_db_version';
    public const DB_VERSION = '1.0.0';

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
            'hide_wp_info' => 1,
            'admin_area_protection_enabled' => 1,
            'admin_ip_whitelist' => '',
            'file_integrity_enabled' => 1,
            'ip_whitelist' => '',
            'rate_limit_per_minute' => 100,
            'allowed_roles' => ['administrator'],
            'csp' => "default-src 'self'",
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
            'hide_wp_info' => !empty($input['hide_wp_info']) ? 1 : 0,
            'admin_area_protection_enabled' => !empty($input['admin_area_protection_enabled']) ? 1 : 0,
            'admin_ip_whitelist' => sanitize_textarea_field((string) ($input['admin_ip_whitelist'] ?? '')),
            'file_integrity_enabled' => !empty($input['file_integrity_enabled']) ? 1 : 0,
            'ip_whitelist' => sanitize_textarea_field((string) ($input['ip_whitelist'] ?? '')),
            'rate_limit_per_minute' => max(1, (int) ($input['rate_limit_per_minute'] ?? $defaults['rate_limit_per_minute'])),
            'allowed_roles' => $allowed_roles,
            'csp' => sanitize_text_field((string) ($input['csp'] ?? $defaults['csp'])),
            'enable_hsts' => !empty($input['enable_hsts']) ? 1 : 0,
            'hsts_max_age' => max(0, (int) ($input['hsts_max_age'] ?? $defaults['hsts_max_age'])),
            'log_retention_days' => max(1, (int) ($input['log_retention_days'] ?? $defaults['log_retention_days'])),
        ];

        $settings['login_medium_threshold'] = max($settings['login_short_threshold'], $settings['login_medium_threshold']);
        $settings['login_hard_block_threshold'] = max($settings['login_medium_threshold'], $settings['login_hard_block_threshold']);

        return $settings;
    }
}
