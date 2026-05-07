<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Security_Presets {
    public const ACTIVE_PRESET_OPTION = 'secure_guard_active_preset';
    public const PREVIOUS_SETTINGS_OPTION = 'secure_guard_previous_settings_snapshot';

    /**
     * @return array<string,array<string,mixed>>
     */
    public static function all(): array {
        return [
            'beginner' => [
                'label'       => __('Beginner', 'secure-guard'),
                'target'      => __('Blogs, creators, and low-risk brochure sites', 'secure-guard'),
                'description' => __('Safe defaults with lower false-positive risk and clear protection against common WordPress abuse.', 'secure-guard'),
                'settings'    => [
                    'rest_lock_enabled' => 1,
                    'block_sensitive_endpoints' => 1,
                    'rest_strict_mode' => 0,
                    'rate_limit_per_minute' => 180,
                    'bot_rate_limit_enabled' => 1,
                    'bot_rate_limit_per_minute' => 120,
                    'bot_block_minutes' => 10,
                    'scan_404_threshold' => 30,
                    'login_protection_enabled' => 1,
                    'login_short_threshold' => 7,
                    'login_medium_threshold' => 14,
                    'login_hard_block_threshold' => 28,
                    'login_ban_hours' => 1,
                    'block_xmlrpc' => 1,
                    'block_user_enumeration' => 1,
                    'block_public_wp_cron' => 0,
                    'reputation_enabled' => 1,
                    'reputation_throttle_score' => 30,
                    'reputation_challenge_score' => 65,
                    'reputation_block_score' => 120,
                    'progressive_throttle_enabled' => 1,
                    'lockdown_velocity_threshold' => 800,
                    'bot_fingerprint_enabled' => 1,
                    'endpoint_sensitivity_enabled' => 1,
                    'hide_wp_info' => 1,
                    'hide_login_errors' => 1,
                    'enable_coop' => 1,
                    'enable_corp' => 1,
                    'enable_hsts' => 1,
                ],
            ],
            'balanced' => [
                'label'       => __('Balanced', 'secure-guard'),
                'target'      => __('Agencies, business sites, and production WordPress installs', 'secure-guard'),
                'description' => __('Recommended default. Strong protection with conservative thresholds to avoid locking out legitimate admins.', 'secure-guard'),
                'settings'    => [
                    'rest_lock_enabled' => 1,
                    'block_sensitive_endpoints' => 1,
                    'rest_strict_mode' => 0,
                    'rate_limit_per_minute' => 100,
                    'bot_rate_limit_enabled' => 1,
                    'bot_rate_limit_per_minute' => 60,
                    'bot_block_minutes' => 15,
                    'scan_404_threshold' => 20,
                    'login_protection_enabled' => 1,
                    'login_short_threshold' => 5,
                    'login_medium_threshold' => 10,
                    'login_hard_block_threshold' => 20,
                    'login_ban_hours' => 2,
                    'block_xmlrpc' => 1,
                    'block_user_enumeration' => 1,
                    'block_public_wp_cron' => 1,
                    'reputation_enabled' => 1,
                    'reputation_throttle_score' => 20,
                    'reputation_challenge_score' => 50,
                    'reputation_block_score' => 100,
                    'progressive_throttle_enabled' => 1,
                    'lockdown_velocity_threshold' => 500,
                    'bot_fingerprint_enabled' => 1,
                    'endpoint_sensitivity_enabled' => 1,
                    'hide_wp_info' => 1,
                    'hide_login_errors' => 1,
                    'enable_coop' => 1,
                    'enable_corp' => 1,
                    'enable_hsts' => 1,
                ],
            ],
            'maximum' => [
                'label'       => __('Maximum Security', 'secure-guard'),
                'target'      => __('APIs, SaaS sites, admin portals, and high-risk environments', 'secure-guard'),
                'description' => __('Aggressive controls for hostile traffic. Review whitelists and recovery before applying.', 'secure-guard'),
                'settings'    => [
                    'rest_lock_enabled' => 1,
                    'block_sensitive_endpoints' => 1,
                    'rest_strict_mode' => 1,
                    'rate_limit_per_minute' => 45,
                    'bot_rate_limit_enabled' => 1,
                    'bot_rate_limit_per_minute' => 30,
                    'bot_block_minutes' => 60,
                    'scan_404_threshold' => 10,
                    'login_protection_enabled' => 1,
                    'login_short_threshold' => 3,
                    'login_medium_threshold' => 6,
                    'login_hard_block_threshold' => 10,
                    'login_ban_hours' => 12,
                    'block_xmlrpc' => 1,
                    'block_user_enumeration' => 1,
                    'block_public_wp_cron' => 1,
                    'reputation_enabled' => 1,
                    'reputation_throttle_score' => 10,
                    'reputation_challenge_score' => 25,
                    'reputation_block_score' => 60,
                    'progressive_throttle_enabled' => 1,
                    'lockdown_velocity_threshold' => 250,
                    'bot_fingerprint_enabled' => 1,
                    'endpoint_sensitivity_enabled' => 1,
                    'hide_wp_info' => 1,
                    'hide_login_errors' => 1,
                    'enable_coop' => 1,
                    'enable_corp' => 1,
                    'enable_hsts' => 1,
                ],
            ],
        ];
    }

    /**
     * @return array<string,mixed>|null
     */
    public static function get(string $slug): ?array {
        $presets = self::all();
        return $presets[$slug] ?? null;
    }

    public static function detect(array $settings): string {
        foreach (self::all() as $slug => $preset) {
            $matches = true;
            foreach ((array) ($preset['settings'] ?? []) as $key => $value) {
                if (!array_key_exists($key, $settings) || (string) $settings[$key] !== (string) $value) {
                    $matches = false;
                    break;
                }
            }

            if ($matches) {
                return $slug;
            }
        }

        return 'custom';
    }

    public static function label(string $slug): string {
        if ($slug === 'custom') {
            return __('Custom', 'secure-guard');
        }

        $preset = self::get($slug);
        return is_array($preset) ? (string) $preset['label'] : __('Unknown', 'secure-guard');
    }
}
