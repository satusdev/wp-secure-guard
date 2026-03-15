<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Admin_Area_Protector {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;
    private Secure_Guard_Rate_Limit_Repository $limits;
    private Secure_Guard_IP_Whitelist $ip_whitelist;

    public function __construct(array $settings, Secure_Guard_Log_Repository $logs, Secure_Guard_Rate_Limit_Repository $limits, Secure_Guard_IP_Whitelist $ip_whitelist) {
        $this->settings = $settings;
        $this->logs = $logs;
        $this->limits = $limits;
        $this->ip_whitelist = $ip_whitelist;
    }

    public function protect(): void {
        if (empty($this->settings['admin_area_protection_enabled'])) {
            return;
        }

        if (!$this->is_admin_request()) {
            return;
        }

        $ip = $this->ip_whitelist->get_request_ip();

        if ($this->is_globally_blocked($ip)) {
            $this->deny('Blocked IP tried admin access', $ip, 403);
        }

        if (!$this->is_logged_user_allowed()) {
            $this->deny('Anonymous access to admin area', $ip, 403);
        }

        $admin_whitelist = trim((string) ($this->settings['admin_ip_whitelist'] ?? ''));
        if ($admin_whitelist !== '' && !$this->ip_is_allowed_by_custom_list($ip, $admin_whitelist)) {
            $this->deny('Admin area IP not allowed', $ip, 403);
        }

        if ($this->is_suspicious_request()) {
            $this->deny('Suspicious admin request blocked', $ip, 403);
        }
    }

    private function is_admin_request(): bool {
        if (defined('WP_CLI') && WP_CLI) {
            return false;
        }

        if (defined('DOING_CRON') && DOING_CRON) {
            return false;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? ''));
        $path = (string) (parse_url($request_uri, PHP_URL_PATH) ?: '');

        // admin-ajax.php handles wp_ajax_nopriv_* actions for logged-out users.
        // Never block it here — plugins relying on public AJAX would break.
        if (basename($path) === 'admin-ajax.php') {
            return false;
        }

        return str_starts_with($path, '/wp-admin');
    }

    private function is_logged_user_allowed(): bool {
        if (!is_user_logged_in()) {
            return false;
        }

        return current_user_can('read');
    }

    private function is_suspicious_request(): bool {
        $request_uri = strtolower(sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '')));
        $patterns = ['../', '<script', 'base64_', 'union%20select', 'concat(', 'sleep('];
        foreach ($patterns as $pattern) {
            if (str_contains($request_uri, $pattern)) {
                return true;
            }
        }

        return false;
    }

    private function is_globally_blocked(string $ip): bool {
        // Cache per-IP block state for 60 s to avoid a DB SELECT on every /wp-admin hit.
        $cache_key = 'sg_iblk_' . substr(md5('ip-block:' . $ip), 0, 16);
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            return (bool) $cached;
        }

        $row = $this->limits->get('ip-block:' . $ip);
        $blocked = $row && !empty($row['blocked_until']) && (strtotime((string) $row['blocked_until']) ?: 0) > time();
        set_transient($cache_key, $blocked ? 1 : 0, 60);

        return $blocked;
    }

    private function ip_is_allowed_by_custom_list(string $ip, string $list): bool {
        // Delegate to the shared IP_Whitelist logic that handles CIDR ranges,
        // so admin IP whitelist entries like '10.0.0.0/8' work correctly.
        return $this->ip_whitelist->check_list($ip, $list);
    }

    private function deny(string $reason, string $ip, int $status): void {
        $endpoint = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/wp-admin'));
        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $this->logs->log($endpoint, $method, 'BLOCKED', $reason, ['ip' => $ip]);

        status_header($status);
        wp_die(esc_html__('Forbidden', 'secure-guard'), esc_html__('Forbidden', 'secure-guard'), ['response' => $status]);
    }
}
