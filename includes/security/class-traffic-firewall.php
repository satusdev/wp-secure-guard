<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Traffic_Firewall {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;
    private Secure_Guard_Rate_Limit $rate_limit;
    private Secure_Guard_Rate_Limit_Repository $limits;
    private Secure_Guard_IP_Whitelist $ip_whitelist;

    public function __construct(
        array $settings,
        Secure_Guard_Log_Repository $logs,
        Secure_Guard_Rate_Limit $rate_limit,
        Secure_Guard_Rate_Limit_Repository $limits,
        Secure_Guard_IP_Whitelist $ip_whitelist
    ) {
        $this->settings = $settings;
        $this->logs = $logs;
        $this->rate_limit = $rate_limit;
        $this->limits = $limits;
        $this->ip_whitelist = $ip_whitelist;
    }

    public function handle_request(): void {
        $ip = $this->ip_whitelist->get_request_ip();

        if ($this->is_sensitive_path_request()) {
            $this->deny_request('Sensitive path blocked', 403, $ip);
        }

        if ($this->ip_whitelist->is_allowed($ip)) {
            return;
        }

        if ($this->is_globally_blocked($ip)) {
            $this->deny_request('IP is blocked', 403, $ip);
        }

        if (empty($this->settings['bot_rate_limit_enabled'])) {
            return;
        }

        if ($this->should_skip_throttle()) {
            return;
        }

        $limit = (int) ($this->settings['bot_rate_limit_per_minute'] ?? 60);
        $block_seconds = max(60, (int) ($this->settings['bot_block_minutes'] ?? 15) * MINUTE_IN_SECONDS);

        $subject = 'traffic:' . $ip;
        if (!$this->rate_limit->allow_with_policy($subject, $limit, 60, $block_seconds)) {
            $this->apply_global_block($ip, $block_seconds);
            $this->deny_request('Bot rate limit exceeded', 429, $ip);
        }
    }

    public function handle_404_scan(): void {
        if (!is_404()) {
            return;
        }

        $ip = $this->ip_whitelist->get_request_ip();
        if ($this->ip_whitelist->is_allowed($ip)) {
            return;
        }

        $threshold = (int) ($this->settings['scan_404_threshold'] ?? 20);
        $scan_key = 'secure_guard_404_scans_' . md5($ip);
        $count = (int) get_transient($scan_key);
        $count++;
        set_transient($scan_key, $count, 10 * MINUTE_IN_SECONDS);

        if ($count >= $threshold) {
            $this->apply_global_block($ip, DAY_IN_SECONDS);
            $endpoint = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
            $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
            $this->logs->log($endpoint, $method, 'BLOCKED', 'Too many 404 scans', ['ip' => $ip, 'count' => $count]);
        }
    }

    private function should_skip_throttle(): bool {
        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }

        if (is_user_logged_in() && current_user_can('manage_options')) {
            return true;
        }

        if (defined('DOING_CRON') && DOING_CRON) {
            return true;
        }

        return false;
    }

    private function is_globally_blocked(string $ip): bool {
        $row = $this->limits->get('ip-block:' . $ip);
        if (!$row || empty($row['blocked_until'])) {
            return false;
        }

        return (strtotime((string) $row['blocked_until']) ?: 0) > time();
    }

    private function apply_global_block(string $ip, int $seconds): void {
        $now = time();
        $this->limits->upsert('ip-block:' . $ip, gmdate('Y-m-d H:i:s', $now), 1, gmdate('Y-m-d H:i:s', $now + $seconds));
    }

    private function deny_request(string $reason, int $status, string $ip): void {
        $endpoint = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $this->logs->log($endpoint, $method, 'BLOCKED', $reason, ['ip' => $ip]);

        status_header($status);
        wp_die(esc_html__('Forbidden', 'secure-guard'), esc_html__('Forbidden', 'secure-guard'), ['response' => $status]);
    }

    private function is_sensitive_path_request(): bool {
        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $path = strtolower((string) (parse_url($request_uri, PHP_URL_PATH) ?: ''));
        $sensitive = ['wp-config.php', '/.env', '/.git', '/wp-content/debug.log'];

        foreach ($sensitive as $needle) {
            if (str_contains($path, $needle)) {
                return true;
            }
        }

        return false;
    }
}
