<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Login_Protection {
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

    public function guard_login_request(): void {
        if (empty($this->settings['login_protection_enabled'])) {
            return;
        }

        if (!$this->is_login_request()) {
            return;
        }

        $ip = $this->ip_whitelist->get_request_ip();
        if ($this->ip_whitelist->is_allowed($ip)) {
            return;
        }

        $blocked_until = $this->get_blocked_until('login-block:' . $ip);
        if ($blocked_until > time()) {
            $this->logs->log('/wp-login.php', 'POST', 'BLOCKED', 'Login temporarily blocked', ['ip' => $ip, 'blocked_until' => gmdate('c', $blocked_until)]);
            status_header(429);
            wp_die(esc_html__('Too many failed login attempts. Try again later.', 'secure-guard'), esc_html__('Login blocked', 'secure-guard'), ['response' => 429]);
        }
    }

    public function record_failed_login(string $username): void {
        if (empty($this->settings['login_protection_enabled'])) {
            return;
        }

        $ip = $this->ip_whitelist->get_request_ip();
        if ($this->ip_whitelist->is_allowed($ip)) {
            return;
        }

        $count_key = 'secure_guard_login_fails_' . md5($ip);
        $fails = (int) get_transient($count_key);
        $fails++;
        set_transient($count_key, $fails, DAY_IN_SECONDS);

        $this->logs->log('/wp-login.php', 'POST', 'FAILED', 'Failed login', ['ip' => $ip, 'username' => sanitize_user($username, true), 'fail_count' => $fails]);

        $short_threshold = (int) ($this->settings['login_short_threshold'] ?? 5);
        $medium_threshold = (int) ($this->settings['login_medium_threshold'] ?? 10);
        $hard_threshold = (int) ($this->settings['login_hard_block_threshold'] ?? 20);

        if ($fails >= $hard_threshold) {
            $this->apply_block('login-block:' . $ip, DAY_IN_SECONDS);
            $this->apply_block('ip-block:' . $ip, DAY_IN_SECONDS);
            return;
        }

        if ($fails >= $medium_threshold) {
            $this->apply_block('login-block:' . $ip, HOUR_IN_SECONDS);
            return;
        }

        if ($fails >= $short_threshold) {
            $this->apply_block('login-block:' . $ip, 10 * MINUTE_IN_SECONDS);
        }
    }

    public function record_successful_login(string $user_login, WP_User $user): void {
        if (empty($this->settings['login_protection_enabled'])) {
            return;
        }

        $ip = $this->ip_whitelist->get_request_ip();
        $count_key = 'secure_guard_login_fails_' . md5($ip);
        delete_transient($count_key);

        $this->logs->log('/wp-login.php', 'POST', 'ALLOWED', 'Successful login', ['ip' => $ip, 'username' => sanitize_user($user_login, true), 'user_id' => (int) $user->ID]);
    }

    private function is_login_request(): bool {
        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? ''));
        $path = (string) (parse_url($request_uri, PHP_URL_PATH) ?: '');

        if (str_contains($path, '/wp-login.php')) {
            return true;
        }

        return (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST);
    }

    private function get_blocked_until(string $subject): int {
        $row = $this->limits->get($subject);
        if (!$row || empty($row['blocked_until'])) {
            return 0;
        }

        return (int) (strtotime((string) $row['blocked_until']) ?: 0);
    }

    private function apply_block(string $subject, int $seconds): void {
        $now = time();
        $this->limits->upsert($subject, gmdate('Y-m-d H:i:s', $now), 1, gmdate('Y-m-d H:i:s', $now + $seconds));
    }
}
