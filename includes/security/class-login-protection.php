<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Login_Protection {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;
    private Secure_Guard_Rate_Limit_Repository $limits;
    private Secure_Guard_IP_Whitelist $ip_whitelist;
    private Secure_Guard_Reputation_Engine $reputation;
    private ?Secure_Guard_Alert_Manager $alert_manager;

    public function __construct(
        array $settings,
        Secure_Guard_Log_Repository $logs,
        Secure_Guard_Rate_Limit_Repository $limits,
        Secure_Guard_IP_Whitelist $ip_whitelist,
        Secure_Guard_Reputation_Engine $reputation,
        ?Secure_Guard_Alert_Manager $alert_manager = null
    ) {
        $this->settings = $settings;
        $this->logs = $logs;
        $this->limits = $limits;
        $this->ip_whitelist = $ip_whitelist;
        $this->reputation = $reputation;
        $this->alert_manager = $alert_manager;
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

        // Reputation check
        if ($this->reputation->get_tier($ip) === Secure_Guard_Reputation_Engine::TIER_BLOCKED) {
            $this->deny_login($ip, 'Blocked by reputation');
        }

        $blocked_until = $this->get_blocked_until('login-block:' . $ip);
        if ($blocked_until > time()) {
            $this->deny_login($ip, 'Login temporarily blocked');
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

        // Feed into reputation engine
        $this->reputation->add_score($ip, 20, 'Failed login attempt');

        $count_key = 'secure_guard_login_fails_' . md5($ip);
        $fails = (int) get_transient($count_key);
        $fails++;
        set_transient($count_key, $fails, DAY_IN_SECONDS);

        // Distributed brute force detection
        $global_fail_key = 'secure_guard_global_fails_' . md5(sanitize_user($username));
        $global_fails = (int) get_transient($global_fail_key);
        $global_fails++;
        set_transient($global_fail_key, $global_fails, 5 * MINUTE_IN_SECONDS);

        if ($global_fails >= 10) {
            $this->logs->log('/wp-login.php', 'POST', 'BLOCKED', 'Distributed brute force detected', ['username' => $username]);
            // Could trigger a temporary global lock or stricter limits here
        }

        $this->logs->log('/wp-login.php', 'POST', 'FAILED', 'Failed login', ['ip' => $ip, 'username' => sanitize_user($username, true), 'fail_count' => $fails]);

        // Configurable ban durations
        $ban_hours = (int) ($this->settings['login_ban_hours'] ?? 2);
        
        $short_threshold = (int) ($this->settings['login_short_threshold'] ?? 5);
        $medium_threshold = (int) ($this->settings['login_medium_threshold'] ?? 10);
        $hard_threshold = (int) ($this->settings['login_hard_block_threshold'] ?? 20);

        if ($fails >= $hard_threshold) {
            $duration = max(DAY_IN_SECONDS, $ban_hours * 12 * HOUR_IN_SECONDS);
            $this->apply_block('login-block:' . $ip, $duration);
            $this->apply_block('ip-block:' . $ip, $duration);
            
            if ($this->alert_manager !== null) {
                $this->alert_manager->notify_ip_blocked($ip, 'Too many failed logins (hard block)', gmdate('Y-m-d H:i:s', time() + $duration));
            }

            delete_transient('sg_dashboard_stats');
            return;
        }

        if ($fails >= $medium_threshold) {
            $this->apply_block('login-block:' . $ip, $ban_hours * HOUR_IN_SECONDS);
            return;
        }

        if ($fails >= $short_threshold) {
            $this->apply_block('login-block:' . $ip, max(600, ($ban_hours * HOUR_IN_SECONDS) / 6));
        }
    }

    public function record_successful_login(string $user_login, WP_User $user): void {
        if (empty($this->settings['login_protection_enabled'])) {
            return;
        }

        $ip = $this->ip_whitelist->get_request_ip();
        $count_key = 'secure_guard_login_fails_' . md5($ip);
        delete_transient($count_key);

        // Reputation bonus
        $this->reputation->add_score($ip, -10, 'Successful login bonus');

        $this->logs->log('/wp-login.php', 'POST', 'ALLOWED', 'Successful login', ['ip' => $ip, 'username' => sanitize_user($user_login, true), 'user_id' => (int) $user->ID]);
    }

    public function show_login_warnings(string $message): string {
        if (empty($this->settings['login_protection_enabled'])) {
            return $message;
        }

        $ip = $this->ip_whitelist->get_request_ip();
        if ($this->ip_whitelist->is_allowed($ip)) {
            return $message;
        }

        $count_key = 'secure_guard_login_fails_' . md5($ip);
        $fails = (int) get_transient($count_key);
        if ($fails <= 0) {
            return $message;
        }

        $short_threshold = (int) ($this->settings['login_short_threshold'] ?? 5);
        $remaining = $short_threshold - $fails;

        if ($remaining > 0 && $remaining <= 3) {
            $warning = sprintf(
                '<div class="notice notice-warning inline"><p>%s</p></div>',
                sprintf(esc_html__('Caution: %d attempts remaining before temporary lockout.', 'wp-secure-guard'), $remaining)
            );
            return $warning . $message;
        }

        return $message;
    }

    public function inject_login_script(): void {
        if (empty($this->settings['login_protection_enabled'])) {
            return;
        }

        $ip = $this->ip_whitelist->get_request_ip();
        if ($this->ip_whitelist->is_allowed($ip)) {
            return;
        }

        $count_key = 'secure_guard_login_fails_' . md5($ip);
        $fails = (int) get_transient($count_key);
        if ($fails <= 0) {
            return;
        }

        $short_threshold = (int) ($this->settings['login_short_threshold'] ?? 5);
        $remaining = $short_threshold - $fails;

        if ($remaining > 0 && $remaining <= 3) {
            ?>
            <style>
                #sg-login-toast {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: #fff;
                    border-left: 4px solid #f0b849;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    padding: 15px 20px;
                    border-radius: 4px;
                    z-index: 9999;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    animation: sg-toast-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
                    font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;
                }
                @keyframes sg-toast-in {
                    from { transform: translateX(120%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                .sg-toast-icon { color: #f0b849; font-size: 20px; }
                .sg-toast-content { font-size: 13px; color: #1d2327; line-height: 1.4; }
                .sg-toast-close { cursor: pointer; color: #c3c4c7; margin-left: 10px; font-size: 18px; }
                .sg-toast-close:hover { color: #d63638; }
            </style>
            <div id="sg-login-toast">
                <div class="sg-toast-icon">⚠️</div>
                <div class="sg-toast-content">
                    <strong><?php esc_html_e('Security Warning', 'wp-secure-guard'); ?></strong><br>
                    <?php printf(esc_html__('You have %d login attempts remaining before a lockout.', 'wp-secure-guard'), $remaining); ?>
                </div>
                <div class="sg-toast-close" onclick="this.parentElement.remove()">&times;</div>
            </div>
            <script>
                setTimeout(function() {
                    var toast = document.getElementById('sg-login-toast');
                    if (toast) {
                        toast.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                        toast.style.opacity = '0';
                        toast.style.transform = 'translateX(20px)';
                        setTimeout(function() { toast.remove(); }, 500);
                    }
                }, 8000);
            </script>
            <?php
        }
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

    private function deny_login(string $ip, string $reason): void {
        $this->logs->log('/wp-login.php', 'POST', 'BLOCKED', $reason, ['ip' => $ip]);
        status_header(429);
        wp_die(esc_html__('Too many failed login attempts. Try again later.', 'wp-secure-guard'), esc_html__('Login blocked', 'wp-secure-guard'), ['response' => 429]);
    }
}
