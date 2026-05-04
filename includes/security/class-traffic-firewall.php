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
    private ?Secure_Guard_Alert_Manager $alert_manager;

    public function __construct(
        array $settings,
        Secure_Guard_Log_Repository $logs,
        Secure_Guard_Rate_Limit $rate_limit,
        Secure_Guard_Rate_Limit_Repository $limits,
        Secure_Guard_IP_Whitelist $ip_whitelist,
        ?Secure_Guard_Alert_Manager $alert_manager = null
    ) {
        $this->settings = $settings;
        $this->logs = $logs;
        $this->rate_limit = $rate_limit;
        $this->limits = $limits;
        $this->ip_whitelist = $ip_whitelist;
        $this->alert_manager = $alert_manager;
    }

    public function handle_request(): void {
        $ip = $this->ip_whitelist->get_request_ip();

        if ($this->is_public_wp_cron_request()) {
            $this->deny_request('Public wp-cron blocked', 403, $ip);
        }

        if ($this->is_sensitive_path_request()) {
            $this->deny_request('Sensitive path blocked', 403, $ip);
        }

        if ($this->is_bad_bot()) {
            $this->deny_request('Malicious User-Agent blocked', 403, $ip);
        }

        if ($this->ip_whitelist->is_allowed($ip)) {
            return;
        }

        if ($this->is_globally_blocked($ip)) {
            $this->deny_request('IP is blocked', 403, $ip);
        }

        // IDS: reject common injection and probing patterns for unauthenticated requests.
        // Skipped for logged-in users, WP-CLI, DOING_AJAX, DOING_CRON, and REST requests.
        if (!$this->should_skip_throttle() && $this->is_malicious_request()) {
            $this->deny_request('Malicious request pattern detected', 403, $ip);
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
            $this->apply_global_block($ip, $block_seconds, 'Bot rate limit exceeded');
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
            $this->apply_global_block($ip, DAY_IN_SECONDS, 'Too many 404 scans');
            $endpoint = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
            $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
            $this->logs->log($endpoint, $method, 'BLOCKED', 'Too many 404 scans', ['ip' => $ip, 'count' => $count]);
        }
    }

    private function should_skip_throttle(): bool {
        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }

        // All authenticated users bypass the bot rate limiter — editors, authors, and
        // contributors using page builders or the media library must never be throttled.
        if (is_user_logged_in()) {
            return true;
        }

        if (defined('DOING_CRON') && DOING_CRON) {
            return true;
        }

        // Skip for AJAX and REST requests to avoid rate-limiting internal WP operations.
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return true;
        }

        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }

        return false;
    }

    private function is_globally_blocked(string $ip): bool {
        // Use a short-lived transient to avoid a DB SELECT on every request.
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

    private function apply_global_block(string $ip, int $seconds, string $reason = 'Firewall block'): void {
        $now = time();
        $expires_at = gmdate('Y-m-d H:i:s', $now + $seconds);
        $this->limits->upsert('ip-block:' . $ip, gmdate('Y-m-d H:i:s', $now), 1, $expires_at);
        // Prime the transient immediately so subsequent requests are denied without a DB read.
        $cache_key = 'sg_iblk_' . substr(md5('ip-block:' . $ip), 0, 16);
        set_transient($cache_key, 1, $seconds);

        if ($this->alert_manager !== null) {
            $this->alert_manager->notify_ip_blocked($ip, $reason, $expires_at);
        }
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
        // Uses str_contains so 'debug.log' matches /anything/debug.log regardless of
        // installation layout (standard /wp-content/, Bedrock /app/, custom paths).
        $sensitive = ['wp-config.php', '/.env', '/.git', 'debug.log', '/error_log'];

        foreach ($sensitive as $needle) {
            if (str_contains($path, $needle)) {
                return true;
            }
        }

        // Block XML-RPC at any path depth (handles Bedrock /wp/xmlrpc.php and custom structures).
        if (!empty($this->settings['block_xmlrpc'])) {
            if (str_ends_with($path, '/xmlrpc.php') || in_array($path, ['/xmlrpc.php', '/wp/xmlrpc.php'], true)) {
                return true;
            }
        }

        return false;
    }

    private function is_public_wp_cron_request(): bool {
        if (empty($this->settings['block_public_wp_cron'])) {
            return false;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $path = strtolower((string) (parse_url($request_uri, PHP_URL_PATH) ?: ''));
        if (!in_array($path, ['/wp-cron.php', '/wp/wp-cron.php'], true)) {
            return false;
        }

        if ($this->is_internal_cron_request()) {
            return false;
        }

        return true;
    }

    private function is_internal_cron_request(): bool {
        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }

        if (defined('DOING_CRON') && DOING_CRON) {
            return true;
        }

        if (is_user_logged_in() && current_user_can('manage_options')) {
            return true;
        }

        $remote_addr = sanitize_text_field((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        $server_addr = sanitize_text_field((string) ($_SERVER['SERVER_ADDR'] ?? ''));
        if ($remote_addr !== '' && ($remote_addr === $server_addr || in_array($remote_addr, ['127.0.0.1', '::1'], true))) {
            return true;
        }

        return false;
    }

    /**
     * Checks the raw REQUEST_URI (after percent-decoding) for common attack signatures.
     * Covers path traversal, SQL injection, XSS, and OS command injection patterns.
     * Only called for non-whitelisted, unauthenticated requests (guarded by should_skip_throttle).
     */
    private function is_malicious_request(): bool {
        // Decode percent-encoding to catch obfuscated attacks (%2e%2e%2f = ../).
        $uri = strtolower(rawurldecode((string) ($_SERVER['REQUEST_URI'] ?? '')));
        $patterns = [
            // Path traversal
            '../', '%2e%2e/', '%2e%2e%2f',
            // XSS
            '<script', '</script', 'javascript:', 'onerror=', 'onload=',
            // SQL injection
            'union select', 'information_schema', 'load_file(', 'into outfile',
            'concat(', 'group_concat(', 'sleep(', 'benchmark(',
            'drop table', 'insert into',
            // PHP code execution
            'base64_decode(', 'eval(',
            'system(', 'exec(', 'passthru(', 'shell_exec(',
            // Server probing
            '/proc/self/environ',
        ];

        foreach ($patterns as $pattern) {
            if (str_contains($uri, $pattern)) {
                return true;
            }
        }

        return false;
    }

    private function is_bad_bot(): bool {
        if (empty($this->settings['block_bad_bots'])) {
            return false;
        }

        $ua = strtolower(sanitize_text_field((string) ($_SERVER['HTTP_USER_AGENT'] ?? '')));
        if ($ua === '') {
            return false; // Empty UA is common for some APIs, maybe don't block by default.
        }

        $bad_bots = [
            'ahrefsbot', 'blexbot', 'dotbot', 'mj12bot', 'rogerbot', 'semrushbot',
            'petalbot', 'python-requests', 'libwww-perl', 'go-http-client',
            'guzzlehttp', 'scrapy', 'headlesschrome', 'zgrab', 'masscan', 'nmap', 'sqlmap',
            'havij', 'pangolin', 'nikto', 'dirbuster', 'w3af', 'acunetix', 'absent',
            'blackwidow', 'custom-get-url', 'emailcollector', 'emailwolf', 'extract',
            'eyeblaster', 'fhscan', 'flaming', 'getright', 'getweb', 'httrack',
            'interget', 'linksmanager', 'offline', 'prowebwalker', 'rogue',
            'scanalert', 'superbot', 'teleport', 'vci', 'webcopy', 'webstripper',
            'webzip', 'zeus',
        ];

        foreach ($bad_bots as $bot) {
            if (str_contains($ua, $bot)) {
                return true;
            }
        }

        return false;
    }
}
