<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Dashboard_Page {
    private Secure_Guard_Log_Repository $logs;
    private Secure_Guard_Token_Repository $tokens;
    private Secure_Guard_Rate_Limit_Repository $limits;

    public function __construct(Secure_Guard_Log_Repository $logs, Secure_Guard_Token_Repository $tokens, Secure_Guard_Rate_Limit_Repository $limits) {
        $this->logs = $logs;
        $this->tokens = $tokens;
        $this->limits = $limits;
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        $blocked_ips = $this->limits->count_active_blocks('ip-block:%');
        $failed_logins = $this->logs->count_by_reason('Failed login');
        $api_requests = $this->logs->count_endpoint_prefix('/wp-json');
        $active_tokens = $this->tokens->count_active();
        $integrity_alerts = (int) get_transient('secure_guard_integrity_alert_count');
        $tokens_url = admin_url('admin.php?page=secure-guard-tokens');
        $logs_url = admin_url('admin.php?page=secure-guard-logs');
        $settings_url = admin_url('admin.php?page=secure-guard-settings');
        $rules_url = admin_url('admin.php?page=secure-guard-rules');
        $users_endpoint_ready = $this->users_collection_endpoint_available();

        echo '<div class="wrap secure-guard-ui">';
        echo '<h1>' . esc_html__('Security Dashboard', 'secure-guard') . '</h1>';
        echo '<p class="description">' . esc_html__('Operational security metrics and quick verification shortcuts for Secure Guard.', 'secure-guard') . '</p>';

        echo '<div class="card" style="max-width:1100px;padding:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('Security Overview', 'secure-guard') . '</h2>';
        echo '<table class="widefat striped" style="max-width:100%;margin-top:8px;">';
        echo '<tbody>';
        echo '<tr><th>' . esc_html__('Blocked IPs', 'secure-guard') . '</th><td>' . esc_html((string) $blocked_ips) . '</td></tr>';
        echo '<tr><th>' . esc_html__('Failed Logins (logged)', 'secure-guard') . '</th><td>' . esc_html((string) $failed_logins) . '</td></tr>';
        echo '<tr><th>' . esc_html__('API Requests (logged)', 'secure-guard') . '</th><td>' . esc_html((string) $api_requests) . '</td></tr>';
        echo '<tr><th>' . esc_html__('Active Tokens', 'secure-guard') . '</th><td>' . esc_html((string) $active_tokens) . '</td></tr>';
        echo '<tr><th>' . esc_html__('Integrity Alerts', 'secure-guard') . '</th><td>' . esc_html((string) $integrity_alerts) . '</td></tr>';
        echo '<tr><th>' . esc_html__('Last Integrity Scan (UTC)', 'secure-guard') . '</th><td>' . esc_html(Secure_Guard_File_Integrity_Monitor::get_last_scan()) . '</td></tr>';
        echo '</tbody>';
        echo '</table>';

        echo '<p style="margin-top:12px;">';
        echo '<a class="button button-primary" href="' . esc_url($tokens_url) . '">' . esc_html__('Manage Tokens', 'secure-guard') . '</a> ';
        echo '<a class="button" href="' . esc_url($logs_url) . '">' . esc_html__('View Logs', 'secure-guard') . '</a> ';
        echo '<a class="button" href="' . esc_url($rules_url) . '">' . esc_html__('View Rules', 'secure-guard') . '</a> ';
        echo '<a class="button" href="' . esc_url($settings_url) . '">' . esc_html__('Open Settings', 'secure-guard') . '</a>';
        echo '</p>';
        echo '</div>';

        echo '<div class="card" style="max-width:1100px;padding:16px;margin-top:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('Users Endpoint Status', 'secure-guard') . '</h2>';
        if ($users_endpoint_ready) {
            echo '<p><span class="sg-pill" style="color:#0f5132;">' . esc_html__('Ready', 'secure-guard') . '</span> ' . esc_html__('/wp/v2/users supports GET and should respond for authorized requests.', 'secure-guard') . '</p>';
        } else {
            echo '<p><span class="sg-pill" style="color:#842029;">' . esc_html__('Missing', 'secure-guard') . '</span> ' . esc_html__('/wp/v2/users GET route is not currently available.', 'secure-guard') . '</p>';
            echo '<p class="description">' . esc_html__('If this persists, verify plugin deployment path and run a runtime reload.', 'secure-guard') . '</p>';
        }
        echo '</div>';

        echo '<div class="card" style="max-width:1100px;padding:16px;margin-top:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('Quick Verification', 'secure-guard') . '</h2>';
        echo '<p class="description">' . esc_html__('Use the examples below to validate API lock behavior. Replace TOKEN with a value from the Tokens page.', 'secure-guard') . '</p>';
        echo '<pre style="white-space:pre-wrap;">' . esc_html("# Without token (expect 403 when REST lock is enabled)\ncurl https://your-site.example/wp-json/wp/v2/posts\n\n# With token (expect route response if endpoint exists)\ncurl -H \"Authorization: Bearer TOKEN\" https://your-site.example/wp-json/wp/v2/posts") . '</pre>';
        echo '</div>';
        echo '</div>';
    }

    private function users_collection_endpoint_available(): bool {
        if (!function_exists('rest_get_server')) {
            return false;
        }

        $server = rest_get_server();
        if (!$server instanceof WP_REST_Server) {
            return false;
        }

        $routes = $server->get_routes();
        $candidates = ['/wp/v2/users', '/wp/v2/users/(?P<id>[\\d]+)'];

        foreach ($candidates as $candidate) {
            if (!isset($routes[$candidate]) || !is_array($routes[$candidate])) {
                continue;
            }

            if ($this->route_supports_get($routes[$candidate])) {
                return true;
            }
        }

        return false;
    }

    private function route_supports_get(array $route_config): bool {
        foreach ($route_config as $endpoint) {
            if (!is_array($endpoint) || !isset($endpoint['methods'])) {
                continue;
            }

            $methods = $endpoint['methods'];
            if (is_string($methods)) {
                if (stripos($methods, 'GET') !== false) {
                    return true;
                }
                continue;
            }

            if (is_array($methods) && in_array('GET', array_map('strtoupper', $methods), true)) {
                return true;
            }
        }

        return false;
    }
}
