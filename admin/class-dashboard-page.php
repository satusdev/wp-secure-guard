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

    public function register(): void {
        add_action('admin_post_sg_refresh_dashboard_stats', [$this, 'handle_refresh_stats']);
    }

    public function handle_refresh_stats(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('sg_refresh_dashboard_stats');
        delete_transient('sg_dashboard_stats');
        wp_safe_redirect(admin_url('admin.php?page=secure-guard&refreshed=1'));
        exit;
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        // Cache expensive COUNT queries for 5 minutes.
        $stats = get_transient('sg_dashboard_stats');
        if (!is_array($stats)) {
            $stats = [
                'blocked_ips'   => $this->limits->count_active_blocks('ip-block:%'),
                'failed_logins' => $this->logs->count_by_reason('Failed login'),
                'api_requests'  => $this->logs->count_endpoint_prefix('/wp-json'),
                'active_tokens' => $this->tokens->count_active(),
                'clusters'      => $this->logs->get_cluster_summary(24),
                '_cached_at'    => time(),
            ];
            set_transient('sg_dashboard_stats', $stats, 5 * MINUTE_IN_SECONDS);
        }

        $blocked_ips      = (int) ($stats['blocked_ips'] ?? 0);
        $failed_logins    = (int) ($stats['failed_logins'] ?? 0);
        $api_requests     = (int) ($stats['api_requests'] ?? 0);
        $active_tokens    = (int) ($stats['active_tokens'] ?? 0);
        $cached_at        = (int) ($stats['_cached_at'] ?? 0);
        $integrity_alerts     = (int) get_transient('secure_guard_integrity_alert_count');
        $users_endpoint_ready = $this->users_collection_endpoint_available();
        $settings        = Secure_Guard_Config::get_settings();
        $preset_label    = Secure_Guard_Security_Presets::label(Secure_Guard_Security_Presets::detect($settings));
        $lock_data       = get_transient('sg_lock_state');
        if (!is_array($lock_data)) {
            $lock_data = get_option('secure_guard_lock_state', []);
        }
        if (is_array($lock_data) && isset($lock_data['expires']) && (int) $lock_data['expires'] <= time()) {
            $lock_data = [];
        }
        $tokens_url      = admin_url('admin.php?page=secure-guard-tokens');
        $assistant_url   = admin_url('admin.php?page=secure-guard-assistant');
        $logs_url        = admin_url('admin.php?page=secure-guard-logs');
        $settings_url    = admin_url('admin.php?page=secure-guard-settings');
        $rules_url       = admin_url('admin.php?page=secure-guard-rules');
        $blocked_ips_url = admin_url('admin.php?page=secure-guard-blocked-ips');
        $whitelists_url  = admin_url('admin.php?page=secure-guard-whitelists');
        $refresh_url     = wp_nonce_url(admin_url('admin-post.php?action=sg_refresh_dashboard_stats'), 'sg_refresh_dashboard_stats');

        $cached_label = '';
        if ($cached_at > 0) {
            $age_min = (int) round((time() - $cached_at) / 60);
            if ($age_min <= 0) {
                $cached_label = esc_html__('cached just now', 'wp-secure-guard');
            } else {
                // translators: %d: number of minutes
                $cached_label = sprintf(esc_html__('cached %d min ago', 'wp-secure-guard'), $age_min);
            }
        }

        $last_scan = Secure_Guard_File_Integrity_Monitor::get_last_scan();

        echo '<div class="wrap secure-guard-ui">';
        echo '<div class="sg-page-header">';
        echo '<h1>' . esc_html__('Security Dashboard', 'wp-secure-guard') . '</h1>';
        echo '<div class="sg-header-actions">';
        echo '<a class="button button-primary" href="' . esc_url($assistant_url) . '">' . esc_html__('Security Assistant', 'wp-secure-guard') . '</a>';
        echo '<a class="button button-primary" href="' . esc_url($tokens_url) . '">' . esc_html__('Manage Tokens', 'wp-secure-guard') . '</a>';
        echo '<a class="button" href="' . esc_url($logs_url) . '">' . esc_html__('View Logs', 'wp-secure-guard') . '</a>';
        echo '<a class="button" href="' . esc_url($blocked_ips_url) . '">' . esc_html__('Blocked IPs', 'wp-secure-guard') . '</a>';
        echo '<a class="button" href="' . esc_url($whitelists_url) . '">' . esc_html__('Whitelists', 'wp-secure-guard') . '</a>';
        echo '<a class="button" href="' . esc_url($rules_url) . '">' . esc_html__('Security Rules', 'wp-secure-guard') . '</a>';
        echo '<a class="button" href="' . esc_url($settings_url) . '">' . esc_html__('Settings', 'wp-secure-guard') . '</a>';
        echo '</div>';
        if ($cached_label !== '') {
            echo '<span class="sg-header-meta">' . esc_html($cached_label) . ' &mdash; <a href="' . esc_url($refresh_url) . '">' . esc_html__('Refresh now', 'wp-secure-guard') . '</a></span>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['refreshed'])) {
            echo '<span style="color:#00a32a;font-size:12px;">' . esc_html__('Stats refreshed.', 'wp-secure-guard') . '</span>';
        }
        echo '</div>';

        // ── metric cards ────────────────────────────────────────────────
        echo '<div class="sg-metric-grid">';

        // Blocked IPs
        $card_mod = $blocked_ips > 0 ? ' sg-metric-card--alert' : ' sg-metric-card--ok';
        echo '<div class="sg-metric-card' . esc_attr($card_mod) . '">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-shield-alt"></span> ' . esc_html__('Blocked IPs', 'wp-secure-guard') . '</div>';
        echo '<div class="sg-metric-card__number">' . esc_html((string) $blocked_ips) . '</div>';
        echo '<div class="sg-metric-card__sub"><a href="' . esc_url($blocked_ips_url) . '">' . esc_html__('Manage blocked IPs', 'wp-secure-guard') . '</a></div>';
        echo '</div>';

        // Failed Logins
        $card_mod = $failed_logins > 0 ? ' sg-metric-card--alert' : ' sg-metric-card--ok';
        echo '<div class="sg-metric-card' . esc_attr($card_mod) . '">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-warning"></span> ' . esc_html__('Failed Logins', 'wp-secure-guard') . '</div>';
        echo '<div class="sg-metric-card__number">' . esc_html((string) $failed_logins) . '</div>';
        echo '<div class="sg-metric-card__sub"><a href="' . esc_url(add_query_arg(['result' => 'blocked'], $logs_url)) . '">' . esc_html__('View in logs', 'wp-secure-guard') . '</a></div>';
        echo '</div>';

        // API Requests
        echo '<div class="sg-metric-card">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-rest-api"></span> ' . esc_html__('API Requests Logged', 'wp-secure-guard') . '</div>';
        echo '<div class="sg-metric-card__number">' . esc_html((string) $api_requests) . '</div>';
        echo '<div class="sg-metric-card__sub"><a href="' . esc_url($logs_url) . '">' . esc_html__('Allowed and blocked /wp-json events in retained logs', 'wp-secure-guard') . '</a></div>';
        echo '</div>';

        // Active Tokens
        $card_mod = $active_tokens > 0 ? ' sg-metric-card--ok' : '';
        echo '<div class="sg-metric-card' . esc_attr($card_mod) . '">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-admin-network"></span> ' . esc_html__('Active Tokens', 'wp-secure-guard') . '</div>';
        echo '<div class="sg-metric-card__number">' . esc_html((string) $active_tokens) . '</div>';
        echo '<div class="sg-metric-card__sub"><a href="' . esc_url($tokens_url) . '">' . esc_html__('Manage tokens', 'wp-secure-guard') . '</a></div>';
        echo '</div>';

        // Integrity Alerts
        $card_mod = $integrity_alerts > 0 ? ' sg-metric-card--alert' : ' sg-metric-card--ok';
        echo '<div class="sg-metric-card' . esc_attr($card_mod) . '">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-media-code"></span> ' . esc_html__('Integrity Alerts', 'wp-secure-guard') . '</div>';
        echo '<div class="sg-metric-card__number">' . esc_html((string) $integrity_alerts) . '</div>';
        echo '<div class="sg-metric-card__sub">' . esc_html($integrity_alerts > 0 ? __('File changes detected', 'wp-secure-guard') : __('No changes detected', 'wp-secure-guard')) . '</div>';
        echo '</div>';

        // Last Integrity Scan
        echo '<div class="sg-metric-card">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-clock"></span> ' . esc_html__('Last Integrity Scan', 'wp-secure-guard') . '</div>';
        echo '<div class="sg-metric-card__number" style="font-size:14px;font-weight:600;">' . esc_html($last_scan ?: '—') . '</div>';
        echo '<div class="sg-metric-card__sub">' . esc_html__('UTC', 'wp-secure-guard') . '</div>';
        echo '</div>';

        echo '<div class="sg-metric-card sg-metric-card--ok">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-admin-settings"></span> ' . esc_html__('Current Preset', 'wp-secure-guard') . '</div>';
        echo '<div class="sg-metric-card__number" style="font-size:22px;">' . esc_html($preset_label) . '</div>';
        echo '<div class="sg-metric-card__sub"><a href="' . esc_url($assistant_url) . '">' . esc_html__('Review in Security Assistant', 'wp-secure-guard') . '</a></div>';
        echo '</div>';

        $lock_active = is_array($lock_data) && $lock_data !== [];
        echo '<div class="sg-metric-card' . ($lock_active ? ' sg-metric-card--alert' : ' sg-metric-card--ok') . '">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-lock"></span> ' . esc_html__('Lockdown State', 'wp-secure-guard') . '</div>';
        echo '<div class="sg-metric-card__number" style="font-size:22px;">' . esc_html($lock_active ? __('Active', 'wp-secure-guard') : __('Normal', 'wp-secure-guard')) . '</div>';
        echo '<div class="sg-metric-card__sub"><a href="' . esc_url($assistant_url) . '">' . esc_html__('Open lockdown controls', 'wp-secure-guard') . '</a></div>';
        echo '</div>';

        echo '</div>'; // .sg-metric-grid
        
        // ── attack clusters ─────────────────────────────────────────────
        $clusters = $stats['clusters'] ?? [];
        if (!empty($clusters)) {
            echo '<h2>' . esc_html__('Attack Vectors (Last 24h)', 'wp-secure-guard') . '</h2>';
            echo '<div class="sg-metric-grid">';
            foreach ($clusters as $c) {
                $cluster_name = str_replace('_', ' ', ucfirst((string) ($c['cluster'] ?? 'unknown')));
                echo '<div class="sg-metric-card">';
                echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-target"></span> ' . esc_html($cluster_name) . '</div>';
                echo '<div class="sg-metric-card__number">' . esc_html((string) $c['count']) . '</div>';
                echo '</div>';
            }
            echo '</div>';
        }

        if ($integrity_alerts > 0) {
            echo '<div class="notice notice-warning inline" style="margin:12px 0 0;padding:8px 12px;">';
            echo '<p><strong>' . esc_html__('File Integrity Alert', 'wp-secure-guard') . ':</strong> ';
            // translators: %d: number of file changes
            echo esc_html(sprintf(esc_html__('%d file change(s) detected since last baseline.', 'wp-secure-guard'), $integrity_alerts));
            echo ' <form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline;margin-left:8px;">';
            echo '<input type="hidden" name="action" value="sg_reset_integrity_baseline" />';
            wp_nonce_field('sg_reset_integrity_baseline');
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            submit_button(
                __('Reset Baseline Now', 'wp-secure-guard'),
                'small',
                '',
                false,
                ['onclick' => 'return confirm(\'' . esc_js(__('This clears the stored baseline. The next scan will re-baseline from the current state. Continue?', 'wp-secure-guard')) . '\')']
            );
            echo '</form></p>';
            echo '</div>';
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['baseline_reset'])) {
            echo '<div class="notice notice-success inline" style="margin:8px 0;padding:8px 12px;"><p>'
                . esc_html__('Baseline cleared. The next scheduled scan will re-baseline from the current file state.', 'wp-secure-guard')
                . '</p></div>';
        }

        // ── Users endpoint status ────────────────────────────────────────
        echo '<div class="sg-metric-grid" style="margin-top:20px;">';
        echo '<div class="sg-metric-card' . ($users_endpoint_ready ? ' sg-metric-card--ok' : '') . '" style="grid-column:1/-1;">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-admin-users"></span> ' . esc_html__('Users Endpoint Status', 'wp-secure-guard') . '</div>';
        if ($users_endpoint_ready) {
            echo '<div class="sg-metric-card__sub"><span class="sg-pill sg-pill--allowed">' . esc_html__('Ready', 'wp-secure-guard') . '</span> ' . esc_html__('/wp/v2/users supports GET and should respond for authorized requests.', 'wp-secure-guard') . '</div>';
        } else {
            echo '<div class="sg-metric-card__sub"><span class="sg-pill sg-pill--blocked">' . esc_html__('Missing', 'wp-secure-guard') . '</span> ' . esc_html__('/wp/v2/users GET route is not currently available.', 'wp-secure-guard') . '</div>';
        }
        echo '</div>';
        echo '</div>'; // .sg-metric-grid (users endpoint)

        // ── Quick Verification ──────────────────────────────────────────
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $show_curl = !empty($_GET['show_curl']) ? 'open' : '';
        echo '<details style="margin-top:20px;" ' . esc_attr($show_curl) . '>';
        echo '<summary style="cursor:pointer;font-size:14px;font-weight:600;color:var(--sg-primary);padding:4px 0;">';
        echo esc_html__('Quick Verification (curl examples)', 'wp-secure-guard');
        echo '</summary>';
        echo '<div class="card">';
        echo '<p class="description">' . esc_html__('Replace SITE and TOKEN with actual values. Without a token expect 403; with a valid token expect route-specific responses.', 'wp-secure-guard') . '</p>';
        echo '<pre style="white-space:pre-wrap;">' . esc_html("# Without token (expect 403 when REST lock is enabled)\ncurl -i https://SITE/wp-json/wp/v2/posts\n\n# With token\ncurl -i -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/posts\n\n# With token to sensitive route (requires full_api_access when enabled)\ncurl -i -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/users") . '</pre>';
        echo '</div></details>';

        // ── Documentation & Support ─────────────────────────────────────
        echo '<div class="sg-docs-dashboard card">';
        echo '<div style="font-size: 40px;"><span class="dashicons dashicons-book-alt" style="font-size: 40px; width: 40px; height: 40px; color: var(--sg-primary);"></span></div>';
        echo '<div>';
        echo '<h3 style="margin: 0 0 4px 0;">' . esc_html__('Need Help?', 'wp-secure-guard') . '</h3>';
        echo '<p style="margin: 0;">' . esc_html__('Check out our comprehensive documentation to learn more about JWT, REST security, and hardening features.', 'wp-secure-guard') . '</p>';
        echo '<a class="button button-secondary" style="margin-top: 10px;" href="' . esc_url(admin_url('admin.php?page=secure-guard-docs')) . '">' . esc_html__('View Documentation', 'wp-secure-guard') . '</a>';
        echo '</div>';
        echo '</div>';

        echo '</div>'; // .wrap
    }

    private function users_collection_endpoint_available(): bool {
        $cached = get_transient('sg_users_endpoint_avail');
        if ($cached !== false) {
            return (bool) $cached;
        }

        if (!function_exists('rest_get_server')) {
            set_transient('sg_users_endpoint_avail', 0, 5 * MINUTE_IN_SECONDS);
            return false;
        }

        $server = rest_get_server();
        if (!$server instanceof WP_REST_Server) {
            set_transient('sg_users_endpoint_avail', 0, 5 * MINUTE_IN_SECONDS);
            return false;
        }

        $routes     = $server->get_routes();
        $candidates = ['/wp/v2/users', '/wp/v2/users/(?P<id>[\\d]+)'];
        $result     = false;

        foreach ($candidates as $candidate) {
            if (!isset($routes[$candidate]) || !is_array($routes[$candidate])) {
                continue;
            }

            if ($this->route_supports_get($routes[$candidate])) {
                $result = true;
                break;
            }
        }

        set_transient('sg_users_endpoint_avail', $result ? 1 : 0, 5 * MINUTE_IN_SECONDS);
        return $result;
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
