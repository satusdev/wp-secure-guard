<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Blocked_IPs_Page {
    private const PER_PAGE = 25;

    private Secure_Guard_Rate_Limit_Repository $limits;
    private Secure_Guard_Log_Repository $logs;

    public function __construct(Secure_Guard_Rate_Limit_Repository $limits, Secure_Guard_Log_Repository $logs) {
        $this->limits = $limits;
        $this->logs = $logs;
    }

    public function register(): void {
        add_action('admin_post_sg_unblock_ip',       [$this, 'handle_unblock']);
        add_action('admin_post_sg_unblock_login_ip', [$this, 'handle_unblock_login_only']);
        add_action('admin_post_sg_bulk_unblock_ips', [$this, 'handle_bulk_unblock']);
        add_action('admin_post_sg_unblock_all_login_blocks', [$this, 'handle_unblock_all_login_blocks']);
        add_action('admin_post_sg_block_ip_manual',  [$this, 'handle_block_manual']);
    }

    public function handle_unblock(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('sg_unblock_ip');

        $ip = sanitize_text_field(wp_unslash((string) ($_POST['ip'] ?? '')));
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->unblock_ip($ip, true);
            $this->log_admin_action('Manual IP unblock', $ip, ['mode' => 'all']);
        }

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-blocked-ips&unblocked=1'));
        exit;
    }

    public function handle_unblock_login_only(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('sg_unblock_login_ip');

        $ip = sanitize_text_field(wp_unslash((string) ($_POST['ip'] ?? '')));
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->unblock_login_only($ip);
            $this->log_admin_action('Manual login lockout cleared', $ip, ['mode' => 'login-only']);
        }

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-blocked-ips&login_unblocked=1'));
        exit;
    }

    public function handle_bulk_unblock(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('sg_bulk_unblock_ips');

        $mode = sanitize_key(wp_unslash((string) ($_POST['bulk_mode'] ?? 'all')));
        $subjects = isset($_POST['subjects']) && is_array($_POST['subjects']) ? wp_unslash($_POST['subjects']) : [];
        $changed = 0;

        foreach ($subjects as $raw_subject) {
            $subject = sanitize_text_field((string) $raw_subject);
            if (!str_starts_with($subject, 'ip-block:') && !str_starts_with($subject, 'login-block:')) {
                continue;
            }

            $ip = str_replace(['ip-block:', 'login-block:'], '', $subject);
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }

            if ($mode === 'login-only') {
                $this->unblock_login_only($ip);
            } else {
                $this->unblock_ip($ip, true);
            }
            $this->log_admin_action('Bulk IP unblock', $ip, ['mode' => $mode]);
            $changed++;
        }

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-blocked-ips&bulk_unblocked=' . $changed));
        exit;
    }

    public function handle_unblock_all_login_blocks(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('sg_unblock_all_login_blocks');

        $blocks = $this->limits->get_active_blocks_by_prefix('login-block:', 5000);
        $changed = 0;
        foreach ($blocks as $row) {
            $subject = (string) ($row['subject'] ?? '');
            $ip = str_starts_with($subject, 'login-block:') ? substr($subject, strlen('login-block:')) : '';
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
                $this->unblock_login_only($ip);
                $this->log_admin_action('Bulk login lockout cleared', $ip, ['mode' => 'login-only']);
                $changed++;
            }
        }

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-blocked-ips&login_bulk_unblocked=' . $changed));
        exit;
    }

    public function handle_block_manual(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('sg_block_ip_manual');

        $ip    = sanitize_text_field(wp_unslash((string) ($_POST['ip'] ?? '')));
        $hours = max(1, min(8760, (int) wp_unslash($_POST['duration_hours'] ?? 24)));

        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            $now           = time();
            $blocked_until = gmdate('Y-m-d H:i:s', $now + ($hours * HOUR_IN_SECONDS));
            $this->limits->upsert('ip-block:' . $ip, gmdate('Y-m-d H:i:s', $now), 1, $blocked_until);
            // Prime the transient cache so the block takes effect immediately.
            $cache_key = 'sg_iblk_' . substr(md5('ip-block:' . $ip), 0, 16);
            set_transient($cache_key, 1, $hours * HOUR_IN_SECONDS);
            $this->invalidate_runtime_caches();
            $this->log_admin_action('Manual IP block', $ip, ['duration_hours' => $hours]);
        }

        // Return to the page that triggered the action (logs or blocked IPs).
        $referer = wp_get_referer();
        wp_safe_redirect($referer ?: admin_url('admin.php?page=secure-guard-blocked-ips'));
        exit;
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $current_page = max(1, (int) wp_unslash($_GET['paged'] ?? 1));
        $offset       = ($current_page - 1) * self::PER_PAGE;
        $total        = $this->limits->count_active_ip_blocks();
        $blocks       = $this->limits->get_active_blocks(self::PER_PAGE, $offset);
        $base_url     = admin_url('admin.php?page=secure-guard-blocked-ips');

        echo '<div class="wrap secure-guard-ui">';
        echo '<h1>' . esc_html__('Blocked IPs', 'wp-secure-guard') . '</h1>';
        echo '<p class="description">' . esc_html__('Currently active IP blocks imposed by bot rate limiting, login protection, or 404 scan detection. Unblocking removes the block immediately without waiting for expiry.', 'wp-secure-guard') . '</p>';

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['unblocked'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('IP unblocked successfully.', 'wp-secure-guard') . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['login_unblocked'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Login lockout cleared successfully.', 'wp-secure-guard') . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['bulk_unblocked'])) {
            // translators: %d: number of blocks
            echo '<div class="notice notice-success is-dismissible"><p>' . sprintf(esc_html__('%d selected block(s) processed.', 'wp-secure-guard'), (int) wp_unslash($_GET['bulk_unblocked'])) . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['login_bulk_unblocked'])) {
            // translators: %d: number of lockouts
            echo '<div class="notice notice-success is-dismissible"><p>' . sprintf(esc_html__('%d login lockout(s) cleared.', 'wp-secure-guard'), (int) wp_unslash($_GET['login_bulk_unblocked'])) . '</p></div>';
        }

        // ── quick unlock tool ───────────────────────────────────────────
        echo '<div class="card" style="max-width:900px;padding:16px;margin-bottom:16px;">';
        echo '<h2 style="margin-top:0;font-size:16px;">' . esc_html__('Quick Unlock', 'wp-secure-guard') . '</h2>';
        echo '<p class="description">' . esc_html__('Enter an IP address to immediately clear all associated blocks and reset their failure count.', 'wp-secure-guard') . '</p>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:flex;gap:8px;align-items:center;margin-top:12px;">';
        echo '<input type="hidden" name="action" value="sg_unblock_ip" />';
        wp_nonce_field('sg_unblock_ip');
        echo '<input type="text" name="ip" class="regular-text" placeholder="e.g. 1.2.3.4" required />';
        submit_button(__('Unlock IP', 'wp-secure-guard'), 'primary', 'submit', false);
        echo '</form></div>';

        echo '<div class="card" style="max-width:900px;padding:16px;margin-bottom:16px;">';
        echo '<h2 style="margin-top:0;font-size:16px;">' . esc_html__('False Positive Recovery', 'wp-secure-guard') . '</h2>';
        echo '<p class="description">' . esc_html__('If real admins are locked out after failed logins, clear only login lockouts first. Firewall blocks remain in place.', 'wp-secure-guard') . '</p>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline-block;margin-right:8px;">';
        echo '<input type="hidden" name="action" value="sg_unblock_all_login_blocks" />';
        wp_nonce_field('sg_unblock_all_login_blocks');
        submit_button(__('Clear All Login Lockouts', 'wp-secure-guard'), 'secondary', 'submit', false, ['onclick' => 'return confirm(\'' . esc_js(__('Clear every active login lockout?', 'wp-secure-guard')) . '\')']);
        echo '</form>';
        echo '<a class="button" href="' . esc_url(admin_url('admin.php?page=secure-guard-assistant')) . '">' . esc_html__('Open Security Assistant', 'wp-secure-guard') . '</a>';
        echo '</div>';

        echo '<div class="card" style="max-width:900px;padding:16px;">';
        echo '<p style="margin-top:0;color:#646970;">' . sprintf(esc_html__('%d active block(s) detected', 'wp-secure-guard'), $total) . '</p>';

        if ($blocks === []) {
            echo '<p><em>' . esc_html__('No active IP blocks.', 'wp-secure-guard') . '</em></p>';
            echo '</div></div>';
            return;
        }

        echo '<form id="sg-bulk-unblock-form" method="post" action="' . esc_url(admin_url('admin-post.php')) . '" class="sg-action-row" style="margin:0 0 12px;">';
        echo '<input type="hidden" name="action" value="sg_bulk_unblock_ips" />';
        wp_nonce_field('sg_bulk_unblock_ips');
        echo '<select name="bulk_mode">';
        echo '<option value="all">' . esc_html__('Unblock selected IPs completely', 'wp-secure-guard') . '</option>';
        echo '<option value="login-only">' . esc_html__('Clear selected login lockouts only', 'wp-secure-guard') . '</option>';
        echo '</select>';
        submit_button(__('Apply to Selected', 'wp-secure-guard'), 'secondary', 'submit', false, ['onclick' => 'return confirm(\'' . esc_js(__('Apply the selected unblock action?', 'wp-secure-guard')) . '\')']);
        echo '</form>';

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th style="width:36px;"><input type="checkbox" class="sg-select-all" aria-label="' . esc_attr__('Select all active blocks', 'wp-secure-guard') . '" /></th>';
        echo '<th>' . esc_html__('IP Address', 'wp-secure-guard') . '</th>';
        echo '<th>' . esc_html__('Type', 'wp-secure-guard') . '</th>';
        echo '<th>' . esc_html__('Why Blocked', 'wp-secure-guard') . '</th>';
        echo '<th>' . esc_html__('Blocked Since (UTC)', 'wp-secure-guard') . '</th>';
        echo '<th>' . esc_html__('Expires (UTC)', 'wp-secure-guard') . '</th>';
        echo '<th style="width:100px;">' . esc_html__('Action', 'wp-secure-guard') . '</th>';
        echo '</tr></thead>';
        echo '<tbody>';

        foreach ($blocks as $row) {
            $subject       = (string) $row['subject'];
            $type          = str_starts_with($subject, 'login-block:') ? 'Login' : 'Firewall';
            $ip            = str_replace(['ip-block:', 'login-block:'], '', $subject);
            $blocked_since = (string) ($row['window_started_at'] ?? '');
            $blocked_until = (string) ($row['blocked_until'] ?? '');
            $reasons       = $this->logs->recent_reasons_by_ip($ip, 2);

            echo '<tr>';
            echo '<td><input type="checkbox" class="sg-row-selector" form="sg-bulk-unblock-form" name="subjects[]" value="' . esc_attr($subject) . '" /></td>';
            echo '<td><code>' . esc_html($ip) . '</code></td>';
            echo '<td><span class="sg-pill ' . ($type === 'Login' ? 'sg-pill--info' : 'sg-pill--blocked') . '">' . esc_html($type) . '</span></td>';
            echo '<td style="font-size:12px;">';
            if ($reasons === []) {
                echo esc_html__('No related log retained.', 'wp-secure-guard');
            } else {
                foreach ($reasons as $reason) {
                    echo '<div>' . esc_html((string) ($reason['reason'] ?? '')) . '</div>';
                }
            }
            echo '</td>';
            echo '<td style="font-size:12px;">' . esc_html($blocked_since) . '</td>';
            echo '<td style="font-size:12px;">' . esc_html($blocked_until) . '</td>';
            echo '<td>';
            echo '<div class="sg-action-row">';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" onsubmit="return confirm(\'' . esc_js(__('Unblock this IP address?', 'wp-secure-guard')) . '\')">';
            echo '<input type="hidden" name="action" value="sg_unblock_ip" />';
            echo '<input type="hidden" name="ip" value="' . esc_attr($ip) . '" />';
            wp_nonce_field('sg_unblock_ip');
            submit_button(__('Unblock', 'wp-secure-guard'), 'delete small', '', false);
            echo '</form>';
            if ($type === 'Login') {
                echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" onsubmit="return confirm(\'' . esc_js(__('Clear only this login lockout?', 'wp-secure-guard')) . '\')">';
                echo '<input type="hidden" name="action" value="sg_unblock_login_ip" />';
                echo '<input type="hidden" name="ip" value="' . esc_attr($ip) . '" />';
                wp_nonce_field('sg_unblock_login_ip');
                submit_button(__('Login only', 'wp-secure-guard'), 'secondary small', '', false);
                echo '</form>';
            }
            echo '</div>';
            echo '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';

        // Pagination
        $total_pages = max(1, (int) ceil($total / self::PER_PAGE));
        if ($total_pages > 1) {
            echo '<div class="tablenav bottom" style="margin-top:12px;">';
            echo '<div class="tablenav-pages" style="display:flex;align-items:center;gap:8px;">';
            if ($current_page > 1) {
                echo '<a class="button" href="' . esc_url(add_query_arg('paged', $current_page - 1, $base_url)) . '">&laquo; ' . esc_html__('Previous', 'wp-secure-guard') . '</a>';
            }
            // translators: 1: current page, 2: total pages
            echo '<span>' . sprintf(esc_html__('Page %1$d of %2$d', 'wp-secure-guard'), (int) $current_page, (int) $total_pages) . '</span>';
            if ($current_page < $total_pages) {
                echo '<a class="button" href="' . esc_url(add_query_arg('paged', $current_page + 1, $base_url)) . '">' . esc_html__('Next', 'wp-secure-guard') . ' &raquo;</a>';
            }
            echo '</div></div>';
        }

        echo '</div></div>';

        echo '<script>(function(){var master=document.querySelector(".sg-select-all");if(!master){return;}master.addEventListener("change",function(){document.querySelectorAll(".sg-row-selector").forEach(function(box){box.checked=master.checked;});});})();</script>';
    }

    private function unblock_ip(string $ip, bool $include_login): void {
        $subject = 'ip-block:' . $ip;
        $this->limits->delete_block($subject);
        $this->clear_block_transient($subject);

        if ($include_login) {
            $this->unblock_login_only($ip);
        }

        $this->invalidate_runtime_caches();
    }

    private function unblock_login_only(string $ip): void {
        $subject = 'login-block:' . $ip;
        $this->limits->delete_block($subject);
        $this->clear_block_transient($subject);
        delete_transient('secure_guard_login_fails_' . md5($ip));
        $this->invalidate_runtime_caches();
    }

    private function clear_block_transient(string $subject): void {
        delete_transient('sg_iblk_' . substr(md5($subject), 0, 16));
    }

    private function invalidate_runtime_caches(): void {
        delete_transient('sg_dashboard_stats');
        delete_transient('sg_attack_velocity');
    }

    private function log_admin_action(string $reason, string $ip, array $context = []): void {
        $context['ip'] = $ip;
        $context['user_id'] = get_current_user_id();
        $this->logs->log('/wp-admin/admin.php?page=secure-guard-blocked-ips', 'POST', 'ALLOWED', $reason, $context);
    }
}
