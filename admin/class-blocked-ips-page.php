<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Blocked_IPs_Page {
    private const PER_PAGE = 25;

    private Secure_Guard_Rate_Limit_Repository $limits;

    public function __construct(Secure_Guard_Rate_Limit_Repository $limits) {
        $this->limits = $limits;
    }

    public function register(): void {
        add_action('admin_post_sg_unblock_ip',       [$this, 'handle_unblock']);
        add_action('admin_post_sg_block_ip_manual',  [$this, 'handle_block_manual']);
    }

    public function handle_unblock(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }
        check_admin_referer('sg_unblock_ip');

        $ip = sanitize_text_field((string) ($_POST['ip'] ?? ''));
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            $subject = 'ip-block:' . $ip;
            $this->limits->delete_block($subject);
            // Also clear the login-specific block so wp-login.php is unblocked immediately.
            $this->limits->delete_block('login-block:' . $ip);
            // Clear per-IP transient caches for both block subjects.
            delete_transient('sg_iblk_' . substr(md5($subject), 0, 16));
            delete_transient('sg_iblk_' . substr(md5('login-block:' . $ip), 0, 16));
            // Clear the login fail-count transient so the threshold resets.
            delete_transient('secure_guard_login_fails_' . md5($ip));
        }

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-blocked-ips&unblocked=1'));
        exit;
    }

    public function handle_block_manual(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }
        check_admin_referer('sg_block_ip_manual');

        $ip    = sanitize_text_field((string) ($_POST['ip'] ?? ''));
        $hours = max(1, min(8760, (int) ($_POST['duration_hours'] ?? 24)));

        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            $now           = time();
            $blocked_until = gmdate('Y-m-d H:i:s', $now + ($hours * HOUR_IN_SECONDS));
            $this->limits->upsert('ip-block:' . $ip, gmdate('Y-m-d H:i:s', $now), 1, $blocked_until);
            // Prime the transient cache so the block takes effect immediately.
            $cache_key = 'sg_iblk_' . substr(md5('ip-block:' . $ip), 0, 16);
            set_transient($cache_key, 1, $hours * HOUR_IN_SECONDS);
        }

        // Return to the page that triggered the action (logs or blocked IPs).
        $referer = wp_get_referer();
        wp_safe_redirect($referer ?: admin_url('admin.php?page=secure-guard-blocked-ips'));
        exit;
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        $current_page = max(1, (int) ($_GET['paged'] ?? 1));
        $offset       = ($current_page - 1) * self::PER_PAGE;
        $total        = $this->limits->count_active_ip_blocks();
        $blocks       = $this->limits->get_active_blocks(self::PER_PAGE, $offset);
        $base_url     = admin_url('admin.php?page=secure-guard-blocked-ips');

        echo '<div class="wrap secure-guard-ui">';
        echo '<h1>' . esc_html__('Blocked IPs', 'secure-guard') . '</h1>';
        echo '<p class="description">' . esc_html__('Currently active IP blocks imposed by bot rate limiting, login protection, or 404 scan detection. Unblocking removes the block immediately without waiting for expiry.', 'secure-guard') . '</p>';

        if (!empty($_GET['unblocked'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('IP unblocked successfully.', 'secure-guard') . '</p></div>';
        }

        echo '<div class="card" style="max-width:900px;padding:16px;">';
        echo '<p style="margin-top:0;color:#646970;">' . sprintf(esc_html__('%d active block(s)', 'secure-guard'), $total) . '</p>';

        if ($blocks === []) {
            echo '<p><em>' . esc_html__('No active IP blocks.', 'secure-guard') . '</em></p>';
            echo '</div></div>';
            return;
        }

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th>' . esc_html__('IP Address', 'secure-guard') . '</th>';
        echo '<th>' . esc_html__('Blocked Since (UTC)', 'secure-guard') . '</th>';
        echo '<th>' . esc_html__('Expires (UTC)', 'secure-guard') . '</th>';
        echo '<th style="width:120px;">' . esc_html__('Action', 'secure-guard') . '</th>';
        echo '</tr></thead>';
        echo '<tbody>';

        foreach ($blocks as $row) {
            $subject       = (string) $row['subject'];
            $ip            = str_starts_with($subject, 'ip-block:') ? substr($subject, strlen('ip-block:')) : $subject;
            $blocked_since = (string) ($row['window_started_at'] ?? '');
            $blocked_until = (string) ($row['blocked_until'] ?? '');

            echo '<tr>';
            echo '<td><code>' . esc_html($ip) . '</code></td>';
            echo '<td style="font-size:12px;">' . esc_html($blocked_since) . '</td>';
            echo '<td style="font-size:12px;">' . esc_html($blocked_until) . '</td>';
            echo '<td>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" onsubmit="return confirm(\'' . esc_js(__('Unblock this IP address?', 'secure-guard')) . '\')">';
            echo '<input type="hidden" name="action" value="sg_unblock_ip" />';
            echo '<input type="hidden" name="ip" value="' . esc_attr($ip) . '" />';
            wp_nonce_field('sg_unblock_ip');
            submit_button(__('Unblock', 'secure-guard'), 'delete small', '', false);
            echo '</form>';
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
                echo '<a class="button" href="' . esc_url(add_query_arg('paged', $current_page - 1, $base_url)) . '">&laquo; ' . esc_html__('Previous', 'secure-guard') . '</a>';
            }
            echo '<span>' . sprintf(esc_html__('Page %1$d of %2$d', 'secure-guard'), $current_page, $total_pages) . '</span>';
            if ($current_page < $total_pages) {
                echo '<a class="button" href="' . esc_url(add_query_arg('paged', $current_page + 1, $base_url)) . '">' . esc_html__('Next', 'secure-guard') . ' &raquo;</a>';
            }
            echo '</div></div>';
        }

        echo '</div></div>';
    }
}
