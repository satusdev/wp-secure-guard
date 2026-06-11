<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Reputation_Page {
    private const PER_PAGE = 25;
    private Secure_Guard_Rate_Limit_Repository $limits;
    private Secure_Guard_Reputation_Engine $reputation;

    public function __construct(Secure_Guard_Rate_Limit_Repository $limits, Secure_Guard_Reputation_Engine $reputation) {
        $this->limits = $limits;
        $this->reputation = $reputation;
    }

    public function register(): void {
        add_action('admin_post_sg_reset_reputation', [$this, 'handle_reset_reputation']);
    }

    public function handle_reset_reputation(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('sg_reset_reputation');

        $ip = sanitize_text_field(wp_unslash((string) ($_POST['ip'] ?? '')));
        if ($ip !== '' && (filter_var($ip, FILTER_VALIDATE_IP) || str_contains($ip, ':'))) {
            $this->limits->reset_reputation('rep:' . $ip);
            delete_transient('sg_rep_' . md5($ip));
        }

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-reputation&reset=1'));
        exit;
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $current_page = max(1, (int) wp_unslash($_GET['paged'] ?? 1));
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $search_ip    = sanitize_text_field(wp_unslash((string) ($_GET['s'] ?? '')));
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $tier_filter  = sanitize_key(wp_unslash((string) ($_GET['tier'] ?? '')));
        
        $offset       = ($current_page - 1) * self::PER_PAGE;
        $settings = Secure_Guard_Config::get_settings();
        $total = $this->limits->count_reputations($search_ip, $tier_filter, $settings);
        $rows = $this->limits->list_reputations($search_ip, $tier_filter, $settings, self::PER_PAGE, $offset);

        echo '<div class="wrap secure-guard-ui">';
        echo '<h1>' . esc_html__('IP Reputation Dashboard', 'wp-secure-guard') . '</h1>';
        echo '<p class="description">' . esc_html__('Manage behavioral security scores. High scores trigger automatic challenges, throttling, or blocks.', 'wp-secure-guard') . '</p>';

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['reset'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Reputation reset successfully.', 'wp-secure-guard') . '</p></div>';
        }

        // Filter Bar
        echo '<div style="margin:20px 0; display:flex; gap:12px; align-items:center; flex-wrap:wrap;">';
        echo '<form method="get" action="' . esc_url(admin_url('admin.php')) . '">';
        echo '<input type="hidden" name="page" value="secure-guard-reputation" />';
        echo '<input type="text" name="s" value="' . esc_attr($search_ip) . '" placeholder="Search IP..." class="regular-text" style="width:200px;" />';
        echo ' <select name="tier">';
        echo '<option value="">' . esc_html__('All Tiers', 'wp-secure-guard') . '</option>';
        foreach (['blocked' => 'Blocked', 'challenged' => 'Challenged', 'throttled' => 'Throttled', 'normal' => 'Normal'] as $v => $l) {
            echo '<option value="' . esc_attr($v) . '" ' . selected($tier_filter, $v, false) . '>' . esc_html($l) . '</option>';
        }
        echo '</select>';
        echo ' <button type="submit" class="button">' . esc_html__('Filter', 'wp-secure-guard') . '</button>';
        if ($search_ip !== '' || $tier_filter !== '') {
            echo ' <a href="' . esc_url(admin_url('admin.php?page=secure-guard-reputation')) . '" class="button button-link">' . esc_html__('Clear', 'wp-secure-guard') . '</a>';
        }
        echo '</form>';
        echo '</div>';

        echo '<div class="card" style="max-width:1000px;padding:16px;">';
        
        if (empty($rows)) {
            echo '<p><em>' . esc_html__('No IPs found matching the current filters.', 'wp-secure-guard') . '</em></p>';
            echo '</div></div>';
            return;
        }

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th>' . esc_html__('IP Address', 'wp-secure-guard') . '</th>';
        echo '<th>' . esc_html__('Reputation Score', 'wp-secure-guard') . '</th>';
        echo '<th>' . esc_html__('Current Tier', 'wp-secure-guard') . '</th>';
        echo '<th style="width:180px;">' . esc_html__('Actions', 'wp-secure-guard') . '</th>';
        echo '</tr></thead>';
        echo '<tbody>';

        foreach ($rows as $row) {
            $subject = (string) $row['subject'];
            $ip = str_starts_with($subject, 'rep:') ? substr($subject, strlen('rep:')) : $subject;
            $score = (int) $row['reputation_score'];
            $tier = $this->reputation->get_tier($ip);

            $tier_class = 'sg-pill--allowed';
            if ($tier === Secure_Guard_Reputation_Engine::TIER_BLOCKED) $tier_class = 'sg-pill--blocked';
            elseif ($tier === Secure_Guard_Reputation_Engine::TIER_THROTTLED) $tier_class = 'sg-pill--warning';
            elseif ($tier === Secure_Guard_Reputation_Engine::TIER_CHALLENGED) $tier_class = 'sg-pill--info';

            echo '<tr>';
            echo '<td><code>' . esc_html($ip) . '</code></td>';
            echo '<td><strong>' . esc_html((string) $score) . '</strong> / 100</td>';
            echo '<td><span class="sg-pill ' . esc_attr($tier_class) . '">' . esc_html(strtoupper($tier)) . '</span></td>';
            echo '<td>';
            echo '<div class="sg-action-row">';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" onsubmit="return confirm(\'' . esc_js(__('Reset reputation for this IP?', 'wp-secure-guard')) . '\')">';
            echo '<input type="hidden" name="action" value="sg_reset_reputation" />';
            echo '<input type="hidden" name="ip" value="' . esc_attr($ip) . '" />';
            wp_nonce_field('sg_reset_reputation');
            echo '<button type="submit" class="button button-small">' . esc_html__('Reset', 'wp-secure-guard') . '</button>';
            echo '</form>';
            echo '<a class="button button-small" href="' . esc_url(admin_url('admin.php?page=secure-guard-logs&filter_ip=' . rawurlencode($ip))) . '">' . esc_html__('Logs', 'wp-secure-guard') . '</a>';
            echo '</div>';
            echo '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';

        // Pagination
        $total_pages = ceil($total / self::PER_PAGE);
        if ($total_pages > 1) {
            echo '<div class="tablenav bottom"><div class="tablenav-pages">';
            echo paginate_links([
                'base'      => add_query_arg('paged', '%#%'),
                'format'    => '',
                'prev_text' => esc_html__('&laquo; Previous', 'wp-secure-guard'),
                'next_text' => esc_html__('Next &raquo;', 'wp-secure-guard'),
                'total'     => (int) $total_pages,
                'current'   => (int) $current_page,
            ]);
            echo '</div></div>';
        }

        echo '</div></div>';
    }
}
