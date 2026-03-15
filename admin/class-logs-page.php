<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Logs_Page {
    private Secure_Guard_Log_Repository $logs;
    private const PER_PAGE = 25;

    public function __construct(Secure_Guard_Log_Repository $logs) {
        $this->logs = $logs;
    }

    public function register(): void {
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        $current_page  = max(1, (int) ($_GET['paged'] ?? 1));
        $result_filter = strtoupper(sanitize_key((string) ($_GET['result'] ?? '')));
        if (!in_array($result_filter, ['BLOCKED', 'ALLOWED', 'FAILED', ''], true)) {
            $result_filter = '';
        }
        $ip_filter = sanitize_text_field((string) ($_GET['filter_ip'] ?? ''));
        $date_from = sanitize_text_field((string) ($_GET['date_from'] ?? ''));
        $date_to   = sanitize_text_field((string) ($_GET['date_to'] ?? ''));
        // Discard values that don’t match YYYY-MM-DD to prevent injection via prepare().
        if ($date_from !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date_from)) {
            $date_from = '';
        }
        if ($date_to !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date_to)) {
            $date_to = '';
        }

        $offset  = ($current_page - 1) * self::PER_PAGE;
        $total   = $this->logs->count_filtered($result_filter, $ip_filter, $date_from, $date_to);
        $entries = $this->logs->recent_filtered(self::PER_PAGE, $offset, $result_filter, $ip_filter, $date_from, $date_to);

        $base_url = admin_url('admin.php?page=secure-guard-logs');

        echo '<div class="wrap secure-guard-ui">';
        echo '<h1>' . esc_html__('Logs', 'secure-guard') . '</h1>';
        echo '<p class="description">' . esc_html__('Security and API decisions. ALLOWED = token/auth checks passed; WordPress may still return rest_no_route if the endpoint is unregistered.', 'secure-guard') . '</p>';

        // Filter bar
        $filter_args = ['filter_ip' => $ip_filter, 'date_from' => $date_from, 'date_to' => $date_to];
        echo '<form method="get" action="' . esc_url(admin_url('admin.php')) . '" style="margin-bottom:12px;">';
        echo '<input type="hidden" name="page" value="secure-guard-logs" />';
        echo '<div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;">';
        echo '<strong>' . esc_html__('Result:', 'secure-guard') . '</strong>';
        foreach (['' => __('All', 'secure-guard'), 'BLOCKED' => __('Blocked', 'secure-guard'), 'ALLOWED' => __('Allowed', 'secure-guard'), 'FAILED' => __('Failed', 'secure-guard')] as $val => $text) {
            $is_active = $result_filter === strtoupper($val);
            echo '<a href="' . esc_url(add_query_arg(array_merge($filter_args, ['result' => strtolower($val), 'paged' => 1]), $base_url)) . '"'
                . ' class="button button-small' . ($is_active ? ' button-primary' : '') . '">'
                . esc_html($text) . '</a>';
        }
        echo '<span style="color:#646970;margin-left:4px;">' . sprintf(esc_html__('%d entries', 'secure-guard'), $total) . '</span>';
        echo '<span style="margin-left:12px;"><label>' . esc_html__('IP:', 'secure-guard') . ' ';
        echo '<input type="text" name="filter_ip" value="' . esc_attr($ip_filter) . '" placeholder="1.2.3.4" style="width:130px;" /></label></span>';
        echo '<span><label>' . esc_html__('From:', 'secure-guard') . ' ';
        echo '<input type="date" name="date_from" value="' . esc_attr($date_from) . '" style="width:140px;" /></label></span>';
        echo '<span><label>' . esc_html__('To:', 'secure-guard') . ' ';
        echo '<input type="date" name="date_to" value="' . esc_attr($date_to) . '" style="width:140px;" /></label></span>';
        echo '<input type="hidden" name="result" value="' . esc_attr(strtolower($result_filter)) . '" />';
        echo '<button type="submit" class="button button-small">' . esc_html__('Apply', 'secure-guard') . '</button>';
        if ($ip_filter !== '' || $date_from !== '' || $date_to !== '') {
            echo ' <a class="button button-small" href="' . esc_url(add_query_arg(['result' => strtolower($result_filter), 'paged' => 1], $base_url)) . '">' . esc_html__('Clear filters', 'secure-guard') . '</a>';
        }
        echo '</div></form>';

        echo '<div class="card" style="max-width:1400px;padding:16px;">';

        if ($entries === []) {
            echo '<p><em>' . esc_html__('No log entries match the current filter.', 'secure-guard') . '</em></p>';
            echo '</div></div>';
            return;
        }

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        echo '<th style="width:60px;">ID</th>';
        echo '<th style="width:150px;">' . esc_html__('Time (UTC)', 'secure-guard') . '</th>';
        echo '<th style="width:120px;">' . esc_html__('IP', 'secure-guard') . '</th>';
        echo '<th style="width:70px;">' . esc_html__('Method', 'secure-guard') . '</th>';
        echo '<th>' . esc_html__('Endpoint', 'secure-guard') . '</th>';
        echo '<th style="width:90px;">' . esc_html__('Result', 'secure-guard') . '</th>';
        echo '<th>' . esc_html__('Reason', 'secure-guard') . '</th>';
        echo '<th style="width:120px;">' . esc_html__('Details', 'secure-guard') . '</th>';
        echo '</tr></thead>';
        echo '<tbody>';

        foreach ($entries as $entry) {
            $result     = strtoupper((string) $entry['result']);
            $is_blocked = $result === 'BLOCKED';
            $is_failed  = $result === 'FAILED';
            $row_ip     = (string) ($entry['ip'] ?? '');

            $pill_class = 'sg-pill--allowed';
            if ($is_blocked) {
                $pill_class = 'sg-pill--blocked';
            } elseif ($is_failed) {
                $pill_class = 'sg-pill--warning';
            }

            echo '<tr>';
            echo '<td>' . esc_html((string) $entry['id']) . '</td>';
            echo '<td style="white-space:nowrap;font-size:12px;">' . esc_html((string) $entry['created_at']) . '</td>';
            echo '<td><code>' . esc_html($row_ip) . '</code></td>';
            echo '<td><span class="sg-method-badge">' . esc_html(strtoupper((string) $entry['method'])) . '</span></td>';
            echo '<td style="word-break:break-all;max-width:300px;font-size:12px;">' . esc_html((string) $entry['endpoint']) . '</td>';
            echo '<td><span class="sg-pill ' . $pill_class . '">' . esc_html($result) . '</span></td>';
            echo '<td style="font-size:12px;">' . esc_html((string) $entry['reason']) . '</td>';

            // Context column — decode JSON and render as expandable detail block.
            $ctx_raw  = (string) ($entry['context'] ?? '');
            $ctx_data = $ctx_raw !== '' ? json_decode($ctx_raw, true) : null;
            if (is_array($ctx_data) && $ctx_data !== []) {
                echo '<td style="font-size:11px;">';
                echo '<details><summary style="cursor:pointer;color:#2271b1;">' . esc_html__('view', 'secure-guard') . '</summary>';
                echo '<dl style="margin:4px 0;padding:0;">';
                foreach ($ctx_data as $k => $v) {
                    if ($k === 'ip') {
                        continue;
                    }
                    echo '<dt style="font-weight:600;color:#646970;">' . esc_html((string) $k) . '</dt>';
                    $v_display = is_scalar($v)
                        ? esc_html((string) $v)
                        : '<code>' . esc_html(wp_json_encode($v)) . '</code>';
                    // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                    echo '<dd style="margin:0 0 2px 8px;">' . $v_display . '</dd>';
                }
                echo '</dl></details>';
                // Inline Block IP button for blocked/failed rows
                if (($is_blocked || $is_failed) && $row_ip !== '') {
                    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:4px;">';
                    echo '<input type="hidden" name="action" value="sg_block_ip_manual" />';
                    echo '<input type="hidden" name="ip" value="' . esc_attr($row_ip) . '" />';
                    echo '<input type="hidden" name="duration_hours" value="24" />';
                    wp_nonce_field('sg_block_ip_manual');
                    echo '<button type="submit" class="button button-small" style="color:#a00;border-color:#a00;"'
                        . ' onclick="return confirm(\'' . esc_js(sprintf(__('Block %s for 24 hours?', 'secure-guard'), $row_ip)) . '\')">' . esc_html__('Block IP', 'secure-guard') . '</button>';
                    echo '</form>';
                }
                echo '</td>';
            } elseif (($is_blocked || $is_failed) && $row_ip !== '') {
                // No context but still show Block IP form
                echo '<td style="font-size:11px;">';
                echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
                echo '<input type="hidden" name="action" value="sg_block_ip_manual" />';
                echo '<input type="hidden" name="ip" value="' . esc_attr($row_ip) . '" />';
                echo '<input type="hidden" name="duration_hours" value="24" />';
                wp_nonce_field('sg_block_ip_manual');
                echo '<button type="submit" class="button button-small" style="color:#a00;border-color:#a00;"'
                    . ' onclick="return confirm(\'' . esc_js(sprintf(__('Block %s for 24 hours?', 'secure-guard'), $row_ip)) . '\')">' . esc_html__('Block IP', 'secure-guard') . '</button>';
                echo '</form></td>';
            } else {
                echo '<td></td>';
            }

            echo '</tr>';
        }

        echo '</tbody></table>';

        // Pagination
        $total_pages = max(1, (int) ceil($total / self::PER_PAGE));
        if ($total_pages > 1) {
            $page_args = ['result' => strtolower($result_filter), 'filter_ip' => $ip_filter, 'date_from' => $date_from, 'date_to' => $date_to];
            echo '<div class="tablenav bottom" style="margin-top:12px;">';
            echo '<div class="tablenav-pages" style="display:flex;align-items:center;gap:8px;">';
            if ($current_page > 1) {
                echo '<a class="button" href="' . esc_url(add_query_arg(array_merge($page_args, ['paged' => $current_page - 1]), $base_url)) . '">'
                    . '&laquo; ' . esc_html__('Previous', 'secure-guard') . '</a>';
            }
            echo '<span class="paging-input">'
                . sprintf(esc_html__('Page %1$d of %2$d', 'secure-guard'), $current_page, $total_pages)
                . '</span>';
            if ($current_page < $total_pages) {
                echo '<a class="button" href="' . esc_url(add_query_arg(array_merge($page_args, ['paged' => $current_page + 1]), $base_url)) . '">'
                    . esc_html__('Next', 'secure-guard') . ' &raquo;</a>';
            }
            echo '</div></div>';
        }

        echo '</div></div>';
    }
}
