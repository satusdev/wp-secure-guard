<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Logs_Page {
    private Secure_Guard_Log_Repository $logs;

    public function __construct(Secure_Guard_Log_Repository $logs) {
        $this->logs = $logs;
    }

    public function register(): void {
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        $entries = $this->logs->recent(300);
        echo '<div class="wrap secure-guard-ui">';
        echo '<h1>' . esc_html__('Logs', 'secure-guard') . '</h1>';
        echo '<p class="description">' . esc_html__('Recent security and API decisions. ALLOWED means token/auth checks passed; WordPress may still return rest_no_route if the endpoint is not registered.', 'secure-guard') . '</p>';

        echo '<div class="card" style="max-width:1200px;padding:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('Recent Events', 'secure-guard') . '</h2>';
        if ($entries === []) {
            echo '<p><em>' . esc_html__('No log entries yet.', 'secure-guard') . '</em></p>';
            echo '</div>';
            echo '</div>';
            return;
        }

        echo '<table class="widefat striped">';
        echo '<thead><tr><th>ID</th><th>Time (UTC)</th><th>IP</th><th>Method</th><th>Endpoint</th><th>Result</th><th>Reason</th></tr></thead>';
        echo '<tbody>';
        foreach ($entries as $entry) {
            echo '<tr>';
            echo '<td>' . esc_html((string) $entry['id']) . '</td>';
            echo '<td>' . esc_html((string) $entry['created_at']) . '</td>';
            echo '<td>' . esc_html((string) $entry['ip']) . '</td>';
            echo '<td>' . esc_html((string) $entry['method']) . '</td>';
            echo '<td>' . esc_html((string) $entry['endpoint']) . '</td>';
            echo '<td>' . esc_html((string) $entry['result']) . '</td>';
            echo '<td>' . esc_html((string) $entry['reason']) . '</td>';
            echo '</tr>';
        }
        echo '</tbody>';
        echo '</table>';
        echo '</div>';
        echo '</div>';
    }
}
