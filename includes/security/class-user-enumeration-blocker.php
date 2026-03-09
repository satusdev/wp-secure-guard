<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_User_Enumeration_Blocker {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;

    public function __construct(array $settings, Secure_Guard_Log_Repository $logs) {
        $this->settings = $settings;
        $this->logs = $logs;
    }

    public function block_author_enumeration(): void {
        if (empty($this->settings['block_user_enumeration'])) {
            return;
        }

        if (!isset($_GET['author'])) {
            return;
        }

        $endpoint = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $this->logs->log($endpoint, $method, 'BLOCKED', 'User enumeration attempt', []);

        status_header(403);
        wp_die(esc_html__('Forbidden', 'secure-guard'), esc_html__('Forbidden', 'secure-guard'), ['response' => 403]);
    }
}
