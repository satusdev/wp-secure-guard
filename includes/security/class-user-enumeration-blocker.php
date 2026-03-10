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

        if (is_user_logged_in() && current_user_can('list_users')) {
            return;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $path = strtolower((string) (parse_url($request_uri, PHP_URL_PATH) ?: '/'));

        $reason = '';
        if (isset($_GET['author'])) {
            $reason = 'User enumeration via author query blocked';
        } elseif ($path === '/author' || str_starts_with($path, '/author/')) {
            $reason = 'User enumeration via author archive blocked';
        } elseif (isset($_GET['rest_route'])) {
            $rest_route = strtolower((string) wp_unslash($_GET['rest_route']));
            if ($rest_route === '/wp/v2/users' || str_starts_with($rest_route, '/wp/v2/users/')) {
                $reason = 'User enumeration via rest_route blocked';
            }
        }

        if ($reason === '') {
            return;
        }

        $this->logs->log($request_uri, $method, 'BLOCKED', $reason, []);

        status_header(403);
        wp_die(esc_html__('Forbidden', 'secure-guard'), esc_html__('Forbidden', 'secure-guard'), ['response' => 403]);
    }
}
