<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_WP_Hardening {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;

    public function __construct(array $settings, Secure_Guard_Log_Repository $logs) {
        $this->settings = $settings;
        $this->logs = $logs;
    }

    public function register(): void {
        if (empty($this->settings['hide_wp_info'])) {
            return;
        }

        remove_action('wp_head', 'wp_generator');
        remove_action('admin_head', 'wp_generator');
    }

    public function hide_generator(string $generator): string {
        if (empty($this->settings['hide_wp_info'])) {
            return $generator;
        }

        return '';
    }

    public function strip_version_query_arg(string $src): string {
        if (empty($this->settings['hide_wp_info'])) {
            return $src;
        }

        return (string) remove_query_arg('ver', $src);
    }

    public function block_probe_files(): void {
        if (empty($this->settings['hide_wp_info'])) {
            return;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? ''));
        $path = strtolower((string) (parse_url($request_uri, PHP_URL_PATH) ?: ''));
        if (!in_array($path, ['/readme.html', '/license.txt'], true)) {
            return;
        }

        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $this->logs->log($path, $method, 'BLOCKED', 'WordPress fingerprint probe blocked', []);

        status_header(403);
        wp_die(esc_html__('Forbidden', 'secure-guard'), esc_html__('Forbidden', 'secure-guard'), ['response' => 403]);
    }
}
