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
        remove_action('wp_head', 'feed_links', 2);
        remove_action('wp_head', 'feed_links_extra', 3);
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'wp_shortlink_wp_head', 10);
        remove_action('wp_head', 'rest_output_link_wp_head', 10);
        remove_action('template_redirect', 'rest_output_link_header', 11);
        remove_action('wp_head', 'wp_oembed_add_discovery_links');
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
        $exact = [
            '/readme.html',
            '/wp/readme.html',
            '/license.txt',
            '/wp/license.txt',
            '/wp-config.php',
            '/wp-config-sample.php',
            '/wp-content/debug.log',
            '/app/debug.log',
            '/phpinfo.php',
            '/info.php',
        ];

        $is_probe_path = in_array($path, $exact, true);
        if (!$is_probe_path && preg_match('#/(db|database|backup|dump)[^/]*\.(sql|zip|gz|tar|bz2)$#i', $path) === 1) {
            $is_probe_path = true;
        }

        // Catch debug.log and error_log at any installation path (standard, Bedrock, custom).
        if (!$is_probe_path && (str_ends_with($path, '/debug.log') || $path === '/debug.log'
            || str_ends_with($path, '/error_log') || $path === '/error_log')) {
            $is_probe_path = true;
        }

        // Catch XML-RPC at any path depth.
        if (!$is_probe_path && str_ends_with($path, '/xmlrpc.php')) {
            $is_probe_path = true;
        }

        if (!$is_probe_path) {
            return;
        }

        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $this->logs->log($path, $method, 'BLOCKED', 'WordPress fingerprint probe blocked', []);

        status_header(403);
        wp_die(esc_html__('Forbidden', 'secure-guard'), esc_html__('Forbidden', 'secure-guard'), ['response' => 403]);
    }
}
