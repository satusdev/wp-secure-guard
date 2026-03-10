<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_XMLRPC_Protector {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;

    public function __construct(array $settings, Secure_Guard_Log_Repository $logs) {
        $this->settings = $settings;
        $this->logs = $logs;
    }

    public function xmlrpc_enabled(bool $enabled): bool {
        if (empty($this->settings['block_xmlrpc'])) {
            return $enabled;
        }

        $endpoint = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/xmlrpc.php'));
        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'POST'));
        $this->logs->log($endpoint, $method, 'BLOCKED', 'XML-RPC disabled', []);

        return false;
    }

    public function block_direct_request(): void {
        if (empty($this->settings['block_xmlrpc'])) {
            return;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $path = strtolower((string) (parse_url($request_uri, PHP_URL_PATH) ?: '/'));
        if (!in_array($path, ['/xmlrpc.php', '/wp/xmlrpc.php'], true)) {
            return;
        }

        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'POST'));
        $this->logs->log($path, $method, 'BLOCKED', 'XML-RPC request blocked', []);

        status_header(403);
        wp_die(esc_html__('Forbidden', 'secure-guard'), esc_html__('Forbidden', 'secure-guard'), ['response' => 403]);
    }
}
