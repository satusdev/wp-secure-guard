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
}
