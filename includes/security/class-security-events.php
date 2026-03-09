<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Security_Events {
    private Secure_Guard_Log_Repository $logs;

    public function __construct(Secure_Guard_Log_Repository $logs) {
        $this->logs = $logs;
    }

    public function on_user_role_change(int $user_id, string $new_role, array $old_roles): void {
        $this->logs->log('/wp-admin/users.php', 'ROLE_CHANGE', 'INFO', 'User role changed', [
            'user_id' => $user_id,
            'new_role' => sanitize_key($new_role),
            'old_roles' => array_map('sanitize_key', $old_roles),
        ]);
    }

    public function on_plugin_change($upgrader, array $options): void {
        $type = sanitize_text_field((string) ($options['type'] ?? ''));
        if ($type !== 'plugin') {
            return;
        }

        $action = sanitize_text_field((string) ($options['action'] ?? ''));
        $plugins = isset($options['plugins']) && is_array($options['plugins']) ? array_map('sanitize_text_field', $options['plugins']) : [];

        $this->logs->log('/wp-admin/plugins.php', strtoupper($action), 'INFO', 'Plugin change event', [
            'action' => $action,
            'plugins' => $plugins,
        ]);
    }
}
