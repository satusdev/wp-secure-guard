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

    public function on_password_reset(WP_User $user): void {
        $this->logs->log('/wp-login.php', 'PASSWORD_RESET', 'INFO', 'Password reset successful', [
            'user_id' => (int) $user->ID,
            'username' => $user->user_login,
        ]);
    }

    public function on_profile_update(int $user_id, WP_User $old_user_data): void {
        $new_user = get_userdata($user_id);
        if (!$new_user) return;

        $changes = [];
        if ($new_user->user_email !== $old_user_data->user_email) {
            $changes['email'] = 'changed';
        }

        if ($changes !== []) {
            $this->record_profile_update($user_id);
            $this->logs->log('/wp-admin/profile.php', 'PROFILE_UPDATE', 'INFO', 'Sensitive profile change', [
                'user_id' => $user_id,
                'changes' => $changes,
            ]);
        }
    }

    public function record_profile_update(int $user_id): void {
        delete_transient('sg_dashboard_stats');
    }
}
