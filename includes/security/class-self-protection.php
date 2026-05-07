<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Self_Protection {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;

    public function __construct(array $settings, Secure_Guard_Log_Repository $logs) {
        $this->settings = $settings;
        $this->logs = $logs;
    }

    public function protect_active_plugins(array $new_value, array $old_value): array {
        if (empty($this->settings['self_protection_enabled'])) {
            return $new_value;
        }

        if (defined('WP_CLI') && WP_CLI) {
            return $new_value;
        }

        $plugin_file = 'secure-guard/secure-guard.php';
        
        // If Secure Guard was active but is missing from the new list
        if (in_array($plugin_file, $old_value, true) && !in_array($plugin_file, $new_value, true)) {
            $new_value[] = $plugin_file;
            $this->logs->log('admin', 'POST', 'BLOCKED', 'Plugin deactivation attempt blocked', ['user_id' => get_current_user_id()]);
        }

        return $new_value;
    }
}
