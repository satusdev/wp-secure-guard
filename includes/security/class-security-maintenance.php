<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Security_Maintenance {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;

    public function __construct(array $settings, Secure_Guard_Log_Repository $logs) {
        $this->settings = $settings;
        $this->logs = $logs;
    }

    public function register_schedule(): void {
        if (!wp_next_scheduled('secure_guard_log_retention_purge')) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'secure_guard_log_retention_purge');
        }
    }

    public function purge_logs(): void {
        $days = max(1, (int) ($this->settings['log_retention_days'] ?? 30));
        $this->logs->purge_older_than_days($days);
    }
}
