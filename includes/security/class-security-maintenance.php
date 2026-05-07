<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Security_Maintenance {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;
    private ?Secure_Guard_Token_Repository $tokens;
    private ?Secure_Guard_Alert_Manager $alert_manager;

    public function __construct(
        array $settings,
        Secure_Guard_Log_Repository $logs,
        ?Secure_Guard_Token_Repository $tokens = null,
        ?Secure_Guard_Alert_Manager $alert_manager = null
    ) {
        $this->settings       = $settings;
        $this->logs           = $logs;
        $this->tokens         = $tokens;
        $this->alert_manager  = $alert_manager;
    }

    public function register_schedule(): void {
        if (!wp_next_scheduled('secure_guard_log_retention_purge')) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'secure_guard_log_retention_purge');
        }
        if (!wp_next_scheduled('secure_guard_token_expiry_check')) {
            wp_schedule_event(time() + 2 * HOUR_IN_SECONDS, 'daily', 'secure_guard_token_expiry_check');
        }
        if (!wp_next_scheduled('secure_guard_reputation_decay')) {
            wp_schedule_event(time() + 3 * HOUR_IN_SECONDS, 'daily', 'secure_guard_reputation_decay');
        }
    }

    public function purge_logs(): void {
        global $wpdb;
        $days = max(1, (int) ($this->settings['log_retention_days'] ?? 30));
        $this->logs->purge_older_than_days($days);
        // Prune expired JWT denylist entries to prevent unbounded table growth.
        $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
            "DELETE FROM {$wpdb->prefix}sg_jwt_denylist WHERE revoked_until IS NOT NULL AND revoked_until < UTC_TIMESTAMP()"
        );
    }

    /**
     * Check for tokens expiring within the configured alert window and send
     * email notifications via the Alert_Manager (if configured).
     */
    public function check_token_expiry(): void {
        if ($this->tokens === null || $this->alert_manager === null) {
            return;
        }
        if (empty($this->settings['email_alerts_enabled'])) {
            return;
        }

        $days = max(1, (int) ($this->settings['alert_on_token_expiry_days'] ?? 3));
        $expiring = $this->tokens->get_expiring_soon($days);

        foreach ($expiring as $token_row) {
            $this->alert_manager->notify_token_expiry($token_row);
        }
    }
}
