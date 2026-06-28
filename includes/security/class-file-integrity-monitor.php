<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_File_Integrity_Monitor {
    private const BASELINE_OPTION = 'secure_guard_integrity_baseline';
    private const LAST_SCAN_OPTION = 'secure_guard_integrity_last_scan';

    private array $settings;
    private Secure_Guard_Log_Repository $logs;
    private ?Secure_Guard_Alert_Manager $alert_manager;

    public function __construct(
        array $settings,
        Secure_Guard_Log_Repository $logs,
        ?Secure_Guard_Alert_Manager $alert_manager = null
    ) {
        $this->settings = $settings;
        $this->logs     = $logs;
        $this->alert_manager = $alert_manager;
    }

    public function register_schedule(): void {
        if (empty($this->settings['file_integrity_enabled'])) {
            return;
        }

        if (!wp_next_scheduled('secure_guard_integrity_scan')) {
            wp_schedule_event(time() + MINUTE_IN_SECONDS, 'hourly', 'secure_guard_integrity_scan');
        }
    }

    public function perform_scan(): void {
        if (empty($this->settings['file_integrity_enabled'])) {
            return;
        }

        $current = $this->build_file_hash_map();
        $baseline = get_option(self::BASELINE_OPTION, []);
        if (!is_array($baseline) || $baseline === []) {
            update_option(self::BASELINE_OPTION, $current, false);
            update_option(self::LAST_SCAN_OPTION, current_time('mysql', true), false);
            return;
        }

        $changes = $this->detect_changes($baseline, $current);
        if ($changes !== []) {
            foreach (array_slice($changes, 0, 100) as $change) {
                $this->logs->log($change['file'], 'SCAN', 'ALERT', 'File integrity change detected', ['type' => $change['type']]);
            }

            set_transient('secure_guard_integrity_alert_count', count($changes), DAY_IN_SECONDS);

            if ($this->alert_manager !== null) {
                $this->alert_manager->notify_integrity_alert(count($changes));
            }
        }

        update_option(self::BASELINE_OPTION, $current, false);
        update_option(self::LAST_SCAN_OPTION, current_time('mysql', true), false);
    }

    public static function get_last_scan(): string {
        return (string) get_option(self::LAST_SCAN_OPTION, 'Never');
    }

    /**
     * Handles the admin_post_sg_reset_integrity_baseline action.
     * Deletes the stored baseline so the next scheduled scan re-baselines from the current
     * file state, dismissing all pending integrity alerts.
     */
    public function handle_reset_baseline(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('sg_reset_integrity_baseline');

        delete_option(self::BASELINE_OPTION);
        delete_transient('secure_guard_integrity_alert_count');

        wp_safe_redirect(admin_url('admin.php?page=wp-secure-guard&baseline_reset=1'));
        exit;
    }

    private function build_file_hash_map(): array {
        $targets = [
            ABSPATH . 'wp-admin',
            ABSPATH . 'wp-includes',
            $this->settings['mu_plugin_path'],
        ];
        $hash_map = [];

        foreach ($targets as $target) {
            if (!is_dir($target)) {
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if (!$file instanceof SplFileInfo || !$file->isFile()) {
                    continue;
                }

                $file_name = $file->getFilename();
                if (!str_ends_with($file_name, '.php') && !str_ends_with($file_name, '.js')) {
                    continue;
                }

                $path = $file->getPathname();
                $relative = ltrim(str_replace(ABSPATH, '', $path), '/');
                $hash_map[$relative] = hash_file('sha256', $path) ?: '';
            }
        }

        ksort($hash_map);
        return $hash_map;
    }

    private function detect_changes(array $baseline, array $current): array {
        $changes = [];

        foreach ($current as $file => $hash) {
            if (!array_key_exists($file, $baseline)) {
                $changes[] = ['type' => 'added', 'file' => $file];
                continue;
            }

            if ($baseline[$file] !== $hash) {
                $changes[] = ['type' => 'modified', 'file' => $file];
            }
        }

        foreach ($baseline as $file => $_hash) {
            if (!array_key_exists($file, $current)) {
                $changes[] = ['type' => 'deleted', 'file' => $file];
            }
        }

        return $changes;
    }
}
