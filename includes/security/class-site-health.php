<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Site_Health {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;

    public function __construct(array $settings, Secure_Guard_Log_Repository $logs) {
        $this->settings = $settings;
        $this->logs = $logs;
    }

    public function register(): void {
        add_filter('site_status_tests', [$this, 'add_tests']);
    }

    public function add_tests(array $tests): array {
        $tests['direct']['secure_guard_status'] = [
            'label' => __('Secure Guard Status', 'wp-secure-guard'),
            'test'  => [$this, 'test_secure_guard_status'],
        ];
        $tests['direct']['secure_guard_rest_lock'] = [
            'label' => __('REST API Hardening', 'wp-secure-guard'),
            'test'  => [$this, 'test_rest_hardening'],
        ];
        $tests['direct']['secure_guard_debug_log'] = [
            'label' => __('Debug Log Exposure Check', 'wp-secure-guard'),
            'test'  => [$this, 'test_debug_log_exposure'],
        ];
        return $tests;
    }

    public function test_secure_guard_status(): array {
        $result = [
            'label'       => __('Secure Guard is active and protecting your site', 'wp-secure-guard'),
            'status'      => 'good',
            'badge'       => ['label' => __('Security', 'wp-secure-guard'), 'color' => 'blue'],
            'description' => sprintf(
                __('Secure Guard is currently monitoring traffic. We have blocked %d threats in the last 24 hours.', 'wp-secure-guard'),
                $this->logs->count_by_result('BLOCKED', 1)
            ),
            'actions'     => sprintf(
                '<a href="%s">%s</a>',
                esc_url(admin_url('admin.php?page=secure-guard')),
                __('View Security Dashboard', 'wp-secure-guard')
            ),
            'test'        => 'secure_guard_status',
        ];

        return $result;
    }

    public function test_rest_hardening(): array {
        $strict = !empty($this->settings['rest_strict_mode']);
        $locked = !empty($this->settings['rest_lock_enabled']);

        if ($strict && $locked) {
            return [
                'label'       => __('REST API is fully hardened', 'wp-secure-guard'),
                'status'      => 'good',
                'badge'       => ['label' => __('Security', 'wp-secure-guard'), 'color' => 'blue'],
                'description' => __('Your REST API is in Strict Mode and locked to authorized tokens only. This is the most secure configuration.', 'wp-secure-guard'),
                'test'        => 'secure_guard_rest_lock',
            ];
        }

        return [
            'label'       => __('REST API could be more secure', 'wp-secure-guard'),
            'status'      => 'recommended',
            'badge'       => ['label' => __('Security', 'wp-secure-guard'), 'color' => 'orange'],
            'description' => __('We recommend enabling "Strict Mode" and "REST Lock" in Secure Guard settings to prevent unauthorized API discovery and access.', 'wp-secure-guard'),
            'actions'     => sprintf(
                '<a href="%s">%s</a>',
                esc_url(admin_url('admin.php?page=secure-guard-settings&tab=rest-jwt')),
                __('Configure REST Security', 'wp-secure-guard')
            ),
            'test'        => 'secure_guard_rest_lock',
        ];
    }

    public function test_debug_log_exposure(): array {
        $debug_log_path = Secure_Guard_Config::get_debug_log_path();
        if (!file_exists($debug_log_path)) {
            return [
                'label'       => __('Debug log is not present', 'wp-secure-guard'),
                'status'      => 'good',
                'badge'       => ['label' => __('Security', 'wp-secure-guard'), 'color' => 'blue'],
                'description' => __('No debug.log file was found in the content directory. This is safe.', 'wp-secure-guard'),
                'test'        => 'secure_guard_debug_log',
            ];
        }

        // Try to access the file via HTTP request
        $debug_log_url = content_url('debug.log');
        $response = wp_remote_get($debug_log_url, [
            'sslverify' => false,
            'timeout'   => 5,
        ]);

        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            delete_option('secure_guard_htaccess_hardened');
            return [
                'label'       => __('Debug log is publicly accessible!', 'wp-secure-guard'),
                'status'      => 'critical',
                'badge'       => ['label' => __('Security', 'wp-secure-guard'), 'color' => 'red'],
                'description' => __('Your debug.log file contains sensitive application logs and is publicly readable. Secure Guard has attempted to block this via .htaccess, but your web server (e.g. Nginx) or configuration is bypassing it. Please restrict access to this file immediately.', 'wp-secure-guard'),
                'actions'     => sprintf(
                    '<a href="%s">%s</a>',
                    esc_url(admin_url('admin.php?page=secure-guard-settings&tab=hardening')),
                    __('Go to Hardening Settings', 'wp-secure-guard')
                ),
                'test'        => 'secure_guard_debug_log',
            ];
        }

        return [
            'label'       => __('Debug log is secure', 'wp-secure-guard'),
            'status'      => 'good',
            'badge'       => ['label' => __('Security', 'wp-secure-guard'), 'color' => 'blue'],
            'description' => __('A debug.log file is present, but public access to it is blocked successfully.', 'wp-secure-guard'),
            'test'        => 'secure_guard_debug_log',
        ];
    }
}
