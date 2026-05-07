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
            'label' => __('Secure Guard Status', 'secure-guard'),
            'test'  => [$this, 'test_secure_guard_status'],
        ];
        $tests['direct']['secure_guard_rest_lock'] = [
            'label' => __('REST API Hardening', 'secure-guard'),
            'test'  => [$this, 'test_rest_hardening'],
        ];
        return $tests;
    }

    public function test_secure_guard_status(): array {
        $result = [
            'label'       => __('Secure Guard is active and protecting your site', 'secure-guard'),
            'status'      => 'good',
            'badge'       => ['label' => __('Security', 'secure-guard'), 'color' => 'blue'],
            'description' => sprintf(
                __('Secure Guard is currently monitoring traffic. We have blocked %d threats in the last 24 hours.', 'secure-guard'),
                $this->logs->count_by_result('BLOCKED', 1)
            ),
            'actions'     => sprintf(
                '<a href="%s">%s</a>',
                esc_url(admin_url('admin.php?page=secure-guard')),
                __('View Security Dashboard', 'secure-guard')
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
                'label'       => __('REST API is fully hardened', 'secure-guard'),
                'status'      => 'good',
                'badge'       => ['label' => __('Security', 'secure-guard'), 'color' => 'blue'],
                'description' => __('Your REST API is in Strict Mode and locked to authorized tokens only. This is the most secure configuration.', 'secure-guard'),
                'test'        => 'secure_guard_rest_lock',
            ];
        }

        return [
            'label'       => __('REST API could be more secure', 'secure-guard'),
            'status'      => 'recommended',
            'badge'       => ['label' => __('Security', 'secure-guard'), 'color' => 'orange'],
            'description' => __('We recommend enabling "Strict Mode" and "REST Lock" in Secure Guard settings to prevent unauthorized API discovery and access.', 'secure-guard'),
            'actions'     => sprintf(
                '<a href="%s">%s</a>',
                esc_url(admin_url('admin.php?page=secure-guard-settings&tab=rest-jwt')),
                __('Configure REST Security', 'secure-guard')
            ),
            'test'        => 'secure_guard_rest_lock',
        ];
    }
}
