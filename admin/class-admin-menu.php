<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Admin_Menu {
    private Secure_Guard_Dashboard_Page $dashboard_page;
    private Secure_Guard_Settings_Page $settings_page;
    private Secure_Guard_Tokens_Page $tokens_page;
    private Secure_Guard_Rules_Page $rules_page;
    private Secure_Guard_Logs_Page $logs_page;

    public function __construct(
        Secure_Guard_Dashboard_Page $dashboard_page,
        Secure_Guard_Settings_Page $settings_page,
        Secure_Guard_Tokens_Page $tokens_page,
        Secure_Guard_Rules_Page $rules_page,
        Secure_Guard_Logs_Page $logs_page
    ) {
        $this->dashboard_page = $dashboard_page;
        $this->settings_page = $settings_page;
        $this->tokens_page = $tokens_page;
        $this->rules_page = $rules_page;
        $this->logs_page = $logs_page;
    }

    public function register_menu(): void {
        add_menu_page(
            __('Security API Guard', 'secure-guard'),
            __('Security API Guard', 'secure-guard'),
            'manage_options',
            'secure-guard',
            [$this->dashboard_page, 'render'],
            'dashicons-shield-alt',
            56
        );

        add_submenu_page('secure-guard', __('Dashboard', 'secure-guard'), __('Dashboard', 'secure-guard'), 'manage_options', 'secure-guard', [$this->dashboard_page, 'render']);
        add_submenu_page('secure-guard', __('Tokens', 'secure-guard'), __('Tokens', 'secure-guard'), 'manage_options', 'secure-guard-tokens', [$this->tokens_page, 'render']);
        add_submenu_page('secure-guard', __('API Rules', 'secure-guard'), __('API Rules', 'secure-guard'), 'manage_options', 'secure-guard-rules', [$this->rules_page, 'render']);
        add_submenu_page('secure-guard', __('Logs', 'secure-guard'), __('Logs', 'secure-guard'), 'manage_options', 'secure-guard-logs', [$this->logs_page, 'render']);
        add_submenu_page('secure-guard', __('Settings', 'secure-guard'), __('Settings', 'secure-guard'), 'manage_options', 'secure-guard-settings', [$this->settings_page, 'render']);
    }

    public function register_admin_actions(): void {
        $this->settings_page->register();
        $this->tokens_page->register();
        $this->rules_page->register();
        $this->logs_page->register();
    }

    public function render_admin_styles(): void {
        $page = isset($_GET['page']) ? sanitize_key((string) $_GET['page']) : '';
        if ($page === '' || !str_starts_with($page, 'secure-guard')) {
            return;
        }

        echo '<style>';
        echo '.secure-guard-ui .card{border-radius:12px;padding:16px 18px;max-width:1200px;}';
        echo '.secure-guard-ui .card h2{margin-top:0;margin-bottom:12px;}';
        echo '.secure-guard-ui .description{max-width:1000px;}';
        echo '.secure-guard-ui .widefat td,.secure-guard-ui .widefat th{padding:10px 12px;vertical-align:top;}';
        echo '.secure-guard-ui .form-table th{width:280px;padding-top:14px;}';
        echo '.secure-guard-ui .form-table td{padding-top:10px;}';
        echo '.secure-guard-ui .sg-stack > *{margin-bottom:14px;}';
        echo '.secure-guard-ui .sg-stack > *:last-child{margin-bottom:0;}';
        echo '.secure-guard-ui .sg-action-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;}';
        echo '.secure-guard-ui .sg-pill{display:inline-block;padding:2px 8px;border:1px solid currentColor;border-radius:999px;font-size:12px;line-height:1.5;}';
        echo '.secure-guard-ui code{font-size:12px;}';
        echo '</style>';
    }
}
