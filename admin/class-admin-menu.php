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
    private Secure_Guard_Blocked_IPs_Page $blocked_ips_page;
    private Secure_Guard_Docs_Page $docs_page;

    public function __construct(
        Secure_Guard_Dashboard_Page $dashboard_page,
        Secure_Guard_Settings_Page $settings_page,
        Secure_Guard_Tokens_Page $tokens_page,
        Secure_Guard_Rules_Page $rules_page,
        Secure_Guard_Logs_Page $logs_page,
        Secure_Guard_Blocked_IPs_Page $blocked_ips_page,
        Secure_Guard_Docs_Page $docs_page
    ) {
        $this->dashboard_page   = $dashboard_page;
        $this->settings_page    = $settings_page;
        $this->tokens_page      = $tokens_page;
        $this->rules_page       = $rules_page;
        $this->logs_page        = $logs_page;
        $this->blocked_ips_page = $blocked_ips_page;
        $this->docs_page        = $docs_page;
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
        add_submenu_page('secure-guard', __('Blocked IPs', 'secure-guard'), __('Blocked IPs', 'secure-guard'), 'manage_options', 'secure-guard-blocked-ips', [$this->blocked_ips_page, 'render']);
        add_submenu_page('secure-guard', __('Settings', 'secure-guard'), __('Settings', 'secure-guard'), 'manage_options', 'secure-guard-settings', [$this->settings_page, 'render']);
        add_submenu_page('secure-guard', __('Documentation', 'secure-guard'), __('Documentation', 'secure-guard'), 'manage_options', 'secure-guard-docs', [$this->docs_page, 'render']);
    }

    public function register_admin_actions(): void {
        $this->dashboard_page->register();
        $this->settings_page->register();
        $this->tokens_page->register();
        $this->rules_page->register();
        $this->logs_page->register();
        $this->blocked_ips_page->register();
    }

    public function enqueue_admin_assets(string $hook): void {
        // Only load on this plugin's pages.
        if (!str_contains($hook, 'secure-guard')) {
            return;
        }

        wp_enqueue_style(
            'secure-guard-admin',
            plugin_dir_url(SECURE_GUARD_FILE) . 'admin/secure-guard-admin.css',
            [],
            SECURE_GUARD_VERSION
        );

        wp_localize_script('jquery', 'sg_admin_params', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('sg_settings_nonce'),
        ]);
    }

    /** @deprecated Use enqueue_admin_assets instead. Kept for back-compat. */
    public function render_admin_styles(): void {
    }
}
