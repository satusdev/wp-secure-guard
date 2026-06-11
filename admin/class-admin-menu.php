<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Admin_Menu {
    private Secure_Guard_Dashboard_Page $dashboard_page;
    private Secure_Guard_Security_Assistant_Page $security_assistant_page;
    private Secure_Guard_Settings_Page $settings_page;
    private Secure_Guard_Tokens_Page $tokens_page;
    private Secure_Guard_Rules_Page $rules_page;
    private Secure_Guard_Reputation_Page $reputation_page;
    private Secure_Guard_Logs_Page $logs_page;
    private Secure_Guard_Blocked_IPs_Page $blocked_ips_page;
    private Secure_Guard_Docs_Page $docs_page;

    public function __construct(
        Secure_Guard_Dashboard_Page $dashboard_page,
        Secure_Guard_Security_Assistant_Page $security_assistant_page,
        Secure_Guard_Settings_Page $settings_page,
        Secure_Guard_Tokens_Page $tokens_page,
        Secure_Guard_Rules_Page $rules_page,
        Secure_Guard_Reputation_Page $reputation_page,
        Secure_Guard_Logs_Page $logs_page,
        Secure_Guard_Blocked_IPs_Page $blocked_ips_page,
        Secure_Guard_Docs_Page $docs_page
    ) {
        $this->dashboard_page            = $dashboard_page;
        $this->security_assistant_page  = $security_assistant_page;
        $this->settings_page             = $settings_page;
        $this->tokens_page               = $tokens_page;
        $this->rules_page                = $rules_page;
        $this->reputation_page           = $reputation_page;
        $this->logs_page                 = $logs_page;
        $this->blocked_ips_page          = $blocked_ips_page;
        $this->docs_page                 = $docs_page;
    }

    public function register_menu(): void {
        add_menu_page(
            __('Security API Guard', 'wp-secure-guard'),
            __('Security API Guard', 'wp-secure-guard'),
            'manage_options',
            'wp-secure-guard',
            [$this->dashboard_page, 'render'],
            'dashicons-shield-alt',
            56
        );

        add_submenu_page('wp-secure-guard', __('Dashboard', 'wp-secure-guard'), __('Dashboard', 'wp-secure-guard'), 'manage_options', 'wp-secure-guard', [$this->dashboard_page, 'render']);
        add_submenu_page('wp-secure-guard', __('Security Assistant', 'wp-secure-guard'), __('Security Assistant', 'wp-secure-guard'), 'manage_options', 'secure-guard-assistant', [$this->security_assistant_page, 'render']);
        add_submenu_page('wp-secure-guard', __('Tokens', 'wp-secure-guard'), __('Tokens', 'wp-secure-guard'), 'manage_options', 'secure-guard-tokens', [$this->tokens_page, 'render']);
        add_submenu_page('wp-secure-guard', __('Security Rules', 'wp-secure-guard'), __('Security Rules', 'wp-secure-guard'), 'manage_options', 'secure-guard-rules', [$this->rules_page, 'render']);
        add_submenu_page('wp-secure-guard', __('IP Reputation', 'wp-secure-guard'), __('IP Reputation', 'wp-secure-guard'), 'manage_options', 'secure-guard-reputation', [$this->reputation_page, 'render']);
        add_submenu_page('wp-secure-guard', __('Logs', 'wp-secure-guard'), __('Logs', 'wp-secure-guard'), 'manage_options', 'secure-guard-logs', [$this->logs_page, 'render']);
        add_submenu_page('wp-secure-guard', __('Blocked IPs', 'wp-secure-guard'), __('Blocked IPs', 'wp-secure-guard'), 'manage_options', 'secure-guard-blocked-ips', [$this->blocked_ips_page, 'render']);
        add_submenu_page('wp-secure-guard', __('Whitelists', 'wp-secure-guard'), __('Whitelists', 'wp-secure-guard'), 'manage_options', 'secure-guard-whitelists', [$this->settings_page, 'render']);
        add_submenu_page('wp-secure-guard', __('Settings', 'wp-secure-guard'), __('Settings', 'wp-secure-guard'), 'manage_options', 'secure-guard-settings', [$this->settings_page, 'render']);
        add_submenu_page('wp-secure-guard', __('Documentation', 'wp-secure-guard'), __('Documentation', 'wp-secure-guard'), 'manage_options', 'secure-guard-docs', [$this->docs_page, 'render']);
    }

    public function register_admin_actions(): void {
        $this->dashboard_page->register();
        $this->security_assistant_page->register();
        $this->settings_page->register();
        $this->tokens_page->register();
        $this->rules_page->register();
        $this->reputation_page->register();
        $this->logs_page->register();
        $this->blocked_ips_page->register();
        $this->docs_page->register();
    }

    public function enqueue_admin_assets(string $hook): void {
        // Only load on this plugin's pages.
        if (!str_contains($hook, 'wp-secure-guard')) {
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
