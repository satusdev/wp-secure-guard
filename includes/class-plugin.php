<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Plugin {
    private Secure_Guard_Loader $loader;
    private Secure_Guard_Log_Repository $logs;
    private Secure_Guard_Token_Repository $tokens;
    private Secure_Guard_Rate_Limit_Repository $limits;
    private Secure_Guard_REST_Guard $rest_guard;
    private Secure_Guard_User_Enumeration_Blocker $enumeration_blocker;
    private Secure_Guard_XMLRPC_Protector $xmlrpc_protector;
    private Secure_Guard_Security_Headers $security_headers;
    private Secure_Guard_Login_Protection $login_protection;
    private Secure_Guard_Traffic_Firewall $traffic_firewall;
    private Secure_Guard_WP_Hardening $wp_hardening;
    private Secure_Guard_Admin_Area_Protector $admin_area_protector;
    private Secure_Guard_File_Integrity_Monitor $file_integrity_monitor;
    private Secure_Guard_Security_Maintenance $security_maintenance;
    private Secure_Guard_Reputation_Engine $reputation_engine;
    private Secure_Guard_Lock_State $lock_state;
    private Secure_Guard_Bot_Fingerprint $bot_fingerprint;
    private Secure_Guard_Progressive_Throttle $progressive_throttle;
    private Secure_Guard_Self_Protection $self_protection;
    private Secure_Guard_Security_Events $security_events;
    private Secure_Guard_Admin_Menu $admin_menu;
    private Secure_Guard_Security_Assistant_Page $security_assistant_page;
    private Secure_Guard_Docs_Page $docs_page;
    private Secure_Guard_Site_Health $site_health;

    public function __construct() {
        $settings = Secure_Guard_Config::get_settings();

        $this->loader = new Secure_Guard_Loader();
        $this->logs = new Secure_Guard_Log_Repository();
        $this->tokens = new Secure_Guard_Token_Repository();
        $this->limits = new Secure_Guard_Rate_Limit_Repository();

        $token_manager = new Secure_Guard_Token_Manager($this->tokens, $settings);
        $ip_whitelist = new Secure_Guard_IP_Whitelist($settings);
        $rate_limit = new Secure_Guard_Rate_Limit($this->limits, $settings);
        $endpoint_blocker = new Secure_Guard_Endpoint_Blocker($settings);
        $alert_manager = new Secure_Guard_Alert_Manager($settings);
        $this->lock_state = new Secure_Guard_Lock_State($settings);
        $this->reputation_engine = new Secure_Guard_Reputation_Engine($this->limits, $settings, $this->lock_state);
        $this->bot_fingerprint = new Secure_Guard_Bot_Fingerprint($settings);
        $this->progressive_throttle = new Secure_Guard_Progressive_Throttle($settings);
        $this->self_protection = new Secure_Guard_Self_Protection($settings, $this->logs);
        $sensitivity = new Secure_Guard_Endpoint_Sensitivity($settings);

        $this->rest_guard = new Secure_Guard_REST_Guard(
            $settings,
            $this->logs,
            $token_manager,
            $ip_whitelist,
            $rate_limit,
            $endpoint_blocker,
            $this->reputation_engine,
            $sensitivity,
            $this->lock_state
        );
        $this->enumeration_blocker = new Secure_Guard_User_Enumeration_Blocker($settings, $this->logs, $token_manager);
        $this->xmlrpc_protector = new Secure_Guard_XMLRPC_Protector($settings, $this->logs);
        $this->security_headers = new Secure_Guard_Security_Headers($settings);
        $this->login_protection = new Secure_Guard_Login_Protection($settings, $this->logs, $this->limits, $ip_whitelist, $this->reputation_engine, $alert_manager);
        $this->traffic_firewall = new Secure_Guard_Traffic_Firewall(
            $settings,
            $this->logs,
            $rate_limit,
            $this->limits,
            $ip_whitelist,
            $this->reputation_engine,
            $sensitivity,
            $this->lock_state,
            $this->bot_fingerprint,
            $this->progressive_throttle,
            $alert_manager
        );
        $this->wp_hardening = new Secure_Guard_WP_Hardening($settings, $this->logs);
        $this->admin_area_protector = new Secure_Guard_Admin_Area_Protector($settings, $this->logs, $this->limits, $ip_whitelist);
        $this->file_integrity_monitor = new Secure_Guard_File_Integrity_Monitor($settings, $this->logs, $alert_manager);
        $this->security_maintenance = new Secure_Guard_Security_Maintenance($settings, $this->logs, $this->tokens, $alert_manager);
        $this->security_events = new Secure_Guard_Security_Events($this->logs);
        $this->security_assistant_page = new Secure_Guard_Security_Assistant_Page($this->logs, $this->tokens, $this->limits, $this->lock_state);

        $this->admin_menu = new Secure_Guard_Admin_Menu(
            new Secure_Guard_Dashboard_Page($this->logs, $this->tokens, $this->limits),
            $this->security_assistant_page,
            new Secure_Guard_Settings_Page(),
            new Secure_Guard_Tokens_Page($this->tokens, $token_manager, $settings, $this->logs),
            new Secure_Guard_Rules_Page(),
            new Secure_Guard_Reputation_Page($this->limits, $this->reputation_engine),
            new Secure_Guard_Logs_Page($this->logs),
            new Secure_Guard_Blocked_IPs_Page($this->limits, $this->logs),
            new Secure_Guard_Docs_Page()
        );
        $this->site_health = new Secure_Guard_Site_Health($settings, $this->logs);
    }

    public function register_hooks(): void {
        $this->loader->action('init', [$this->traffic_firewall, 'handle_request'], 1, 0);
        $this->loader->action('parse_request', [$this->traffic_firewall, 'enforce_parse_request'], 1, 0);
        $this->loader->action('wp_loaded', [$this->traffic_firewall, 'enforce_wp_loaded'], 1, 0);
        $this->loader->action('init', [$this->xmlrpc_protector, 'block_direct_request'], 2, 0);
        $this->loader->action('init', [$this->login_protection, 'guard_login_request'], 2, 0);
        $this->loader->action('init', [$this->admin_area_protector, 'protect'], 3, 0);
        $this->loader->action('init', [$this->wp_hardening, 'register'], 4, 0);
        $this->loader->action('init', [$this->file_integrity_monitor, 'register_schedule'], 8, 0);
        $this->loader->action('init', [$this->security_maintenance, 'register_schedule'], 9, 0);
        $this->loader->filter('rest_authentication_errors', [$this->rest_guard, 'authenticate'], 20, 1);
        $this->loader->filter('rest_endpoints', [$this->enumeration_blocker, 'remove_rest_endpoints'], 99, 1);
        $this->loader->filter('rest_pre_dispatch', [$this->enumeration_blocker, 'block_rest_users_endpoint'], 5, 3);
        $this->loader->filter('rest_pre_dispatch', [$this->rest_guard, 'pre_dispatch'], 10, 3);
        $this->loader->filter('rest_pre_dispatch', [$this->rest_guard, 'final_gate'], 99, 3);
        $this->loader->action('rest_api_init', [$this->rest_guard, 'register_routes'], 10, 0);
        $this->loader->action('template_redirect', [$this->enumeration_blocker, 'block_author_enumeration'], 1, 0);
        $this->loader->action('template_redirect', [$this->wp_hardening, 'block_probe_files'], 2, 0);
        $this->loader->action('template_redirect', [$this->traffic_firewall, 'handle_404_scan'], 3, 0);
        $this->loader->filter('xmlrpc_enabled', [$this->xmlrpc_protector, 'xmlrpc_enabled'], 99, 1);
        $this->loader->action('send_headers', [$this->security_headers, 'send'], 10, 0);
        $this->loader->action('login_init', [$this->login_protection, 'guard_login_request'], 10, 0);
        $this->loader->filter('login_message', [$this->login_protection, 'show_login_warnings'], 10, 1);
        $this->loader->action('login_footer', [$this->login_protection, 'inject_login_script'], 10, 0);
        $this->loader->action('wp_login_failed', [$this->login_protection, 'record_failed_login'], 10, 1);
        $this->loader->action('wp_login', [$this->login_protection, 'record_successful_login'], 10, 2);
        $this->loader->action('set_user_role', [$this->security_events, 'on_user_role_change'], 10, 3);
        $this->loader->action('upgrader_process_complete', [$this->security_events, 'on_plugin_change'], 10, 2);
        $this->loader->action('after_password_reset', [$this->security_events, 'on_password_reset'], 10, 1);
        $this->loader->action('profile_update', [$this->security_events, 'on_profile_update'], 10, 2);
        $this->loader->filter('script_loader_src', [$this->wp_hardening, 'strip_version_query_arg'], 99, 1);
        $this->loader->filter('style_loader_src', [$this->wp_hardening, 'strip_version_query_arg'], 99, 1);
        $this->loader->filter('the_generator', [$this->wp_hardening, 'hide_generator'], 99, 1);
        $this->loader->action('secure_guard_integrity_scan', [$this->file_integrity_monitor, 'perform_scan'], 10, 0);
        $this->loader->action('admin_post_sg_reset_integrity_baseline', [$this->file_integrity_monitor, 'handle_reset_baseline'], 10, 0);
        $this->loader->action('secure_guard_log_retention_purge', [$this->security_maintenance, 'purge_logs'], 10, 0);
        $this->loader->action('secure_guard_token_expiry_check',  [$this->security_maintenance, 'check_token_expiry'], 10, 0);
        $this->loader->action('secure_guard_reputation_decay', [$this->reputation_engine, 'decay'], 10, 0);
        $this->loader->filter('pre_update_option_active_plugins', [$this->self_protection, 'protect_active_plugins'], 10, 2);
        $this->loader->action('admin_menu', [$this->admin_menu, 'register_menu'], 10, 0);
        $this->loader->action('admin_init', [$this->admin_menu, 'register_admin_actions'], 10, 0);
        $this->loader->action('admin_enqueue_scripts', [$this->admin_menu, 'enqueue_admin_assets'], 10, 1);
        $this->loader->action('init', [$this->site_health, 'register'], 10, 0);
    }
}
