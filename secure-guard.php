<?php
/**
 * Plugin Name: Secure Guard
 * Description: REST API and sensitive endpoint security guard for WordPress.
 * Version: 1.1.8
 * Requires at least: 6.4
 * Requires PHP: 8.1
 * Author: satusdev
 * License: GPL-2.0-or-later
 * Text Domain: wp-secure-guard
 */

if (!defined('ABSPATH')) {
    exit;
}

define('SECURE_GUARD_VERSION', '1.1.8');
define('SECURE_GUARD_FILE', __FILE__);
define('SECURE_GUARD_DIR', plugin_dir_path(__FILE__));
define('SECURE_GUARD_URL', plugin_dir_url(__FILE__));

if (file_exists(SECURE_GUARD_DIR . 'vendor/autoload.php')) {
    require_once SECURE_GUARD_DIR . 'vendor/autoload.php';
}

require_once SECURE_GUARD_DIR . 'includes/class-config.php';
require_once SECURE_GUARD_DIR . 'includes/class-loader.php';
require_once SECURE_GUARD_DIR . 'includes/install/class-installer.php';
require_once SECURE_GUARD_DIR . 'includes/data/class-token-repository.php';
require_once SECURE_GUARD_DIR . 'includes/data/class-log-repository.php';
require_once SECURE_GUARD_DIR . 'includes/data/class-rate-limit-repository.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-token-manager.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-ip-whitelist.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-rate-limit.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-endpoint-sensitivity.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-endpoint-blocker.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-user-enumeration-blocker.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-xmlrpc-protector.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-security-headers.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-lock-state.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-security-presets.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-bot-fingerprint.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-progressive-throttle.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-self-protection.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-rest-guard.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-login-protection.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-traffic-firewall.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-wp-hardening.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-admin-area-protector.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-file-integrity-monitor.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-security-maintenance.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-alert-manager.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-reputation-engine.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-security-events.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-site-health.php';
require_once SECURE_GUARD_DIR . 'includes/security/class-recovery-cli.php';
require_once SECURE_GUARD_DIR . 'admin/class-admin-menu.php';
require_once SECURE_GUARD_DIR . 'admin/class-security-assistant-page.php';
require_once SECURE_GUARD_DIR . 'admin/class-dashboard-page.php';
require_once SECURE_GUARD_DIR . 'admin/class-settings-page.php';
require_once SECURE_GUARD_DIR . 'admin/class-tokens-page.php';
require_once SECURE_GUARD_DIR . 'admin/class-rules-page.php';
require_once SECURE_GUARD_DIR . 'admin/class-reputation-page.php';
require_once SECURE_GUARD_DIR . 'admin/class-logs-page.php';
require_once SECURE_GUARD_DIR . 'admin/class-blocked-ips-page.php';
require_once SECURE_GUARD_DIR . 'admin/class-docs-page.php';
require_once SECURE_GUARD_DIR . 'includes/class-plugin.php';

add_action(
    'update_option_' . Secure_Guard_Config::OPTION_KEY,
    [Secure_Guard_Config::class, 'reconcile_trusted_ips'],
    10,
    2
);
Secure_Guard_Recovery_CLI::register();

function secure_guard_bootstrap(): Secure_Guard_Plugin {
    static $plugin = null;

    $db_version = get_option(Secure_Guard_Config::DB_VERSION_OPTION, '0.0.0');
    $plugin_version = get_option(Secure_Guard_Config::PLUGIN_VERSION_OPTION, '0.0.0');
    if ((string) $db_version !== Secure_Guard_Config::DB_VERSION || (string) $plugin_version !== SECURE_GUARD_VERSION) {
        Secure_Guard_Installer::activate();
    }

    if ($plugin instanceof Secure_Guard_Plugin) {
        return $plugin;
    }

    $plugin = new Secure_Guard_Plugin();
    $plugin->register_hooks();

    return $plugin;
}

register_activation_hook(
    SECURE_GUARD_FILE,
    static function (): void {
        Secure_Guard_Installer::activate();
    }
);

register_deactivation_hook(
    SECURE_GUARD_FILE,
    static function (): void {
        $timestamp = wp_next_scheduled('secure_guard_integrity_scan');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'secure_guard_integrity_scan');
        }

        $log_retention_timestamp = wp_next_scheduled('secure_guard_log_retention_purge');
        if ($log_retention_timestamp) {
            wp_unschedule_event($log_retention_timestamp, 'secure_guard_log_retention_purge');
        }

        $token_expiry_timestamp = wp_next_scheduled('secure_guard_token_expiry_check');
        if ($token_expiry_timestamp) {
            wp_unschedule_event($token_expiry_timestamp, 'secure_guard_token_expiry_check');
        }

        // Restore relocated debug.log
        $secure_path = get_option('secure_guard_resolved_debug_log_path');
        if (!empty($secure_path) && file_exists($secure_path)) {
            $default_debug_log = WP_CONTENT_DIR . '/debug.log';
            if (@rename($secure_path, $default_debug_log) === false) {
                if (@copy($secure_path, $default_debug_log)) {
                    @unlink($secure_path);
                }
            }
        }
        delete_option('secure_guard_resolved_debug_log_path');

        // Remove .htaccess protections
        Secure_Guard_WP_Hardening::remove_htaccess_protection();
        delete_option('secure_guard_htaccess_hardened');
    }
);

add_action('plugins_loaded', 'secure_guard_bootstrap');
