<?php

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

delete_option('secure_guard_settings');
delete_option('secure_guard_db_version');
delete_option('secure_guard_plugin_version');
delete_option('secure_guard_safe_mode_until');
delete_option('secure_guard_integrity_baseline');
delete_option('secure_guard_integrity_last_scan');

delete_transient('secure_guard_integrity_alert_count');

$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}sg_tokens");
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}sg_logs");
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}sg_rate_limits");
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}sg_jwt_denylist");
