<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Settings_Page {
    public function register(): void {
        register_setting(
            'secure_guard_settings_group',
            Secure_Guard_Config::OPTION_KEY,
            [
                'type' => 'array',
                'sanitize_callback' => [$this, 'sanitize'],
                'default' => Secure_Guard_Config::defaults(),
            ]
        );
    }

    public function sanitize($input): array {
        $input = is_array($input) ? $input : [];
        return Secure_Guard_Config::save_settings($input);
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        $settings = Secure_Guard_Config::get_settings();
        $roles = wp_roles()->roles;
        ?>
        <div class="wrap secure-guard-ui">
            <h1><?php echo esc_html__('Settings', 'secure-guard'); ?></h1>
            <p class="description"><?php echo esc_html__('Configure hardening defaults. REST API access is force-disabled for all routes and methods by plugin policy.', 'secure-guard'); ?></p>
            <div class="notice notice-info"><p><?php echo esc_html__('Tip: After saving settings, validate behavior from API Rules and Logs pages.', 'secure-guard'); ?></p></div>

            <div class="card" style="max-width:1200px;padding:16px;">
                <h2 style="margin-top:0;"><?php echo esc_html__('Security Configuration', 'secure-guard'); ?></h2>
            <form method="post" action="options.php">
                <?php settings_fields('secure_guard_settings_group'); ?>
                <table class="form-table" role="presentation">
                    <tr><th><?php echo esc_html__('REST Lock', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[rest_lock_enabled]" value="1" <?php checked(!empty($settings['rest_lock_enabled'])); ?> /> <?php echo esc_html__('Reserved for compatibility. REST API is currently force-disabled by policy.', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Block Sensitive Endpoints', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[block_sensitive_endpoints]" value="1" <?php checked(!empty($settings['block_sensitive_endpoints'])); ?> /> <?php echo esc_html__('Reserved for compatibility. All REST routes/methods are blocked globally.', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Block User Enumeration', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[block_user_enumeration]" value="1" <?php checked(!empty($settings['block_user_enumeration'])); ?> /> <?php echo esc_html__('Block author query, author archive, and REST route user enumeration probes', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Block XML-RPC', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[block_xmlrpc]" value="1" <?php checked(!empty($settings['block_xmlrpc'])); ?> /> <?php echo esc_html__('Disable XML-RPC and return hard 403 for direct XML-RPC paths (`/xmlrpc.php` and `/wp/xmlrpc.php`)', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Login Protection', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[login_protection_enabled]" value="1" <?php checked(!empty($settings['login_protection_enabled'])); ?> /> <?php echo esc_html__('Enable login lockout controls', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Login thresholds', 'secure-guard'); ?></th><td>
                        <label><?php echo esc_html__('Short block threshold', 'secure-guard'); ?> <input type="number" min="1" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[login_short_threshold]" value="<?php echo esc_attr((string) $settings['login_short_threshold']); ?>" /></label><br />
                        <label><?php echo esc_html__('Medium block threshold', 'secure-guard'); ?> <input type="number" min="1" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[login_medium_threshold]" value="<?php echo esc_attr((string) $settings['login_medium_threshold']); ?>" /></label><br />
                        <label><?php echo esc_html__('Hard block threshold', 'secure-guard'); ?> <input type="number" min="1" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[login_hard_block_threshold]" value="<?php echo esc_attr((string) $settings['login_hard_block_threshold']); ?>" /></label>
                    </td></tr>
                    <tr><th><?php echo esc_html__('Bot Rate Limiting', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[bot_rate_limit_enabled]" value="1" <?php checked(!empty($settings['bot_rate_limit_enabled'])); ?> /> <?php echo esc_html__('Enable per-IP bot rate limiting', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Bot limits', 'secure-guard'); ?></th><td>
                        <label><?php echo esc_html__('Requests per minute', 'secure-guard'); ?> <input type="number" min="1" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[bot_rate_limit_per_minute]" value="<?php echo esc_attr((string) $settings['bot_rate_limit_per_minute']); ?>" /></label><br />
                        <label><?php echo esc_html__('Block minutes when exceeded', 'secure-guard'); ?> <input type="number" min="1" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[bot_block_minutes]" value="<?php echo esc_attr((string) $settings['bot_block_minutes']); ?>" /></label><br />
                        <label><?php echo esc_html__('404 scan threshold (10 min window)', 'secure-guard'); ?> <input type="number" min="1" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[scan_404_threshold]" value="<?php echo esc_attr((string) $settings['scan_404_threshold']); ?>" /></label>
                    </td></tr>
                    <tr><th><?php echo esc_html__('Block Public WP-Cron', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[block_public_wp_cron]" value="1" <?php checked(!empty($settings['block_public_wp_cron'])); ?> /> <?php echo esc_html__('Block external access to wp-cron.php and allow only internal/system cron execution', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Global IP Whitelist', 'secure-guard'); ?></th><td><textarea rows="6" cols="60" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[ip_whitelist]"><?php echo esc_textarea((string) $settings['ip_whitelist']); ?></textarea><p class="description"><?php echo esc_html__('One IP/CIDR per line.', 'secure-guard'); ?></p></td></tr>
                    <tr><th><?php echo esc_html__('Admin Area Protection', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[admin_area_protection_enabled]" value="1" <?php checked(!empty($settings['admin_area_protection_enabled'])); ?> /> <?php echo esc_html__('Protect /wp-admin requests', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Admin IP whitelist', 'secure-guard'); ?></th><td><textarea rows="4" cols="60" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[admin_ip_whitelist]"><?php echo esc_textarea((string) $settings['admin_ip_whitelist']); ?></textarea><p class="description"><?php echo esc_html__('Optional. If set, only these IPs can access admin.', 'secure-guard'); ?></p></td></tr>
                    <tr><th><?php echo esc_html__('Trusted Proxy IPs', 'secure-guard'); ?></th><td><textarea rows="4" cols="60" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[trusted_proxy_ips]"><?php echo esc_textarea((string) ($settings['trusted_proxy_ips'] ?? '')); ?></textarea><p class="description"><?php echo esc_html__('Optional. One IPv4/IPv6/CIDR per line. Forwarded headers are trusted only when REMOTE_ADDR matches this list.', 'secure-guard'); ?></p></td></tr>
                    <tr><th><?php echo esc_html__('Hide WordPress Info', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[hide_wp_info]" value="1" <?php checked(!empty($settings['hide_wp_info'])); ?> /> <?php echo esc_html__('Hide generator/meta/version and block readme/license probes', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('File Integrity Monitoring', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[file_integrity_enabled]" value="1" <?php checked(!empty($settings['file_integrity_enabled'])); ?> /> <?php echo esc_html__('Enable hourly scan of wp-admin/wp-includes', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Rate limit per minute', 'secure-guard'); ?></th><td><input type="number" min="1" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[rate_limit_per_minute]" value="<?php echo esc_attr((string) $settings['rate_limit_per_minute']); ?>" /></td></tr>
                    <tr><th><?php echo esc_html__('Allowed User Roles', 'secure-guard'); ?></th><td>
                        <?php foreach ($roles as $role_key => $role): ?>
                            <label style="display:block"><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[allowed_roles][]" value="<?php echo esc_attr($role_key); ?>" <?php checked(in_array($role_key, $settings['allowed_roles'], true)); ?> /> <?php echo esc_html($role['name']); ?></label>
                        <?php endforeach; ?>
                    </td></tr>
                    <tr><th><?php echo esc_html__('JWT Secret', 'secure-guard'); ?></th><td><input type="text" class="regular-text" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[jwt_secret]" value="<?php echo esc_attr((string) $settings['jwt_secret']); ?>" /><p class="description"><?php echo esc_html__('Optional. If empty, plugin uses SECURE_GUARD_JWT_SECRET constant, then AUTH_KEY fallback.', 'secure-guard'); ?></p></td></tr>
                    <tr><th><?php echo esc_html__('JWT Issuer', 'secure-guard'); ?></th><td><input type="url" class="regular-text" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[jwt_issuer]" value="<?php echo esc_attr((string) $settings['jwt_issuer']); ?>" /></td></tr>
                    <tr><th><?php echo esc_html__('JWT Audience', 'secure-guard'); ?></th><td><input type="url" class="regular-text" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[jwt_audience]" value="<?php echo esc_attr((string) $settings['jwt_audience']); ?>" /></td></tr>
                    <tr><th><?php echo esc_html__('JWT TTL (minutes)', 'secure-guard'); ?></th><td><input type="number" min="1" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[jwt_ttl_minutes]" value="<?php echo esc_attr((string) $settings['jwt_ttl_minutes']); ?>" /></td></tr>
                    <tr><th><?php echo esc_html__('JWT Clock Skew (seconds)', 'secure-guard'); ?></th><td><input type="number" min="0" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[jwt_clock_skew_seconds]" value="<?php echo esc_attr((string) $settings['jwt_clock_skew_seconds']); ?>" /></td></tr>
                    <tr><th><?php echo esc_html__('Content Security Policy', 'secure-guard'); ?></th><td><input type="text" class="regular-text" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[csp]" value="<?php echo esc_attr((string) $settings['csp']); ?>" /><p class="description"><?php echo esc_html__('Balanced CSP is enabled by default for tougher hardening. Override only if required by your theme/plugins.', 'secure-guard'); ?></p></td></tr>
                    <tr><th><?php echo esc_html__('Referrer Policy', 'secure-guard'); ?></th><td><input type="text" class="regular-text" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[referrer_policy]" value="<?php echo esc_attr((string) $settings['referrer_policy']); ?>" /></td></tr>
                    <tr><th><?php echo esc_html__('Permissions Policy', 'secure-guard'); ?></th><td><input type="text" class="regular-text" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[permissions_policy]" value="<?php echo esc_attr((string) $settings['permissions_policy']); ?>" /></td></tr>
                    <tr><th><?php echo esc_html__('Enable COOP', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[enable_coop]" value="1" <?php checked(!empty($settings['enable_coop'])); ?> /> <?php echo esc_html__('Send Cross-Origin-Opener-Policy: same-origin', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Enable CORP', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[enable_corp]" value="1" <?php checked(!empty($settings['enable_corp'])); ?> /> <?php echo esc_html__('Send Cross-Origin-Resource-Policy: same-site', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('Enable HSTS', 'secure-guard'); ?></th><td><label><input type="checkbox" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[enable_hsts]" value="1" <?php checked(!empty($settings['enable_hsts'])); ?> /> <?php echo esc_html__('Send Strict-Transport-Security on HTTPS', 'secure-guard'); ?></label></td></tr>
                    <tr><th><?php echo esc_html__('HSTS max-age', 'secure-guard'); ?></th><td><input type="number" min="0" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[hsts_max_age]" value="<?php echo esc_attr((string) $settings['hsts_max_age']); ?>" /></td></tr>
                    <tr><th><?php echo esc_html__('Log retention (days)', 'secure-guard'); ?></th><td><input type="number" min="1" name="<?php echo esc_attr(Secure_Guard_Config::OPTION_KEY); ?>[log_retention_days]" value="<?php echo esc_attr((string) $settings['log_retention_days']); ?>" /></td></tr>
                </table>
                <?php submit_button(); ?>
            </form>
            </div>
        </div>
        <?php
    }
}
