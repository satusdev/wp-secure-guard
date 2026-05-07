<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Rules_Page {
    public function register(): void {
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        $s          = Secure_Guard_Config::get_settings();
        $settings_url = admin_url('admin.php?page=secure-guard-settings');

        $on  = '<span class="sg-pill sg-pill--allowed">ON</span>';
        $off = '<span class="sg-pill sg-pill--blocked">OFF</span>';

        /**
         * Each entry: [ label, setting_key|null, description, settings_tab ]
         */
        $modules = [
            [
                'label'       => __('JWT-Only REST Mode', 'secure-guard'),
                'key'         => 'rest_lock_enabled',
                'description' => __('Enforces JWT bearer tokens on all external REST requests. Logged-in WP users bypass this gate automatically.', 'secure-guard'),
                'tab'         => 'rest-jwt',
            ],
            [
                'label'       => __('Block Sensitive Endpoints', 'secure-guard'),
                'key'         => 'block_sensitive_endpoints',
                'description' => __('Routes like /wp/v2/users require full_api_access scope even with a valid JWT.', 'secure-guard'),
                'tab'         => 'rest-jwt',
            ],
            [
                'label'       => __('Login Protection', 'secure-guard'),
                'key'         => 'login_protection_enabled',
                'description' => __('IP-based lockouts on repeated failed login attempts.', 'secure-guard'),
                'tab'         => 'login',
            ],
            [
                'label'       => __('Bot Rate Limiting', 'secure-guard'),
                'key'         => 'bot_rate_limit_enabled',
                'description' => __('Throttles unauthenticated request bursts from bots and scanners.', 'secure-guard'),
                'tab'         => 'rate-limiting',
            ],
            [
                'label'       => __('User Enumeration Blocking', 'secure-guard'),
                'key'         => 'block_user_enumeration',
                'description' => __('Blocks author query strings, author archives, and REST /users probes.', 'secure-guard'),
                'tab'         => 'rate-limiting',
            ],
            [
                'label'       => __('XML-RPC Blocking', 'secure-guard'),
                'key'         => 'block_xmlrpc',
                'description' => __('Hard-blocks xmlrpc.php and the WordPress XML-RPC filter.', 'secure-guard'),
                'tab'         => 'rate-limiting',
            ],
            [
                'label'       => __('WP-Cron Public Access Block', 'secure-guard'),
                'key'         => 'block_public_wp_cron',
                'description' => __('Prevents external HTTP requests to wp-cron.php while allowing internal execution.', 'secure-guard'),
                'tab'         => 'rate-limiting',
            ],
            [
                'label'       => __('Security Headers', 'secure-guard'),
                'key'         => null, // always on — no toggle exists for this module
                'description' => __('Adds CSP, Referrer-Policy, Permissions-Policy, COOP, CORP, HSTS headers to responses.', 'secure-guard'),
                'tab'         => 'headers',
            ],
            [
                'label'       => __('WP Fingerprint Hardening', 'secure-guard'),
                'key'         => 'hide_wp_info',
                'description' => __('Removes WordPress version meta, readme.html, license.txt, and other fingerprinting vectors.', 'secure-guard'),
                'tab'         => 'hardening',
            ],
            [
                'label'       => __('File Integrity Monitoring', 'secure-guard'),
                'key'         => 'file_integrity_enabled',
                'description' => __('Periodically hashes core WordPress files and alerts on unexpected changes.', 'secure-guard'),
                'tab'         => 'hardening',
            ],
            [
                'label'       => __('Admin Area Protection', 'secure-guard'),
                'key'         => 'admin_area_protection_enabled',
                'description' => __('Blocks unauthenticated non-AJAX requests to /wp-admin from IPs not on the whitelist.', 'secure-guard'),
                'tab'         => 'hardening',
            ],
        ];
        ?>
        <div class="wrap secure-guard-ui">
            <h1><?php echo esc_html__('Security Rules', 'secure-guard'); ?></h1>
            <p class="description"><?php echo esc_html__('Live status of all Secure Guard protection modules. Click the Settings link to configure any module.', 'secure-guard'); ?></p>

            <div class="card" style="max-width:1100px;padding:16px;">
                <h2 style="margin-top:0;"><?php esc_html_e('Module Status', 'secure-guard'); ?></h2>
                <table class="widefat striped">
                    <thead>
                        <tr>
                            <th style="width:220px;"><?php esc_html_e('Module', 'secure-guard'); ?></th>
                            <th style="width:70px;"><?php esc_html_e('Status', 'secure-guard'); ?></th>
                            <th><?php esc_html_e('Description', 'secure-guard'); ?></th>
                            <th style="width:100px;"><?php esc_html_e('Configure', 'secure-guard'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($modules as $module): 
                            $config_url = add_query_arg('tab', $module['tab'], $settings_url);
                            if ($module['label'] === __('Global IP Whitelist', 'secure-guard') || $module['label'] === __('Admin Area Protection', 'secure-guard')) {
                                $config_url = add_query_arg('tab', 'whitelist', $settings_url);
                            }
                        ?>
                        <tr>
                            <td><strong><?php echo esc_html($module['label']); ?></strong></td>
                            <td><?php echo ($module['key'] === null || !empty($s[$module['key']])) ? $on : $off; // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
                            <td><?php echo esc_html($module['description']); ?></td>
                            <td><a href="<?php echo esc_url($config_url); ?>"><?php esc_html_e('Settings →', 'secure-guard'); ?></a></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="card" style="max-width:1100px;padding:16px;margin-top:16px;">
                <h2 style="margin-top:0;"><?php echo esc_html__('Constant Overrides', 'secure-guard'); ?></h2>
                <p class="description"><?php esc_html_e('These PHP constants, when defined in wp-config.php, take precedence over all other settings.', 'secure-guard'); ?></p>
                <table class="widefat striped">
                    <thead><tr><th><?php esc_html_e('Constant', 'secure-guard'); ?></th><th><?php esc_html_e('Defined?', 'secure-guard'); ?></th><th><?php esc_html_e('Purpose', 'secure-guard'); ?></th></tr></thead>
                    <tbody>
                        <tr><td><code>SECURE_GUARD_JWT_SECRET</code></td><td><?php echo defined('SECURE_GUARD_JWT_SECRET') ? $on : $off; // phpcs:ignore WordPress.Security.EscapeOutput ?></td><td><?php esc_html_e('Overrides the JWT signing secret stored in the database.', 'secure-guard'); ?></td></tr>
                    </tbody>
                </table>
            </div>

            <div class="card" style="max-width:1100px;padding:16px;margin-top:16px;">
                <h2 style="margin-top:0;"><?php echo esc_html__('Environment Variable Overrides', 'secure-guard'); ?></h2>
                <p class="description"><?php esc_html_e('Environment variables (set in .env for Bedrock / phpdotenv, or via server config) take precedence over database settings and yield only to PHP constants. Setting the same issuer and audience across all environments means tokens survive a staging-to-production database clone without re-signing.', 'secure-guard'); ?></p>
                <p class="description" style="margin-top:6px;"><strong><?php esc_html_e('Bedrock .env example:', 'secure-guard'); ?></strong></p>
                <pre style="margin:4px 0 12px;background:#f6f7f7;padding:10px 14px;border-radius:3px;font-size:12px;">SECURE_GUARD_JWT_SECRET=your-long-random-secret-here
SECURE_GUARD_JWT_ISSUER=https://example.com/
SECURE_GUARD_JWT_AUDIENCE=https://example.com/</pre>
                <table class="widefat striped">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Variable', 'secure-guard'); ?></th>
                            <th style="width:90px;"><?php esc_html_e('Active?', 'secure-guard'); ?></th>
                            <th><?php esc_html_e('Purpose', 'secure-guard'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (Secure_Guard_Config::ENV_VARS as $setting_key => $env_var_name): ?>
                        <tr>
                            <td><code><?php echo esc_html($env_var_name); ?></code></td>
                            <td><?php echo Secure_Guard_Config::is_env_overridden($setting_key) ? $on : $off; // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
                            <td><?php
                                $labels = [
                                    'jwt_secret'   => __('JWT signing secret. Overrides database setting; yields to SECURE_GUARD_JWT_SECRET constant.', 'secure-guard'),
                                    'jwt_issuer'   => __('JWT issuer claim (iss). Tokens are only valid when this matches the value at signing time.', 'secure-guard'),
                                    'jwt_audience' => __('JWT audience claim (aud). Tokens are only valid when this matches the value at signing time.', 'secure-guard'),
                                ];
                                echo esc_html($labels[$setting_key] ?? '');
                            ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="card" style="max-width:1100px;padding:16px;margin-top:16px;">
                <h2 style="margin-top:0;"><?php echo esc_html__('Usage & Verification', 'secure-guard'); ?></h2>
                <p class="description"><?php echo esc_html__('Replace SITE and TOKEN values. Without JWT expect 403; with valid JWT expect route-specific responses.', 'secure-guard'); ?></p>
                <pre style="white-space:pre-wrap;"><?php echo esc_html("# 1) Without token (expect 403)\ncurl -i https://SITE/wp-json/wp/v2/posts\n\n# 2) With token to non-sensitive route\ncurl -i -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/posts\n\n# 3) With token to sensitive route (requires full_api_access when enabled)\ncurl -i -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/users\n\n# 4) Legacy rest_route query format\ncurl -i -H \"Authorization: Bearer TOKEN\" \"https://SITE/?rest_route=/wp/v2/posts\""); ?></pre>
            </div>
        </div>
        <?php
    }
}
