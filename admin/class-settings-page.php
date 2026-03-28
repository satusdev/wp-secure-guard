<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Settings_Page {
    /** @var array<string,string> */
    private const TABS = [
        'rest-jwt'      => 'REST & JWT',
        'login'         => 'Login Protection',
        'rate-limiting' => 'Rate Limiting',
        'headers'       => 'Security Headers',
        'hardening'     => 'Hardening',
        'alerts'        => 'Alerts',
    ];

    public function register(): void {
        register_setting(
            'secure_guard_settings_group',
            Secure_Guard_Config::OPTION_KEY,
            [
                'type'              => 'array',
                'sanitize_callback' => [$this, 'sanitize'],
                'default'           => Secure_Guard_Config::defaults(),
            ]
        );
    }

    public function sanitize($input): array {
        $input = is_array($input) ? $input : [];
        // Merge currently stored settings so keys absent from the current tab’s form
        // (fields rendered on other tabs) keep their stored value rather than being
        // silently reset to 0 / empty. This prevents data-loss when saving a single tab.
        $stored = get_option(Secure_Guard_Config::OPTION_KEY, []);
        if (is_array($stored) && $stored !== []) {
            $input = array_merge($stored, $input);
        }
        return Secure_Guard_Config::save_settings($input);
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        $settings   = Secure_Guard_Config::get_settings();
        $roles      = wp_roles()->roles;
        $active_tab = isset($_GET['tab']) ? sanitize_key((string) $_GET['tab']) : 'rest-jwt';
        if (!array_key_exists($active_tab, self::TABS)) {
            $active_tab = 'rest-jwt';
        }

        $page_base = admin_url('admin.php?page=secure-guard-settings');
        ?>
        <div class="wrap secure-guard-ui">
            <h1><?php esc_html_e('Settings', 'secure-guard'); ?></h1>

            <nav class="nav-tab-wrapper wp-clearfix">
                <?php foreach (self::TABS as $slug => $label): ?>
                    <a href="<?php echo esc_url(add_query_arg('tab', $slug, $page_base)); ?>"
                       class="nav-tab<?php echo $active_tab === $slug ? ' nav-tab-active' : ''; ?>">
                        <?php echo esc_html__($label, 'secure-guard'); ?>
                    </a>
                <?php endforeach; ?>
            </nav>

            <div class="card sg-settings-card">
                <form method="post" action="options.php">
                    <?php settings_fields('secure_guard_settings_group'); ?>
                    <table class="form-table" role="presentation">
                        <?php $this->render_tab($active_tab, $settings, $roles); ?>
                    </table>
                    <?php submit_button(); ?>
                </form>
            </div>
        </div>

        <script>
        (function() {
            document.addEventListener('DOMContentLoaded', function() {
                document.querySelectorAll('.sg-reveal-secret').forEach(function(btn) {
                    var targetId = btn.getAttribute('data-target');
                    var input    = document.getElementById(targetId);
                    if (!input) return;
                    btn.addEventListener('click', function() {
                        var isHidden = input.type === 'password';
                        input.type   = isHidden ? 'text' : 'password';
                        btn.textContent = isHidden
                            ? btn.getAttribute('data-hide')
                            : btn.getAttribute('data-show');
                    });
                });
            });
        })();
        </script>
        <?php
    }

    private function render_tab(string $tab, array $s, array $roles): void {
        $k = Secure_Guard_Config::OPTION_KEY;

        switch ($tab) {
            case 'rest-jwt':
                $this->row_checkbox($k, 'rest_lock_enabled', $s,
                    __('JWT-Only REST Mode', 'secure-guard'),
                    __('Enforce JWT bearer tokens on all external REST requests. Logged-in browser sessions (Gutenberg, Elementor, Divi, media library) always bypass this gate.', 'secure-guard')
                );
                $this->row_checkbox($k, 'block_sensitive_endpoints', $s,
                    __('Block Sensitive Endpoints', 'secure-guard'),
                    __('Routes marked sensitive require full_api_access scope even with a valid JWT.', 'secure-guard')
                );
                $this->row_checkbox($k, 'log_allowed_requests', $s,
                    __('Log Allowed Requests', 'secure-guard'),
                    __('Write a DB log entry for each successfully authenticated JWT API request. Disable on high-traffic sites to reduce write pressure.', 'secure-guard')
                );
                $this->row_number($k, 'rate_limit_per_minute', $s,
                    __('Token Rate Limit (req/min)', 'secure-guard'),
                    __('Per-token request cap applied to external Bearer token callers.', 'secure-guard'),
                    1
                );
                echo '<tr><th colspan="2"><h3 style="margin:8px 0 0;font-size:13px;font-weight:600;border-top:1px solid #dcdcde;padding-top:12px;">'
                    . esc_html__('JWT Configuration', 'secure-guard') . '</h3></th></tr>';
                // AUTH_KEY fallback warning — shown when no explicit secret is configured anywhere.
                if (empty($s['jwt_secret']) && !defined('SECURE_GUARD_JWT_SECRET') && !Secure_Guard_Config::is_env_overridden('jwt_secret')) {
                    echo '<tr><td colspan="2"><div class="notice notice-warning inline" style="margin:8px 0 4px;">'
                        . '<p>' . esc_html__('No JWT secret is set. Tokens are currently signed using WordPress AUTH_KEY. If AUTH_KEY changes (e.g., after a security reset), all issued tokens will be invalidated. Set an explicit secret below for stability.', 'secure-guard') . '</p>'
                        . '</div></td></tr>';
                }
                ?>
                <tr>
                    <td colspan="2">
                        <div class="notice notice-info inline" style="margin:4px 0 8px;">
                            <p><strong><?php esc_html_e('Migrating to a new server?', 'secure-guard'); ?></strong>
                            <?php esc_html_e('Copy the JWT secret from your old site and paste it here. All tokens are cryptographically bound to this secret — if it changes every previously issued token is immediately invalidated.', 'secure-guard'); ?></p>
                        </div>
                    </td>
                </tr>
                <tr>
                    <th><?php esc_html_e('JWT Secret', 'secure-guard'); ?></th>
                    <td>
                        <?php if (Secure_Guard_Config::is_env_overridden('jwt_secret')): ?>
                            <p><span class="sg-pill sg-pill--info">ENV</span> <code>SECURE_GUARD_JWT_SECRET</code></p>
                            <input type="hidden" name="<?php echo esc_attr($k); ?>[jwt_secret]" value="" />
                            <p class="description"><?php esc_html_e('Controlled by the SECURE_GUARD_JWT_SECRET environment variable. Remove the env var to manage it here.', 'secure-guard'); ?></p>
                        <?php else: ?>
                            <div class="sg-secret-wrap">
                                <input type="password" id="sg_jwt_secret" class="regular-text"
                                    name="<?php echo esc_attr($k); ?>[jwt_secret]"
                                    value="<?php echo esc_attr((string) $s['jwt_secret']); ?>"
                                    autocomplete="new-password" />
                                <button type="button" class="button button-secondary sg-reveal-secret"
                                    data-target="sg_jwt_secret"
                                    data-show="<?php esc_attr_e('Show', 'secure-guard'); ?>"
                                    data-hide="<?php esc_attr_e('Hide', 'secure-guard'); ?>">
                                    <?php esc_html_e('Show', 'secure-guard'); ?>
                                </button>
                            </div>
                            <p class="description"><?php esc_html_e('Optional. If empty, falls back to SECURE_GUARD_JWT_SECRET constant, then AUTH_KEY. Bedrock: add SECURE_GUARD_JWT_SECRET to .env.', 'secure-guard'); ?></p>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php
                $this->row_url_env($k, 'jwt_issuer', $s, __('JWT Issuer', 'secure-guard'), '', 'SECURE_GUARD_JWT_ISSUER');
                $this->row_url_env($k, 'jwt_audience', $s, __('JWT Audience', 'secure-guard'), '', 'SECURE_GUARD_JWT_AUDIENCE');
                $this->row_number($k, 'jwt_ttl_minutes', $s, __('JWT TTL (minutes)', 'secure-guard'), '', 1);
                $this->row_number($k, 'jwt_clock_skew_seconds', $s, __('JWT Clock Skew (seconds)', 'secure-guard'), '', 0);
                break;

            case 'login':
                $this->row_checkbox($k, 'login_protection_enabled', $s,
                    __('Login Protection', 'secure-guard'),
                    __('Enable IP-based lockouts on repeated failed login attempts.', 'secure-guard')
                );
                $this->row_number($k, 'login_short_threshold', $s,
                    __('Short Block Threshold', 'secure-guard'),
                    __('Failed attempts before the first short lockout triggers.', 'secure-guard'),
                    1
                );
                $this->row_number($k, 'login_medium_threshold', $s,
                    __('Medium Block Threshold', 'secure-guard'),
                    '',
                    1
                );
                $this->row_number($k, 'login_hard_block_threshold', $s,
                    __('Hard Block Threshold', 'secure-guard'),
                    __('Triggers an extended IP-level block.', 'secure-guard'),
                    1
                );
                break;

            case 'rate-limiting':
                $this->row_checkbox($k, 'bot_rate_limit_enabled', $s,
                    __('Bot Rate Limiting', 'secure-guard'),
                    __('Throttle anonymous IP traffic. All logged-in users (any role) are automatically exempt.', 'secure-guard')
                );
                $this->row_number($k, 'bot_rate_limit_per_minute', $s,
                    __('Requests per Minute', 'secure-guard'),
                    __('Anonymous requests allowed per IP per minute before a block is applied.', 'secure-guard'),
                    1
                );
                $this->row_number($k, 'bot_block_minutes', $s,
                    __('Block Duration (minutes)', 'secure-guard'),
                    '',
                    1
                );
                $this->row_number($k, 'scan_404_threshold', $s,
                    __('404 Scan Threshold', 'secure-guard'),
                    __('Number of 404s in a 10-minute window before the IP is blocked for 24 hours.', 'secure-guard'),
                    1
                );
                $this->row_checkbox($k, 'block_user_enumeration', $s,
                    __('Block User Enumeration', 'secure-guard'),
                    __('Block author query strings, author archive paths, and direct /wp/v2/users probes.', 'secure-guard')
                );
                $this->row_checkbox($k, 'block_xmlrpc', $s,
                    __('Block XML-RPC', 'secure-guard'),
                    __('Return 403 for any direct request to xmlrpc.php.', 'secure-guard')
                );
                $this->row_checkbox($k, 'block_public_wp_cron', $s,
                    __('Block Public WP-Cron', 'secure-guard'),
                    __('Deny external HTTP access to wp-cron.php. Internal and CLI cron execution are unaffected.', 'secure-guard')
                );
                echo '<tr><th>' . esc_html__('Global IP Whitelist', 'secure-guard') . '</th><td>';
                echo '<textarea rows="6" cols="60" name="' . esc_attr($k) . '[ip_whitelist]">'
                    . esc_textarea((string) $s['ip_whitelist']) . '</textarea>';
                echo '<p class="description">' . esc_html__('One IPv4 / IPv6 / CIDR per line. These IPs bypass all rate limiting and block checks.', 'secure-guard') . '</p></td></tr>';

                echo '<tr><th>' . esc_html__('Allowed User Roles', 'secure-guard') . '</th><td>';
                foreach ($roles as $role_key => $role) {
                    echo '<label style="display:block"><input type="checkbox"'
                        . ' name="' . esc_attr($k) . '[allowed_roles][]"'
                        . ' value="' . esc_attr($role_key) . '"'
                        . ' ' . checked(in_array($role_key, $s['allowed_roles'], true), true, false) . ' /> '
                        . esc_html($role['name']) . '</label>';
                }
                echo '<p class="description">' . esc_html__('Legacy role-bypass list. Note: all logged-in users already bypass JWT enforcement regardless of this setting.', 'secure-guard') . '</p></td></tr>';
                break;

            case 'headers':
                echo '<tr><th>' . esc_html__('Content Security Policy', 'secure-guard') . '</th><td>';
                echo '<input type="text" class="large-text" name="' . esc_attr($k) . '[csp]" value="' . esc_attr((string) $s['csp']) . '" />';
                echo '<p class="description">' . esc_html__('Leave empty to use the default balanced CSP. Override only when required by your theme or plugins.', 'secure-guard') . '</p></td></tr>';
                $this->row_text($k, 'referrer_policy', $s, __('Referrer Policy', 'secure-guard'), '');
                $this->row_text($k, 'permissions_policy', $s, __('Permissions Policy', 'secure-guard'), '');
                $this->row_checkbox($k, 'enable_coop', $s,
                    __('COOP', 'secure-guard'),
                    __('Send Cross-Origin-Opener-Policy: same-origin.', 'secure-guard')
                );
                $this->row_checkbox($k, 'enable_corp', $s,
                    __('CORP', 'secure-guard'),
                    __('Send Cross-Origin-Resource-Policy: same-site.', 'secure-guard')
                );
                $this->row_checkbox($k, 'enable_hsts', $s,
                    __('HSTS', 'secure-guard'),
                    __('Send Strict-Transport-Security on HTTPS connections.', 'secure-guard')
                );
                $this->row_number($k, 'hsts_max_age', $s, __('HSTS max-age (seconds)', 'secure-guard'), '', 0);
                break;

            case 'hardening':
                $this->row_checkbox($k, 'hide_wp_info', $s,
                    __('Hide WordPress Fingerprint', 'secure-guard'),
                    __('Remove generator tags, version query strings, and block readme/license/debug.log probes.', 'secure-guard')
                );
                $this->row_checkbox($k, 'file_integrity_enabled', $s,
                    __('File Integrity Monitoring', 'secure-guard'),
                    __('Run hourly checksum scans of wp-admin and wp-includes and alert on changes.', 'secure-guard')
                );
                $this->row_checkbox($k, 'admin_area_protection_enabled', $s,
                    __('Admin Area Protection', 'secure-guard'),
                    __('Guard /wp-admin pages from unauthenticated access. admin-ajax.php is always exempt so public AJAX handlers work.', 'secure-guard')
                );
                echo '<tr><th>' . esc_html__('Admin IP Whitelist', 'secure-guard') . '</th><td>';
                echo '<textarea rows="4" cols="60" name="' . esc_attr($k) . '[admin_ip_whitelist]">'
                    . esc_textarea((string) $s['admin_ip_whitelist']) . '</textarea>';
                echo '<p class="description">' . esc_html__('Optional. If set, only these IPs can access /wp-admin pages.', 'secure-guard') . '</p></td></tr>';
                echo '<tr><th>' . esc_html__('Trusted Proxy IPs', 'secure-guard') . '</th><td>';
                echo '<textarea rows="4" cols="60" name="' . esc_attr($k) . '[trusted_proxy_ips]">'
                    . esc_textarea((string) ($s['trusted_proxy_ips'] ?? '')) . '</textarea>';
                echo '<p class="description">' . esc_html__('Forwarded-For headers are trusted only when REMOTE_ADDR matches this list.', 'secure-guard') . '</p></td></tr>';
                $this->row_number($k, 'log_retention_days', $s,
                    __('Log Retention (days)', 'secure-guard'),
                    __('Log entries older than this are automatically purged by the scheduled maintenance task.', 'secure-guard'),
                    1
                );
                break;
            case 'alerts':
                $this->row_checkbox($k, 'email_alerts_enabled', $s,
                    __('Enable Email Alerts', 'secure-guard'),
                    __('Send email notifications to the site admin address for security events. Uses wp_mail().', 'secure-guard')
                );
                echo '<tr><td colspan="2"><p class="description" style="padding:0 0 4px;">';
                $admin_email = esc_html((string) get_option('admin_email', ''));
                /* translators: %s is the admin email address */
                printf(esc_html__('Alerts are sent to the site admin address: %s', 'secure-guard'), '<strong>' . $admin_email . '</strong>');
                echo '</p></td></tr>';
                $this->row_checkbox($k, 'alert_on_hard_block', $s,
                    __('Alert on Hard IP Block', 'secure-guard'),
                    __('Send an email when an IP is hard-blocked by the bot rate limiter or login protection.', 'secure-guard')
                );
                $this->row_checkbox($k, 'alert_on_integrity', $s,
                    __('Alert on File Integrity Changes', 'secure-guard'),
                    __('Send an email when the hourly integrity scan detects added, modified, or deleted core files.', 'secure-guard')
                );
                $this->row_number($k, 'alert_on_token_expiry_days', $s,
                    __('Token Expiry Warning (days)', 'secure-guard'),
                    __('Send an email when a JWT token will expire within this many days. Set to 0 to disable.', 'secure-guard'),
                    0
                );
                break;
        }
    }

    private function row_checkbox(string $k, string $field, array $s, string $label, string $desc = ''): void {
        echo '<tr><th>' . esc_html($label) . '</th><td>';
        // Hidden field ensures an unchecked box on the active tab submits "0" rather than
        // nothing, so it is not confused with a field on a different (non-rendered) tab.
        echo '<input type="hidden" name="' . esc_attr($k) . '[' . esc_attr($field) . ']" value="0" />';
        echo '<label><input type="checkbox" name="' . esc_attr($k) . '[' . esc_attr($field) . ']" value="1" '
            . checked(!empty($s[$field]), true, false) . ' />';
        if ($desc !== '') {
            echo ' <span class="description">' . esc_html($desc) . '</span>';
        }
        echo '</label></td></tr>';
    }

    private function row_number(string $k, string $field, array $s, string $label, string $desc = '', int $min = 1): void {
        echo '<tr><th>' . esc_html($label) . '</th><td>';
        echo '<input type="number" min="' . esc_attr((string) $min) . '" class="small-text"'
            . ' name="' . esc_attr($k) . '[' . esc_attr($field) . ']"'
            . ' value="' . esc_attr((string) ($s[$field] ?? $min)) . '" />';
        if ($desc !== '') {
            echo '<p class="description">' . esc_html($desc) . '</p>';
        }
        echo '</td></tr>';
    }

    private function row_text(string $k, string $field, array $s, string $label, string $desc = ''): void {
        echo '<tr><th>' . esc_html($label) . '</th><td>';
        echo '<input type="text" class="regular-text"'
            . ' name="' . esc_attr($k) . '[' . esc_attr($field) . ']"'
            . ' value="' . esc_attr((string) ($s[$field] ?? '')) . '" />';
        if ($desc !== '') {
            echo '<p class="description">' . esc_html($desc) . '</p>';
        }
        echo '</td></tr>';
    }

    private function row_url(string $k, string $field, array $s, string $label, string $desc = ''): void {
        echo '<tr><th>' . esc_html($label) . '</th><td>';
        // type="text" instead of type="url" — browsers reject valid URLs like
        // http://localhost:8080/ or custom-scheme URIs under strict url validation.
        echo '<input type="text" class="regular-text"'
            . ' name="' . esc_attr($k) . '[' . esc_attr($field) . ']"'
            . ' value="' . esc_attr((string) ($s[$field] ?? '')) . '" />';
        if ($desc !== '') {
            echo '<p class="description">' . esc_html($desc) . '</p>';
        }
        echo '</td></tr>';
    }

    private function row_url_env(string $k, string $field, array $s, string $label, string $desc, string $env_var_name): void {
        echo '<tr><th>' . esc_html($label) . '</th><td>';
        if (Secure_Guard_Config::is_env_overridden($field)) {
            echo '<p><span class="sg-pill sg-pill--info">ENV</span> <code>' . esc_html($env_var_name) . '</code></p>';
            // Show the resolved value as readonly for visual confirmation, but do not
            // allow editing. The hidden input submits empty; save_settings() restores
            // the existing DB value so the fallback is preserved if the env var is removed.
            echo '<input type="text" class="regular-text" value="' . esc_attr((string) ($s[$field] ?? '')) . '" readonly disabled />';
            echo '<input type="hidden" name="' . esc_attr($k) . '[' . esc_attr($field) . ']" value="" />';
            echo '<p class="description">' . sprintf(
                /* translators: %s is the environment variable name */
                esc_html__('Controlled by the %s environment variable. Remove the env var to manage it here.', 'secure-guard'),
                '<code>' . esc_html($env_var_name) . '</code>'
            ) . '</p>';
        } else {
            echo '<input type="text" class="regular-text"'
                . ' name="' . esc_attr($k) . '[' . esc_attr($field) . ']"'
                . ' value="' . esc_attr((string) ($s[$field] ?? '')) . '" />';
            if ($desc !== '') {
                echo '<p class="description">' . esc_html($desc) . '</p>';
            }
        }
        echo '</td></tr>';
    }
}
