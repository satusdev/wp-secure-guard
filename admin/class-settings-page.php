<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Settings_Page {
    /** @var array<string,string> */
    private const TABS = [
        'rest-jwt'      => 'REST & JWT',
        'whitelist'     => 'Whitelists',
        'login'         => 'Login Protection',
        'rate-limiting' => 'Rate Limiting',
        'headers'       => 'Security Headers',
        'hardening'     => 'Hardening',
        'adaptive-security' => 'Adaptive Security',
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
        add_action('wp_ajax_sg_generate_secret', [$this, 'ajax_generate_secret']);
    }

    public function ajax_generate_secret(): void {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        check_ajax_referer('sg_settings_nonce', 'nonce');
        
        $secret = bin2hex(random_bytes(32));
        wp_send_json_success(['secret' => $secret]);
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
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        $settings   = Secure_Guard_Config::get_settings();
        $roles      = wp_roles()->roles;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $active_tab = isset($_GET['tab']) ? sanitize_key(wp_unslash((string) $_GET['tab'])) : 'rest-jwt';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $page_slug = isset($_GET['page']) ? sanitize_key(wp_unslash((string) $_GET['page'])) : '';
        if ($page_slug === 'secure-guard-whitelists') {
            $active_tab = 'whitelist';
        }
        if (!array_key_exists($active_tab, self::TABS)) {
            $active_tab = 'rest-jwt';
        }

        $page_base = admin_url('admin.php?page=secure-guard-settings');
        ?>
        <div class="wrap secure-guard-ui">
            <h1><?php esc_html_e('Settings', 'wp-secure-guard'); ?></h1>

            <nav class="nav-tab-wrapper wp-clearfix">
                <?php
                $translated_tabs = [
                    'rest-jwt'          => esc_html__('REST & JWT', 'wp-secure-guard'),
                    'whitelist'         => esc_html__('Whitelists', 'wp-secure-guard'),
                    'login'             => esc_html__('Login Protection', 'wp-secure-guard'),
                    'rate-limiting'     => esc_html__('Rate Limiting', 'wp-secure-guard'),
                    'headers'           => esc_html__('Security Headers', 'wp-secure-guard'),
                    'hardening'         => esc_html__('Hardening', 'wp-secure-guard'),
                    'adaptive-security' => esc_html__('Adaptive Security', 'wp-secure-guard'),
                    'alerts'            => esc_html__('Alerts', 'wp-secure-guard'),
                ];
                ?>
                <?php foreach ($translated_tabs as $slug => $label): ?>
                    <?php $tab_class = $active_tab === $slug ? ' nav-tab-active' : ''; ?>
                    <a href="<?php echo esc_url(add_query_arg('tab', $slug, $page_base)); ?>"
                       class="nav-tab<?php echo esc_attr($tab_class); ?>">
                        <?php echo esc_html($label); ?>
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

                document.querySelectorAll('.sg-generate-secret').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        if (!confirm('<?php echo esc_js(__('Generating a new secret will immediately invalidate ALL existing JWT tokens. This cannot be undone. Continue?', 'wp-secure-guard')); ?>')) {
                            return;
                        }
                        
                        btn.disabled = true;
                        var originalText = btn.textContent;
                        btn.textContent = '...';

                        jQuery.post(sg_admin_params.ajax_url, {
                            action: 'sg_generate_secret',
                            nonce: sg_admin_params.nonce
                        }, function(response) {
                            btn.disabled = false;
                            btn.textContent = originalText;
                            if (response.success) {
                                var targetId = btn.getAttribute('data-target');
                                var input = document.getElementById(targetId);
                                if (input) {
                                    input.value = response.data.secret;
                                    input.type = 'text';
                                    var revealBtn = document.querySelector('.sg-reveal-secret[data-target="' + targetId + '"]');
                                    if (revealBtn) {
                                        revealBtn.textContent = revealBtn.getAttribute('data-hide');
                                    }
                                }
                            }
                        });
                    });
                });

                document.querySelectorAll('.sg-add-bot-ua').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        var ua = btn.getAttribute('data-ua');
                        var textarea = document.getElementById('sg_allowed_bot_user_agents');
                        if (!textarea) return;
                        var currentVal = textarea.value.trim();
                        var lines = currentVal ? currentVal.split('\n') : [];
                        lines = lines.map(function(l) { return l.trim(); }).filter(function(l) { return l !== ''; });
                        if (lines.indexOf(ua) === -1) {
                            lines.push(ua);
                            textarea.value = lines.join('\n') + '\n';
                        }
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
                    __('JWT-Only REST Mode', 'wp-secure-guard'),
                    __('Enforce JWT bearer tokens on all external REST requests. Logged-in browser sessions (Gutenberg, Elementor, Divi, media library) always bypass this gate.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'block_sensitive_endpoints', $s,
                    __('Block Sensitive Endpoints', 'wp-secure-guard'),
                    __('Routes marked sensitive require full_api_access scope even with a valid JWT.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'rest_strict_mode', $s,
                    __('REST Strict Mode', 'wp-secure-guard'),
                    __('Completely disable the REST API for all unauthenticated users. Discovery links will also be removed from the site header.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'log_allowed_requests', $s,
                    __('Log Allowed Requests', 'wp-secure-guard'),
                    __('Write a DB log entry for each successfully authenticated JWT API request. Disable on high-traffic sites to reduce write pressure.', 'wp-secure-guard')
                );
                $this->row_number($k, 'rate_limit_per_minute', $s,
                    __('Token Rate Limit (req/min)', 'wp-secure-guard'),
                    __('Per-token request cap applied to external Bearer token callers.', 'wp-secure-guard'),
                    1
                );
                echo '<tr><th colspan="2"><h3 style="margin:8px 0 0;font-size:13px;font-weight:600;border-top:1px solid #dcdcde;padding-top:12px;">'
                    . esc_html__('JWT Configuration', 'wp-secure-guard') . '</h3></th></tr>';
                // AUTH_KEY fallback warning — shown when no explicit secret is configured anywhere.
                if (empty($s['jwt_secret']) && !defined('SECURE_GUARD_JWT_SECRET') && !Secure_Guard_Config::is_env_overridden('jwt_secret')) {
                    echo '<tr><td colspan="2"><div class="notice notice-warning inline" style="margin:8px 0 4px;">'
                        . '<p>' . esc_html__('No JWT secret is set. Tokens are currently signed using WordPress AUTH_KEY. If AUTH_KEY changes (e.g., after a security reset), all issued tokens will be invalidated. Set an explicit secret below for stability.', 'wp-secure-guard') . '</p>'
                        . '</div></td></tr>';
                }
                ?>
                <tr>
                    <td colspan="2">
                        <div class="notice notice-info inline" style="margin:4px 0 8px;">
                            <p><strong><?php esc_html_e('Migrating to a new server?', 'wp-secure-guard'); ?></strong>
                            <?php esc_html_e('Copy the JWT secret from your old site and paste it here. All tokens are cryptographically bound to this secret — if it changes every previously issued token is immediately invalidated.', 'wp-secure-guard'); ?></p>
                        </div>
                    </td>
                </tr>
                <tr>
                    <th><?php esc_html_e('JWT Secret', 'wp-secure-guard'); ?></th>
                    <td>
                        <?php if (Secure_Guard_Config::is_env_overridden('jwt_secret')): ?>
                            <p><span class="sg-pill sg-pill--info">ENV</span> <code>SECURE_GUARD_JWT_SECRET</code></p>
                            <input type="hidden" name="<?php echo esc_attr($k); ?>[jwt_secret]" value="" />
                            <p class="description"><?php esc_html_e('Controlled by the SECURE_GUARD_JWT_SECRET environment variable. Remove the env var to manage it here.', 'wp-secure-guard'); ?></p>
                        <?php else: ?>
                            <div class="sg-secret-wrap">
                                <input type="password" id="sg_jwt_secret" class="regular-text"
                                    name="<?php echo esc_attr($k); ?>[jwt_secret]"
                                    value="<?php echo esc_attr((string) $s['jwt_secret']); ?>"
                                    autocomplete="new-password" />
                                <button type="button" class="button button-secondary sg-reveal-secret"
                                    data-target="sg_jwt_secret"
                                    data-show="<?php esc_attr_e('Show', 'wp-secure-guard'); ?>"
                                    data-hide="<?php esc_attr_e('Hide', 'wp-secure-guard'); ?>">
                                    <?php esc_html_e('Show', 'wp-secure-guard'); ?>
                                </button>
                                <button type="button" class="button button-secondary sg-generate-secret"
                                    data-target="sg_jwt_secret">
                                    <?php esc_html_e('Generate', 'wp-secure-guard'); ?>
                                </button>
                            </div>
                            <p class="description"><?php esc_html_e('Optional. If empty, falls back to SECURE_GUARD_JWT_SECRET constant, then AUTH_KEY. Bedrock: add SECURE_GUARD_JWT_SECRET to .env.', 'wp-secure-guard'); ?></p>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php
                $this->row_url_env($k, 'jwt_issuer', $s, __('JWT Issuer', 'wp-secure-guard'), '', 'SECURE_GUARD_JWT_ISSUER');
                $this->row_url_env($k, 'jwt_audience', $s, __('JWT Audience', 'wp-secure-guard'), '', 'SECURE_GUARD_JWT_AUDIENCE');
                $this->row_number($k, 'jwt_ttl_minutes', $s, __('JWT TTL (minutes)', 'wp-secure-guard'), '', 1);
                $this->row_number( $k, 'jwt_clock_skew_seconds', $s, __( 'JWT Clock Skew (seconds)', 'wp-secure-guard' ), '', 0 );
                ?>
                <tr>
                    <th><?php esc_html_e( 'Hardened Binding', 'wp-secure-guard' ); ?></th>
                    <td>
                        <label style="display:block;margin-bottom:4px;">
                            <input type="checkbox" name="<?php echo esc_attr( $k ); ?>[bind_jwt_to_ip]" value="1" <?php checked( ! empty( $s['bind_jwt_to_ip'] ), 1 ); ?> />
                            <?php esc_html_e( 'Bind JWT to IP Address', 'wp-secure-guard' ); ?>
                        </label>
                        <label style="display:block;">
                            <input type="checkbox" name="<?php echo esc_attr( $k ); ?>[bind_jwt_to_ua]" value="1" <?php checked( ! empty( $s['bind_jwt_to_ua'] ), 1 ); ?> />
                            <?php esc_html_e( 'Bind JWT to User-Agent', 'wp-secure-guard' ); ?>
                        </label>
                        <p class="description"><?php esc_html_e( 'If enabled, tokens will only be valid if the request comes from the same IP/Browser that created it. Use with caution for mobile apps with shifting IPs.', 'wp-secure-guard' ); ?></p>
                    </td>
                </tr>
                <?php
                break;

            case 'whitelist':
                echo '<tr><th colspan="2"><h3 style="margin:8px 0 0;font-size:13px;font-weight:600;padding-top:4px;">'
                     . esc_html__( 'Global Access Rules', 'wp-secure-guard' ) . '</h3></th></tr>';

                echo '<tr><th>' . esc_html__( 'Global IP Whitelist', 'wp-secure-guard' ) . '</th><td>';
                echo '<textarea rows="6" cols="60" name="' . esc_attr( $k ) . '[ip_whitelist]">'
                     . esc_textarea( (string) $s['ip_whitelist'] ) . '</textarea>';
                echo '<p class="description">' . esc_html__( 'One IPv4 / IPv6 / CIDR per line. These IPs bypass all rate limiting and block checks.', 'wp-secure-guard' ) . '</p></td></tr>';

                echo '<tr><th>' . esc_html__( 'Admin Area IP Whitelist', 'wp-secure-guard' ) . '</th><td>';
                echo '<textarea rows="4" cols="60" name="' . esc_attr( $k ) . '[admin_ip_whitelist]">'
                     . esc_textarea( (string) $s['admin_ip_whitelist'] ) . '</textarea>';
                echo '<p class="description">' . esc_html__( 'If set, only these IPs can access /wp-admin pages (except admin-ajax.php).', 'wp-secure-guard' ) . '</p></td></tr>';

                echo '<tr><th>' . esc_html__( 'Allowed REST Namespaces', 'wp-secure-guard' ) . '</th><td>';
                echo '<textarea rows="6" cols="60" name="' . esc_attr( $k ) . '[allowed_rest_namespaces]">'
                     . esc_textarea( (string) ( $s['allowed_rest_namespaces'] ?? '' ) ) . '</textarea>';
                echo '<p class="description">' . esc_html__( 'One REST namespace per line (e.g. contact-form-7/v1). These bypass JWT enforcement and REST Strict Mode.', 'wp-secure-guard' ) . '</p></td></tr>';

                echo '<tr><th>' . esc_html__( 'Allowed Bot User-Agents / Ping Services', 'wp-secure-guard' ) . '</th><td>';
                echo '<textarea id="sg_allowed_bot_user_agents" rows="6" cols="60" name="' . esc_attr( $k ) . '[allowed_bot_user_agents]">'
                     . esc_textarea( (string) ( $s['allowed_bot_user_agents'] ?? '' ) ) . '</textarea>';
                echo '<p class="description">' . esc_html__( 'One User-Agent substring per line (e.g. UptimeRobot, Pingdom). Requests containing these User-Agents will bypass the behavioral bot fingerprinting and bad bot blocks.', 'wp-secure-guard' ) . '</p>';
                echo '<div style="margin-top: 10px;">';
                echo '<span style="font-weight: 500; display: block; margin-bottom: 5px;">' . esc_html__('Quick Allow Bot Services:', 'wp-secure-guard') . '</span>';
                $common_bots = [
                    'UptimeRobot' => 'UptimeRobot',
                    'Pingdom' => 'Pingdom',
                    'BetterStack' => 'BetterStack',
                    'NodePing' => 'NodePing',
                    'NewRelic' => 'New Relic',
                    'curl' => 'curl (Command line)',
                ];
                foreach ($common_bots as $ua_key => $ua_label) {
                    echo '<button type="button" class="button button-small sg-add-bot-ua" data-ua="' . esc_attr($ua_key) . '" style="margin-right: 5px; margin-bottom: 5px;">+ ' . esc_html($ua_label) . '</button>';
                }
                echo '</div>';
                echo '</td></tr>';

                echo '<tr><th colspan="2"><h3 style="margin:8px 0 0;font-size:13px;font-weight:600;border-top:1px solid #dcdcde;padding-top:12px;">'
                     . esc_html__( 'Infrastructure & Proxy', 'wp-secure-guard' ) . '</h3></th></tr>';

                echo '<tr><th>' . esc_html__( 'Trusted Proxy IPs', 'wp-secure-guard' ) . '</th><td>';
                echo '<textarea rows="4" cols="60" name="' . esc_attr( $k ) . '[trusted_proxy_ips]">'
                     . esc_textarea( (string) ( $s['trusted_proxy_ips'] ?? '' ) ) . '</textarea>';
                echo '<p class="description">' . esc_html__( 'Forwarded-For headers are trusted only when REMOTE_ADDR matches this list. Essential for Cloudflare/Varnish.', 'wp-secure-guard' ) . '</p></td></tr>';

                echo '<tr><th>' . esc_html__( 'Allowed User Roles', 'wp-secure-guard' ) . '</th><td>';
                foreach ( $roles as $role_key => $role ) {
                    echo '<label style="display:block"><input type="checkbox"'
                         . ' name="' . esc_attr( $k ) . '[allowed_roles][]"'
                         . ' value="' . esc_attr( $role_key ) . '"'
                         . ' ' . checked( in_array( $role_key, $s['allowed_roles'], true ), true, false ) . ' /> '
                         . esc_html( $role['name'] ) . '</label>';
                }
                echo '<p class="description">' . esc_html__( 'Logged-in users with these roles always bypass JWT enforcement.', 'wp-secure-guard' ) . '</p></td></tr>';
                break;

            case 'login':
                $this->row_checkbox($k, 'login_protection_enabled', $s,
                    __('Login Protection', 'wp-secure-guard'),
                    __('Enable IP-based lockouts on repeated failed login attempts.', 'wp-secure-guard')
                );
                $this->row_number($k, 'login_short_threshold', $s,
                    __('Short Block Threshold', 'wp-secure-guard'),
                    __('Failed attempts before the first short lockout triggers.', 'wp-secure-guard'),
                    1
                );
                $this->row_number($k, 'login_medium_threshold', $s,
                    __('Medium Block Threshold', 'wp-secure-guard'),
                    '',
                    1
                );
                $this->row_number($k, 'login_hard_block_threshold', $s,
                    __('Hard Block Threshold', 'wp-secure-guard'),
                    __('Triggers an extended IP-level block.', 'wp-secure-guard'),
                    1
                );
                $this->row_number($k, 'login_ban_hours', $s,
                    __('Ban Duration (hours)', 'wp-secure-guard'),
                    __('How long an IP remains blocked after hitting the hard threshold.', 'wp-secure-guard'),
                    1
                );
                break;

            case 'rate-limiting':
                $this->row_checkbox($k, 'bot_rate_limit_enabled', $s,
                    __('Bot Rate Limiting', 'wp-secure-guard'),
                    __('Throttle anonymous IP traffic. All logged-in users (any role) are automatically exempt.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'block_bad_bots', $s,
                    __('Block Bad Bots', 'wp-secure-guard'),
                    __('Deny access to known malicious scrapers, scanners, and automated tools based on User-Agent.', 'wp-secure-guard')
                );
                $this->row_number($k, 'bot_rate_limit_per_minute', $s,
                    __('Requests per Minute', 'wp-secure-guard'),
                    __('Anonymous requests allowed per IP per minute before a block is applied.', 'wp-secure-guard'),
                    1
                );
                $this->row_number($k, 'bot_block_minutes', $s,
                    __('Block Duration (minutes)', 'wp-secure-guard'),
                    '',
                    1
                );
                $this->row_number($k, 'scan_404_threshold', $s,
                    __('404 Scan Threshold', 'wp-secure-guard'),
                    __('Number of 404s in a 10-minute window before the IP is blocked for 24 hours.', 'wp-secure-guard'),
                    1
                );
                $this->row_checkbox($k, 'block_user_enumeration', $s,
                    __('Block User Enumeration', 'wp-secure-guard'),
                    __('Block author query strings, author archive paths, and direct /wp/v2/users probes.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'block_xmlrpc', $s,
                    __('Block XML-RPC', 'wp-secure-guard'),
                    __('Return 403 for any direct request to xmlrpc.php.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'block_public_wp_cron', $s,
                    __('Block Public WP-Cron', 'wp-secure-guard'),
                    __('Deny external HTTP access to wp-cron.php. Internal and CLI cron execution are unaffected.', 'wp-secure-guard')
                );
                break;

            case 'headers':
                echo '<tr><th>' . esc_html__('Content Security Policy', 'wp-secure-guard') . '</th><td>';
                echo '<input type="text" class="large-text" name="' . esc_attr($k) . '[csp]" value="' . esc_attr((string) $s['csp']) . '" />';
                echo '<p class="description">' . esc_html__('Leave empty to use the default balanced CSP. Override only when required by your theme or plugins.', 'wp-secure-guard') . '</p></td></tr>';
                $this->row_text($k, 'referrer_policy', $s, __('Referrer Policy', 'wp-secure-guard'), '');
                $this->row_text($k, 'permissions_policy', $s, __('Permissions Policy', 'wp-secure-guard'), '');
                $this->row_checkbox($k, 'enable_coop', $s,
                    __('COOP', 'wp-secure-guard'),
                    __('Send Cross-Origin-Opener-Policy: same-origin.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'enable_corp', $s,
                    __('CORP', 'wp-secure-guard'),
                    __('Send Cross-Origin-Resource-Policy: same-site.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'enable_hsts', $s,
                    __('HSTS', 'wp-secure-guard'),
                    __('Send Strict-Transport-Security on HTTPS connections.', 'wp-secure-guard')
                );
                $this->row_number($k, 'hsts_max_age', $s, __('HSTS max-age (seconds)', 'wp-secure-guard'), '', 0);
                break;

            case 'hardening':
                // Exposure Scan Results
                $exposure_results = get_transient('sg_exposure_results');
                if (isset($_GET['run_exposure_test'])) {
                    if (current_user_can('manage_options') && isset($_GET['_wpnonce']) && wp_verify_nonce($_GET['_wpnonce'], 'sg_run_exposure_test')) {
                        $exposure_results = Secure_Guard_WP_Hardening::test_exposure_status();
                        set_transient('sg_exposure_results', $exposure_results, HOUR_IN_SECONDS);
                    }
                }
                if (!$exposure_results) {
                    $exposure_results = Secure_Guard_WP_Hardening::test_exposure_status();
                    set_transient('sg_exposure_results', $exposure_results, HOUR_IN_SECONDS);
                }

                $scan_url = wp_nonce_url(add_query_arg(['tab' => 'hardening', 'run_exposure_test' => '1'], admin_url('admin.php?page=secure-guard-settings')), 'sg_run_exposure_test');
                
                echo '<tr><th colspan="2"><h3 style="margin:8px 0 0;font-size:14px;font-weight:600;padding-bottom:4px;border-bottom:1px solid #dcdcde;">'
                     . esc_html__('Path Exposure Scanner', 'wp-secure-guard') . '</h3></th></tr>';
                echo '<tr><td colspan="2"><div style="background:#fcfcfc; border:1px solid #ccd0d4; padding:20px; border-radius:6px; margin-bottom:20px; box-shadow:0 1px 1px rgba(0,0,0,.04);">';
                echo '<p style="margin:0 0 15px; font-weight:600; font-size:13px; color:#1d2327;">' . esc_html__('Real-time public exposure status of sensitive files:', 'wp-secure-guard') . '</p>';
                echo '<table class="wp-list-table widefat fixed striped" style="margin-bottom:15px; border:1px solid #dcdcde; box-shadow:none;">';
                echo '<thead><tr>';
                echo '<th style="padding:10px; font-weight:600;">' . esc_html__('Path', 'wp-secure-guard') . '</th>';
                echo '<th style="padding:10px; font-weight:600; width:120px;">' . esc_html__('Status', 'wp-secure-guard') . '</th>';
                echo '<th style="padding:10px; font-weight:600;">' . esc_html__('Details', 'wp-secure-guard') . '</th>';
                echo '</tr></thead>';
                echo '<tbody>';
                
                foreach ($exposure_results as $file => $info) {
                    $status_bg = '#d63638'; // red
                    $status_text = __('Exposed', 'wp-secure-guard');
                    if ($info['status'] === 'protected') {
                        $status_bg = '#00a32a'; // green
                        $status_text = __('Protected', 'wp-secure-guard');
                    } elseif ($info['status'] === 'unknown') {
                        $status_bg = '#cca300'; // yellow
                        $status_text = __('Unreachable', 'wp-secure-guard');
                    }
                    
                    echo '<tr>';
                    echo '<td style="padding:10px; font-family:monospace; font-weight:600;">' . esc_html($file) . '</td>';
                    echo '<td style="padding:10px;"><span style="display:inline-block; background:' . esc_attr($status_bg) . '; color:#fff; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:600; text-align:center; min-width:80px;">' . esc_html($status_text) . '</span></td>';
                    echo '<td style="padding:10px; color:#50575e;">' . esc_html($info['msg']) . '</td>';
                    echo '</tr>';
                }
                echo '</tbody>';
                echo '</table>';
                echo '<a href="' . esc_url($scan_url) . '" class="button button-secondary" style="font-weight:600;">' . esc_html__('Run Exposure Scan Now', 'wp-secure-guard') . '</a>';
                echo '</div></td></tr>';

                echo '<tr><th colspan="2"><h3 style="margin:8px 0 0;font-size:14px;font-weight:600;padding-bottom:4px;border-bottom:1px solid #dcdcde;">'
                     . esc_html__('Security Hardening Options', 'wp-secure-guard') . '</h3></th></tr>';

                $this->row_checkbox($k, 'hide_wp_info', $s,
                    __('Hide WordPress Fingerprint', 'wp-secure-guard'),
                    __('Remove generator tags, version query strings, and block readme/license/debug.log probes.', 'wp-secure-guard')
                );
                $resolved_log = get_option('secure_guard_resolved_debug_log_path');
                if (!empty($resolved_log) && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
                    echo '<tr><th>' . esc_html__('Relocated Debug Log', 'wp-secure-guard') . '</th><td>';
                    echo '<code style="word-break: break-all; background:#f0f0f1; padding:3px 6px; border-radius:3px; font-family:monospace;">' . esc_html($resolved_log) . '</code>';
                    echo '<p class="description" style="margin-top:6px;">' . esc_html__('The debug.log was automatically moved outside of the public web root (or randomized) to prevent public downloads.', 'wp-secure-guard') . '</p>';
                    echo '</td></tr>';
                }
                $this->row_checkbox($k, 'disable_emojis', $s,
                    __('Disable Emojis', 'wp-secure-guard'),
                    __('Remove the emoji detection script and styles to reduce page bloat and fingerprinting.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'disable_oembeds', $s,
                    __('Disable oEmbeds', 'wp-secure-guard'),
                    __('Disable oEmbed discovery links and host JS.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'disable_file_editor', $s,
                    __('Disable File Editor', 'wp-secure-guard'),
                    __('Prevent the theme and plugin editor from being accessed in the dashboard.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'hide_login_errors', $s,
                    __('Hide Login Errors', 'wp-secure-guard'),
                    __('Obfuscate login error messages to prevent username harvesting.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'file_integrity_enabled', $s,
                    __('File Integrity Monitoring', 'wp-secure-guard'),
                    __('Run hourly checksum scans of wp-admin and wp-includes and alert on changes.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'admin_area_protection_enabled', $s,
                    __('Admin Area Protection', 'wp-secure-guard'),
                    __('Guard /wp-admin pages from unauthenticated access. admin-ajax.php is always exempt so public AJAX handlers work.', 'wp-secure-guard')
                );
                $this->row_number($k, 'log_retention_days', $s,
                    __('Log Retention (days)', 'wp-secure-guard'),
                    __('Log entries older than this are automatically purged by the scheduled maintenance task.', 'wp-secure-guard'),
                    1
                );
                $this->row_checkbox($k, 'self_protection_enabled', $s,
                    __('Self-Protection', 'wp-secure-guard'),
                    __('Prevent accidental or malicious deactivation of the Secure Guard plugin via the WordPress admin.', 'wp-secure-guard')
                );
                $this->row_text($k, 'mu_plugin_path', $s,
                    __('MU-Plugin Path', 'wp-secure-guard'),
                    __('Full system path to the mu-plugins directory. Leave empty for default.', 'wp-secure-guard')
                );

                // Nginx Hardening Suggestions
                $server_software = sanitize_text_field((string) ($_SERVER['SERVER_SOFTWARE'] ?? ''));
                $is_nginx = str_contains(strtolower($server_software), 'nginx');
                
                if ($is_nginx) {
                    $is_bedrock = str_ends_with(rtrim(str_replace('\\', '/', ABSPATH), '/'), '/wp') || 
                                  file_exists(ABSPATH . '../config/application.php');
                    
                    $nginx_rules = "# Secure Guard - Nginx Hardening Rules\n";
                    $nginx_rules .= "# Add these rules to your Nginx virtual host 'server' block:\n\n";
                    $nginx_rules .= "# 1. Prevent directory indexing\n";
                    $nginx_rules .= "autoindex off;\n\n";
                    $nginx_rules .= "# 2. Block direct access to sensitive extensions\n";
                    $nginx_rules .= "location ~* \.(log|ini|sh|bak|conf|sql|env)$ {\n";
                    $nginx_rules .= "    deny all;\n";
                    $nginx_rules .= "}\n\n";
                    $nginx_rules .= "# 3. Block readme, license, install, and upgrade files\n";
                    $nginx_rules .= "location ~* /(readme\.html|license\.txt|install\.php|upgrade\.php)$ {\n";
                    $nginx_rules .= "    deny all;\n";
                    $nginx_rules .= "}\n\n";
                    $nginx_rules .= "# 4. Block PHP execution in uploads directory\n";
                    $nginx_rules .= "location ~* /uploads/.*\.php$ {\n";
                    $nginx_rules .= "    deny all;\n";
                    $nginx_rules .= "}\n";
                    
                    if ($is_bedrock) {
                        $nginx_rules .= "\n# 5. Block Bedrock specific paths\n";
                        $nginx_rules .= "location ~* /(config|vendor|\.env) {\n";
                        $nginx_rules .= "    deny all;\n";
                        $nginx_rules .= "}\n";
                    }

                    echo '<tr><th colspan="2"><h3 style="margin:18px 0 0;font-size:14px;font-weight:600;padding-bottom:4px;border-bottom:1px solid #dcdcde;">'
                         . esc_html__('Nginx Server Hardening', 'wp-secure-guard') . '</h3></th></tr>';
                    echo '<tr><td colspan="2">';
                    echo '<div class="notice notice-warning inline" style="margin:4px 0 12px; display:block; padding:10px 15px; border-left-color:#dba617;">';
                    echo '<p style="margin:0;"><strong>' . esc_html__('Nginx detected:', 'wp-secure-guard') . '</strong> ';
                    echo esc_html__('Nginx does not support .htaccess files. To properly block files (like debug.log) from being downloaded directly, you must copy the configuration rules below and add them to your Nginx site configuration block.', 'wp-secure-guard') . '</p>';
                    echo '</div>';
                    echo '<textarea rows="15" cols="80" class="large-text code" readonly style="font-family:monospace; background:#f0f0f1; padding:15px; border-radius:4px; font-size:12px; line-height:1.5; color:#2c3338; border:1px solid #8c8f94;">' . esc_textarea($nginx_rules) . '</textarea>';
                    echo '</td></tr>';
                }
                break;
            case 'adaptive-security':
                $this->row_checkbox($k, 'reputation_enabled', $s,
                    __('Reputation Engine', 'wp-secure-guard'),
                    __('Enable behavioral reputation tracking for all visitors.', 'wp-secure-guard')
                );
                $this->row_number($k, 'reputation_block_score', $s,
                    __('Block Threshold', 'wp-secure-guard'),
                    __('Score (0-100) at which an IP is hard-blocked.', 'wp-secure-guard'),
                    1
                );
                $this->row_number($k, 'reputation_throttle_score', $s,
                    __('Throttle Threshold', 'wp-secure-guard'),
                    __('Score at which an IP enters the Throttled tier.', 'wp-secure-guard'),
                    1
                );
                $this->row_number($k, 'reputation_challenge_score', $s,
                    __('Challenge Threshold', 'wp-secure-guard'),
                    __('Score at which an IP enters the Challenged tier.', 'wp-secure-guard'),
                    1
                );
                $this->row_checkbox($k, 'bot_fingerprint_enabled', $s,
                    __('Behavioral Bot Fingerprinting', 'wp-secure-guard'),
                    __('Analyze headers and patterns to detect headless browsers and scrapers.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'progressive_throttle_enabled', $s,
                    __('Progressive Response', 'wp-secure-guard'),
                    __('Inject artificial delays into high-risk requests to slow down scanners.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'lock_state_enabled', $s,
                    __('Lockdown System', 'wp-secure-guard'),
                    __('Enable the manual/automatic lockdown engine.', 'wp-secure-guard')
                );
                $this->row_number($k, 'lockdown_velocity_threshold', $s,
                    __('Automatic Lockdown Velocity Threshold', 'wp-secure-guard'),
                    __('Reputation points accumulated in a short window before automatic emergency lockdown is engaged.', 'wp-secure-guard'),
                    1
                );
                break;
            case 'alerts':
                $this->row_checkbox($k, 'email_alerts_enabled', $s,
                    __('Enable Email Alerts', 'wp-secure-guard'),
                    __('Send email notifications to the site admin address for security events. Uses wp_mail().', 'wp-secure-guard')
                );
                echo '<tr><td colspan="2"><p class="description" style="padding:0 0 4px;">';
                $admin_email = (string) get_option('admin_email', '');
                // translators: %s: admin email address
                echo wp_kses_post(sprintf(esc_html__('Alerts are sent to the site admin address: %s', 'wp-secure-guard'), '<strong>' . esc_html($admin_email) . '</strong>'));
                echo '</p></td></tr>';
                $this->row_checkbox($k, 'alert_on_hard_block', $s,
                    __('Alert on Hard IP Block', 'wp-secure-guard'),
                    __('Send an email when an IP is hard-blocked by the bot rate limiter or login protection.', 'wp-secure-guard')
                );
                $this->row_checkbox($k, 'alert_on_integrity', $s,
                    __('Alert on File Integrity Changes', 'wp-secure-guard'),
                    __('Send an email when the hourly integrity scan detects added, modified, or deleted core files.', 'wp-secure-guard')
                );
                $this->row_number($k, 'alert_on_token_expiry_days', $s,
                    __('Token Expiry Warning (days)', 'wp-secure-guard'),
                    __('Send an email when a JWT token will expire within this many days. Set to 0 to disable.', 'wp-secure-guard'),
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
                esc_html__('Controlled by the %s environment variable. Remove the env var to manage it here.', 'wp-secure-guard'),
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
