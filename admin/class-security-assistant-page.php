<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Security_Assistant_Page {
    private Secure_Guard_Log_Repository $logs;
    private Secure_Guard_Token_Repository $tokens;
    private Secure_Guard_Rate_Limit_Repository $limits;
    private Secure_Guard_Lock_State $lock_state;

    public function __construct(
        Secure_Guard_Log_Repository $logs,
        Secure_Guard_Token_Repository $tokens,
        Secure_Guard_Rate_Limit_Repository $limits,
        Secure_Guard_Lock_State $lock_state
    ) {
        $this->logs = $logs;
        $this->tokens = $tokens;
        $this->limits = $limits;
        $this->lock_state = $lock_state;
    }

    public function register(): void {
        add_action('admin_post_sg_apply_security_preset', [$this, 'handle_apply_preset']);
        add_action('admin_post_sg_rollback_security_preset', [$this, 'handle_rollback_preset']);
        add_action('admin_post_sg_lockdown_control', [$this, 'handle_lockdown_control']);
        add_action('admin_post_sg_refresh_hardening_rules', [$this, 'handle_refresh_hardening_rules']);
    }

    public function handle_apply_preset(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        check_admin_referer('sg_apply_security_preset');

        $preset_slug = sanitize_key(wp_unslash((string) ($_POST['preset'] ?? '')));
        $preset = Secure_Guard_Security_Presets::get($preset_slug);
        if (!is_array($preset)) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant&preset_error=1'));
            exit;
        }

        $stored = get_option(Secure_Guard_Config::OPTION_KEY, []);
        if (!is_array($stored)) {
            $stored = [];
        }

        update_option(
            Secure_Guard_Security_Presets::PREVIOUS_SETTINGS_OPTION,
            [
                'stored_at' => current_time('mysql', true),
                'settings' => $stored,
            ],
            false
        );

        $input = array_merge(Secure_Guard_Config::defaults(), $stored, (array) $preset['settings']);
        $sanitized = Secure_Guard_Config::save_settings($input);
        update_option(Secure_Guard_Config::OPTION_KEY, $sanitized, false);
        update_option(Secure_Guard_Security_Presets::ACTIVE_PRESET_OPTION, $preset_slug, false);
        delete_transient('sg_dashboard_stats');

        $this->logs->log('/wp-admin/admin.php?page=secure-guard-assistant', 'POST', 'ALLOWED', 'Security preset applied', [
            'preset' => $preset_slug,
            'user_id' => get_current_user_id(),
        ]);

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant&preset_applied=' . rawurlencode($preset_slug)));
        exit;
    }

    public function handle_rollback_preset(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        check_admin_referer('sg_rollback_security_preset');

        $snapshot = get_option(Secure_Guard_Security_Presets::PREVIOUS_SETTINGS_OPTION, []);
        if (!is_array($snapshot) || !isset($snapshot['settings']) || !is_array($snapshot['settings'])) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant&rollback_error=1'));
            exit;
        }

        $sanitized = Secure_Guard_Config::save_settings($snapshot['settings']);
        update_option(Secure_Guard_Config::OPTION_KEY, $sanitized, false);
        update_option(Secure_Guard_Security_Presets::ACTIVE_PRESET_OPTION, Secure_Guard_Security_Presets::detect(Secure_Guard_Config::get_settings()), false);
        delete_option(Secure_Guard_Security_Presets::PREVIOUS_SETTINGS_OPTION);
        delete_transient('sg_dashboard_stats');

        $this->logs->log('/wp-admin/admin.php?page=secure-guard-assistant', 'POST', 'ALLOWED', 'Security preset rollback applied', [
            'user_id' => get_current_user_id(),
        ]);

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant&rollback=1'));
        exit;
    }

    public function handle_lockdown_control(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        check_admin_referer('sg_lockdown_control');

        $settings = Secure_Guard_Config::get_settings();
        if (empty($settings['lock_state_enabled'])) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant&lockdown_disabled=1'));
            exit;
        }

        $command = sanitize_key(wp_unslash((string) ($_POST['lockdown_command'] ?? '')));
        if ($command === 'engage') {
            $duration_minutes = max(5, min(1440, (int) wp_unslash($_POST['duration_minutes'] ?? 60)));
            $reason = sanitize_text_field(wp_unslash((string) ($_POST['reason'] ?? 'Manual emergency lockdown')));
            if ($reason === '') {
                $reason = __('Manual emergency lockdown', 'wp-secure-guard');
            }

            $this->lock_state->engage_lock($duration_minutes * MINUTE_IN_SECONDS, $reason);
            $this->logs->log('/wp-admin/admin.php?page=secure-guard-assistant', 'POST', 'BLOCKED', 'Manual lockdown engaged', [
                'duration_minutes' => $duration_minutes,
                'reason' => $reason,
                'user_id' => get_current_user_id(),
            ]);

            wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant&lockdown=engaged'));
            exit;
        }

        if ($command === 'release') {
            $this->lock_state->release_lock();
            $this->logs->log('/wp-admin/admin.php?page=secure-guard-assistant', 'POST', 'ALLOWED', 'Manual lockdown released', [
                'user_id' => get_current_user_id(),
            ]);

            wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant&lockdown=released'));
            exit;
        }

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant'));
        exit;
    }

    public function handle_refresh_hardening_rules(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        check_admin_referer('sg_refresh_hardening_rules');

        Secure_Guard_WP_Hardening::write_htaccess_protection();
        update_option('secure_guard_htaccess_hardened', 1, false);
        delete_transient('sg_dashboard_stats');

        $this->logs->log('/wp-admin/admin.php?page=secure-guard-assistant', 'POST', 'ALLOWED', 'Hardening rules refreshed', [
            'user_id' => get_current_user_id(),
        ]);

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant&hardening_refreshed=1'));
        exit;
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        $settings = Secure_Guard_Config::get_settings();
        $detected_preset = Secure_Guard_Security_Presets::detect($settings);
        $saved_preset = sanitize_key((string) get_option(Secure_Guard_Security_Presets::ACTIVE_PRESET_OPTION, ''));
        $current_preset = $detected_preset !== 'custom' ? $detected_preset : 'custom';
        $lock_data = $this->lock_state->get_lock_data();
        $blocked_ips = $this->limits->count_active_ip_blocks();
        $failed_logins = $this->logs->count_by_reason('Failed login');
        $active_tokens = $this->tokens->count_active();
        $recommendations = $this->build_recommendations($settings, $blocked_ips, $active_tokens, $lock_data);

        echo '<div class="wrap secure-guard-ui">';
        echo '<h1>' . esc_html__('Security Assistant', 'wp-secure-guard') . '</h1>';
        echo '<p class="description">' . esc_html__('Use this page for common security operations without tuning every advanced setting manually.', 'wp-secure-guard') . '</p>';

        $this->render_notices();
        $this->render_env_override_notice();

        echo '<div class="sg-metric-grid">';
        $this->render_metric(__('Current Mode', 'wp-secure-guard'), Secure_Guard_Security_Presets::label($current_preset), $current_preset === 'custom' ? __('Manual settings differ from a preset.', 'wp-secure-guard') : __('Preset-matched configuration.', 'wp-secure-guard'), $current_preset === 'custom' ? 'warning' : 'ok');
        $this->render_metric(__('Blocked IPs', 'wp-secure-guard'), (string) $blocked_ips, __('Manage false positives and active bans.', 'wp-secure-guard'), $blocked_ips > 0 ? 'alert' : 'ok');
        $this->render_metric(__('Failed Logins', 'wp-secure-guard'), (string) $failed_logins, __('Total failed-login events in the retained log window.', 'wp-secure-guard'), $failed_logins > 0 ? 'alert' : 'ok');
        $this->render_metric(__('Active Tokens', 'wp-secure-guard'), (string) $active_tokens, __('JWT/API credentials currently active.', 'wp-secure-guard'), $active_tokens > 0 ? 'ok' : 'warning');
        $this->render_metric(__('Lockdown', 'wp-secure-guard'), $lock_data ? __('Active', 'wp-secure-guard') : __('Normal', 'wp-secure-guard'), $lock_data ? $this->format_lock_summary($lock_data) : __('Emergency lockdown is not active.', 'wp-secure-guard'), $lock_data ? 'alert' : 'ok');
        $this->render_metric(__('Recommendations', 'wp-secure-guard'), (string) count($recommendations), __('Actionable setup and safety items.', 'wp-secure-guard'), count($recommendations) > 0 ? 'warning' : 'ok');
        echo '</div>';

        $this->render_preset_cards($current_preset, $saved_preset);
        $this->render_bedrock_hardening_status();
        $this->render_lockdown_panel($lock_data, $settings);
        $this->render_recommendations($recommendations);

        echo '</div>';
    }

    private function render_notices(): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['preset_applied'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $slug = sanitize_key(wp_unslash((string) $_GET['preset_applied']));
            // translators: %s: security preset name
            echo '<div class="notice notice-success is-dismissible"><p>' . sprintf(esc_html__('Security preset applied: %s.', 'wp-secure-guard'), esc_html(Secure_Guard_Security_Presets::label($slug))) . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['preset_error'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('The selected preset is not valid.', 'wp-secure-guard') . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['rollback'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Previous settings restored.', 'wp-secure-guard') . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['rollback_error'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('No previous settings snapshot is available to restore.', 'wp-secure-guard') . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['lockdown'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $state = sanitize_key(wp_unslash((string) $_GET['lockdown']));
            $message = $state === 'engaged' ? __('Emergency lockdown engaged.', 'wp-secure-guard') : __('Emergency lockdown released.', 'wp-secure-guard');
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($message) . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['lockdown_disabled'])) {
            echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__('Lockdown controls are disabled in Adaptive Security settings.', 'wp-secure-guard') . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (!empty($_GET['hardening_refreshed'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Web-server hardening rules refreshed.', 'wp-secure-guard') . '</p></div>';
        }
    }

    private function render_metric(string $label, string $value, string $sub, string $state = ''): void {
        $class = 'sg-metric-card';
        if ($state === 'alert') {
            $class .= ' sg-metric-card--alert';
        } elseif ($state === 'ok') {
            $class .= ' sg-metric-card--ok';
        }

        echo '<div class="' . esc_attr($class) . '">';
        echo '<div class="sg-metric-card__header"><span class="dashicons dashicons-shield-alt"></span> ' . esc_html($label) . '</div>';
        echo '<div class="sg-metric-card__number" style="font-size:24px;">' . esc_html($value) . '</div>';
        echo '<div class="sg-metric-card__sub">' . esc_html($sub) . '</div>';
        echo '</div>';
    }

    private function render_env_override_notice(): void {
        $overrides = [];
        foreach (Secure_Guard_Config::ENV_VARS as $setting_key => $env_var) {
            if (Secure_Guard_Config::is_env_overridden($setting_key)) {
                $overrides[] = $env_var;
            }
        }

        if ($overrides === []) {
            return;
        }

        echo '<div class="notice notice-info inline"><p><strong>' . esc_html__('Environment-managed JWT settings detected.', 'wp-secure-guard') . '</strong> ';
        echo esc_html__('Preset changes will not overwrite these fields:', 'wp-secure-guard') . ' ';
        foreach ($overrides as $index => $env_var) {
            echo ($index > 0 ? ', ' : '') . '<code>' . esc_html($env_var) . '</code>';
        }
        echo '.</p></div>';
    }

    private function render_preset_cards(string $current_preset, string $saved_preset): void {
        echo '<h2>' . esc_html__('Security Presets', 'wp-secure-guard') . '</h2>';
        echo '<div class="sg-preset-grid">';

        foreach (Secure_Guard_Security_Presets::all() as $slug => $preset) {
            $is_current = $current_preset === $slug;
            $active_class = $is_current ? ' sg-preset-card--active' : '';
            echo '<div class="card sg-preset-card' . esc_attr($active_class) . '">';
            echo '<h3>' . esc_html((string) $preset['label']) . '</h3>';
            echo '<p><strong>' . esc_html__('Best for:', 'wp-secure-guard') . '</strong> ' . esc_html((string) $preset['target']) . '</p>';
            echo '<p class="description">' . esc_html((string) $preset['description']) . '</p>';
            if ($is_current) {
                echo '<p><span class="sg-pill sg-pill--allowed">' . esc_html__('Active', 'wp-secure-guard') . '</span></p>';
            } elseif ($saved_preset === $slug) {
                echo '<p><span class="sg-pill sg-pill--warning">' . esc_html__('Modified', 'wp-secure-guard') . '</span></p>';
            }
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            echo '<input type="hidden" name="action" value="sg_apply_security_preset" />';
            echo '<input type="hidden" name="preset" value="' . esc_attr((string) $slug) . '" />';
            wp_nonce_field('sg_apply_security_preset');
            $button_args = [];
            if ($slug === 'maximum') {
                $button_args['onclick'] = 'return confirm(\'' . esc_js(__('Maximum Security enables stricter REST and traffic controls. Confirm whitelists, API clients, and admin recovery paths before applying. Continue?', 'wp-secure-guard')) . '\')';
            }
            submit_button($is_current ? __('Reapply Preset', 'wp-secure-guard') : __('Apply Preset', 'wp-secure-guard'), $is_current ? 'secondary' : 'primary', 'submit', false, $button_args);
            echo '</form>';
            echo '</div>';
        }

        $custom_active_class = $current_preset === 'custom' ? ' sg-preset-card--active' : '';
        echo '<div class="card sg-preset-card' . esc_attr($custom_active_class) . '">';
        echo '<h3>' . esc_html__('Custom', 'wp-secure-guard') . '</h3>';
        echo '<p><strong>' . esc_html__('Best for:', 'wp-secure-guard') . '</strong> ' . esc_html__('Teams that want advanced manual control.', 'wp-secure-guard') . '</p>';
        echo '<p class="description">' . esc_html__('Custom mode is selected automatically when settings no longer match a preset.', 'wp-secure-guard') . '</p>';
        echo '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=secure-guard-settings')) . '">' . esc_html__('Open Advanced Settings', 'wp-secure-guard') . '</a></p>';
        echo '</div>';

        echo '</div>';

        $snapshot = get_option(Secure_Guard_Security_Presets::PREVIOUS_SETTINGS_OPTION, []);
        if (is_array($snapshot) && isset($snapshot['settings']) && is_array($snapshot['settings'])) {
            echo '<div class="card sg-lockdown-card">';
            echo '<h3>' . esc_html__('Preset Recovery', 'wp-secure-guard') . '</h3>';
            echo '<p class="description">' . esc_html__('Restore the settings snapshot captured before the last preset application.', 'wp-secure-guard') . '</p>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" onsubmit="return confirm(\'' . esc_js(__('Restore previous Secure Guard settings?', 'wp-secure-guard')) . '\')">';
            echo '<input type="hidden" name="action" value="sg_rollback_security_preset" />';
            wp_nonce_field('sg_rollback_security_preset');
            submit_button(__('Restore Previous Settings', 'wp-secure-guard'), 'secondary', 'submit', false);
            echo '</form>';
            echo '</div>';
        }
    }

    private function render_lockdown_panel(?array $lock_data, array $settings): void {
        echo '<h2 style="margin-top:24px;">' . esc_html__('Emergency Lockdown', 'wp-secure-guard') . '</h2>';
        echo '<div class="card sg-lockdown-card">';

        if (empty($settings['lock_state_enabled'])) {
            echo '<p><span class="sg-pill sg-pill--warning">' . esc_html__('Disabled', 'wp-secure-guard') . '</span> ' . esc_html__('Enable the lockdown system in Adaptive Security settings before using this control.', 'wp-secure-guard') . '</p>';
            echo '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=secure-guard-settings&tab=adaptive-security')) . '">' . esc_html__('Open Adaptive Security Settings', 'wp-secure-guard') . '</a></p>';
            echo '</div>';
            return;
        }

        if ($lock_data) {
            echo '<p><span class="sg-pill sg-pill--blocked">' . esc_html__('Active', 'wp-secure-guard') . '</span> ' . esc_html($this->format_lock_summary($lock_data)) . '</p>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            echo '<input type="hidden" name="action" value="sg_lockdown_control" />';
            echo '<input type="hidden" name="lockdown_command" value="release" />';
            wp_nonce_field('sg_lockdown_control');
            submit_button(__('Restore Normal Mode', 'wp-secure-guard'), 'primary', 'submit', false);
            echo '</form>';
            echo '</div>';
            return;
        }

        echo '<p class="description">' . esc_html__('Use during brute-force or scanning incidents. Non-admin traffic is temporarily restricted by the lock-state engine.', 'wp-secure-guard') . '</p>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" class="sg-action-row">';
        echo '<input type="hidden" name="action" value="sg_lockdown_control" />';
        echo '<input type="hidden" name="lockdown_command" value="engage" />';
        wp_nonce_field('sg_lockdown_control');
        echo '<label>' . esc_html__('Duration:', 'wp-secure-guard') . ' <select name="duration_minutes">';
        foreach ([30, 60, 240, 720, 1440] as $minutes) {
            echo '<option value="' . esc_attr((string) $minutes) . '"' . selected($minutes, 60, false) . '>' . esc_html($this->duration_label($minutes)) . '</option>';
        }
        echo '</select></label>';
        echo '<label>' . esc_html__('Reason:', 'wp-secure-guard') . ' <input type="text" name="reason" class="regular-text" value="' . esc_attr__('Manual emergency lockdown', 'wp-secure-guard') . '" /></label>';
        submit_button(__('Enable Emergency Lockdown', 'wp-secure-guard'), 'delete', 'submit', false, ['onclick' => 'return confirm(\'' . esc_js(__('Enable emergency lockdown now?', 'wp-secure-guard')) . '\')']);
        echo '</form>';
        echo '</div>';
    }

    private function render_bedrock_hardening_status(): void {
        $results = Secure_Guard_WP_Hardening::test_exposure_status();

        echo '<h2 style="margin-top:24px;">' . esc_html__('Bedrock & App Path Shield', 'wp-secure-guard') . '</h2>';
        echo '<div class="card sg-lockdown-card sg-bedrock-shield">';
        echo '<p class="description">' . esc_html__('Checks direct access to WordPress and Bedrock app files that should be blocked before PHP handles the request.', 'wp-secure-guard') . '</p>';

        if ($results === []) {
            echo '<p><span class="sg-pill sg-pill--warning">' . esc_html__('Unknown', 'wp-secure-guard') . '</span> ' . esc_html__('No exposure checks are available.', 'wp-secure-guard') . '</p>';
        } else {
            echo '<div class="sg-exposure-list">';
            foreach ($results as $result) {
                $status = sanitize_key((string) ($result['status'] ?? 'unknown'));
                $pill_class = 'sg-pill--warning';
                if ($status === 'protected') {
                    $pill_class = 'sg-pill--allowed';
                } elseif ($status === 'exposed') {
                    $pill_class = 'sg-pill--blocked';
                }

                echo '<div class="sg-exposure-row">';
                echo '<div>';
                echo '<strong>' . esc_html((string) ($result['label'] ?? __('Exposure check', 'wp-secure-guard'))) . '</strong>';
                echo '<code>' . esc_html((string) ($result['path'] ?? '')) . '</code>';
                echo '<p class="description">' . esc_html((string) ($result['msg'] ?? '')) . '</p>';
                echo '</div>';
                echo '<span class="sg-pill ' . esc_attr($pill_class) . '">' . esc_html($status) . '</span>';
                echo '</div>';
            }
            echo '</div>';
        }

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:14px;">';
        echo '<input type="hidden" name="action" value="sg_refresh_hardening_rules" />';
        wp_nonce_field('sg_refresh_hardening_rules');
        submit_button(__('Refresh Hardening Rules', 'wp-secure-guard'), 'secondary', 'submit', false);
        echo '</form>';
        echo '</div>';
    }

    /**
     * @return array<int,array{severity:string,title:string,body:string,action:string,url:string}>
     */
    private function build_recommendations(array $settings, int $blocked_ips, int $active_tokens, ?array $lock_data): array {
        $items = [];

        if (empty($settings['jwt_secret']) && !defined('SECURE_GUARD_JWT_SECRET') && !Secure_Guard_Config::is_env_overridden('jwt_secret')) {
            $items[] = [
                'severity' => 'warning',
                'title' => __('Set a stable JWT secret', 'wp-secure-guard'),
                'body' => __('Tokens currently depend on WordPress AUTH_KEY. A dedicated secret prevents accidental token invalidation during key rotation.', 'wp-secure-guard'),
                'action' => __('Configure JWT', 'wp-secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-settings&tab=rest-jwt'),
            ];
        }

        if (empty($settings['email_alerts_enabled'])) {
            $items[] = [
                'severity' => 'info',
                'title' => __('Enable security alerts', 'wp-secure-guard'),
                'body' => __('Email alerts make hard blocks, integrity changes, and token expiry easier to respond to.', 'wp-secure-guard'),
                'action' => __('Open Alerts', 'wp-secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-settings&tab=alerts'),
            ];
        }

        if ($blocked_ips > 0) {
            $items[] = [
                'severity' => 'warning',
                'title' => __('Review active IP blocks', 'wp-secure-guard'),
                'body' => __('Active blocks may include legitimate admins during brute-force events. Review before users report lockouts.', 'wp-secure-guard'),
                'action' => __('Manage Blocks', 'wp-secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-blocked-ips'),
            ];
        }

        if ($active_tokens === 0) {
            $items[] = [
                'severity' => 'info',
                'title' => __('Create the first API token', 'wp-secure-guard'),
                'body' => __('REST lockdown is most useful when API clients use scoped JWT tokens instead of broad cookies.', 'wp-secure-guard'),
                'action' => __('Manage Tokens', 'wp-secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-tokens'),
            ];
        }

        if (!$lock_data && empty($settings['lock_state_enabled'])) {
            $items[] = [
                'severity' => 'warning',
                'title' => __('Enable lockdown readiness', 'wp-secure-guard'),
                'body' => __('Emergency lockdown controls are unavailable until the lock-state engine is enabled.', 'wp-secure-guard'),
                'action' => __('Open Adaptive Security', 'wp-secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-settings&tab=adaptive-security'),
            ];
        }

        return $items;
    }

    /**
     * @param array<int,array{severity:string,title:string,body:string,action:string,url:string}> $recommendations
     */
    private function render_recommendations(array $recommendations): void {
        echo '<h2 style="margin-top:24px;">' . esc_html__('Recommendations', 'wp-secure-guard') . '</h2>';
        echo '<div class="card sg-recommendations-card">';

        if ($recommendations === []) {
            echo '<p><span class="sg-pill sg-pill--allowed">' . esc_html__('Good', 'wp-secure-guard') . '</span> ' . esc_html__('No high-priority recommendations right now.', 'wp-secure-guard') . '</p>';
            echo '</div>';
            return;
        }

        echo '<div class="sg-recommendation-list">';
        foreach ($recommendations as $item) {
            $pill_class = $item['severity'] === 'warning' ? 'sg-pill--warning' : 'sg-pill--info';
            echo '<div class="sg-recommendation-item">';
            echo '<div><span class="sg-pill ' . esc_attr($pill_class) . '">' . esc_html($item['severity']) . '</span> <strong>' . esc_html($item['title']) . '</strong>';
            echo '<p class="description">' . esc_html($item['body']) . '</p></div>';
            echo '<a class="button" href="' . esc_url($item['url']) . '">' . esc_html($item['action']) . '</a>';
            echo '</div>';
        }
        echo '</div>';
        echo '</div>';
    }

    private function format_lock_summary(array $lock_data): string {
        $reason = sanitize_text_field((string) ($lock_data['reason'] ?? __('Manual', 'wp-secure-guard')));
        $expires = (int) ($lock_data['expires'] ?? 0);
        if ($expires <= time()) {
            // translators: %s: lock reason
            return sprintf(esc_html__('Reason: %s. Expiring now.', 'wp-secure-guard'), esc_html($reason));
        }

        $minutes = max(1, (int) ceil(($expires - time()) / MINUTE_IN_SECONDS));
        // translators: 1: lock reason, 2: minutes remaining
        return sprintf(esc_html__('Reason: %1$s. Expires in about %2$d minute(s).', 'wp-secure-guard'), esc_html($reason), (int) $minutes);
    }

    private function duration_label(int $minutes): string {
        if ($minutes < 60) {
            // translators: %d: minutes duration
            return sprintf(esc_html__('%d minutes', 'wp-secure-guard'), (int) $minutes);
        }

        $hours = (int) ($minutes / 60);
        // translators: %d: hours duration
        return sprintf(esc_html(_n('%d hour', '%d hours', $hours, 'wp-secure-guard')), (int) $hours);
    }
}
