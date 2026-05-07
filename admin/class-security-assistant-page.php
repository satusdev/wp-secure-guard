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
    }

    public function handle_apply_preset(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        check_admin_referer('sg_apply_security_preset');

        $preset_slug = sanitize_key((string) ($_POST['preset'] ?? ''));
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
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
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
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        check_admin_referer('sg_lockdown_control');

        $settings = Secure_Guard_Config::get_settings();
        if (empty($settings['lock_state_enabled'])) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-assistant&lockdown_disabled=1'));
            exit;
        }

        $command = sanitize_key((string) ($_POST['lockdown_command'] ?? ''));
        if ($command === 'engage') {
            $duration_minutes = max(5, min(1440, (int) ($_POST['duration_minutes'] ?? 60)));
            $reason = sanitize_text_field((string) ($_POST['reason'] ?? 'Manual emergency lockdown'));
            if ($reason === '') {
                $reason = __('Manual emergency lockdown', 'secure-guard');
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

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
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
        echo '<h1>' . esc_html__('Security Assistant', 'secure-guard') . '</h1>';
        echo '<p class="description">' . esc_html__('Use this page for common security operations without tuning every advanced setting manually.', 'secure-guard') . '</p>';

        $this->render_notices();
        $this->render_env_override_notice();

        echo '<div class="sg-metric-grid">';
        $this->render_metric(__('Current Mode', 'secure-guard'), Secure_Guard_Security_Presets::label($current_preset), $current_preset === 'custom' ? __('Manual settings differ from a preset.', 'secure-guard') : __('Preset-matched configuration.', 'secure-guard'), $current_preset === 'custom' ? 'warning' : 'ok');
        $this->render_metric(__('Blocked IPs', 'secure-guard'), (string) $blocked_ips, __('Manage false positives and active bans.', 'secure-guard'), $blocked_ips > 0 ? 'alert' : 'ok');
        $this->render_metric(__('Failed Logins', 'secure-guard'), (string) $failed_logins, __('Total failed-login events in the retained log window.', 'secure-guard'), $failed_logins > 0 ? 'alert' : 'ok');
        $this->render_metric(__('Active Tokens', 'secure-guard'), (string) $active_tokens, __('JWT/API credentials currently active.', 'secure-guard'), $active_tokens > 0 ? 'ok' : 'warning');
        $this->render_metric(__('Lockdown', 'secure-guard'), $lock_data ? __('Active', 'secure-guard') : __('Normal', 'secure-guard'), $lock_data ? $this->format_lock_summary($lock_data) : __('Emergency lockdown is not active.', 'secure-guard'), $lock_data ? 'alert' : 'ok');
        $this->render_metric(__('Recommendations', 'secure-guard'), (string) count($recommendations), __('Actionable setup and safety items.', 'secure-guard'), count($recommendations) > 0 ? 'warning' : 'ok');
        echo '</div>';

        $this->render_preset_cards($current_preset, $saved_preset);
        $this->render_lockdown_panel($lock_data, $settings);
        $this->render_recommendations($recommendations);

        echo '</div>';
    }

    private function render_notices(): void {
        if (!empty($_GET['preset_applied'])) {
            $slug = sanitize_key((string) $_GET['preset_applied']);
            echo '<div class="notice notice-success is-dismissible"><p>' . sprintf(esc_html__('Security preset applied: %s.', 'secure-guard'), esc_html(Secure_Guard_Security_Presets::label($slug))) . '</p></div>';
        }
        if (!empty($_GET['preset_error'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('The selected preset is not valid.', 'secure-guard') . '</p></div>';
        }
        if (!empty($_GET['rollback'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Previous settings restored.', 'secure-guard') . '</p></div>';
        }
        if (!empty($_GET['rollback_error'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('No previous settings snapshot is available to restore.', 'secure-guard') . '</p></div>';
        }
        if (!empty($_GET['lockdown'])) {
            $state = sanitize_key((string) $_GET['lockdown']);
            $message = $state === 'engaged' ? __('Emergency lockdown engaged.', 'secure-guard') : __('Emergency lockdown released.', 'secure-guard');
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($message) . '</p></div>';
        }
        if (!empty($_GET['lockdown_disabled'])) {
            echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__('Lockdown controls are disabled in Adaptive Security settings.', 'secure-guard') . '</p></div>';
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

        echo '<div class="notice notice-info inline"><p><strong>' . esc_html__('Environment-managed JWT settings detected.', 'secure-guard') . '</strong> ';
        echo esc_html__('Preset changes will not overwrite these fields:', 'secure-guard') . ' ';
        foreach ($overrides as $index => $env_var) {
            echo ($index > 0 ? ', ' : '') . '<code>' . esc_html($env_var) . '</code>';
        }
        echo '.</p></div>';
    }

    private function render_preset_cards(string $current_preset, string $saved_preset): void {
        echo '<h2>' . esc_html__('Security Presets', 'secure-guard') . '</h2>';
        echo '<div class="sg-preset-grid">';

        foreach (Secure_Guard_Security_Presets::all() as $slug => $preset) {
            $is_current = $current_preset === $slug;
            echo '<div class="card sg-preset-card' . ($is_current ? ' sg-preset-card--active' : '') . '">';
            echo '<h3>' . esc_html((string) $preset['label']) . '</h3>';
            echo '<p><strong>' . esc_html__('Best for:', 'secure-guard') . '</strong> ' . esc_html((string) $preset['target']) . '</p>';
            echo '<p class="description">' . esc_html((string) $preset['description']) . '</p>';
            if ($is_current) {
                echo '<p><span class="sg-pill sg-pill--allowed">' . esc_html__('Active', 'secure-guard') . '</span></p>';
            } elseif ($saved_preset === $slug) {
                echo '<p><span class="sg-pill sg-pill--warning">' . esc_html__('Modified', 'secure-guard') . '</span></p>';
            }
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            echo '<input type="hidden" name="action" value="sg_apply_security_preset" />';
            echo '<input type="hidden" name="preset" value="' . esc_attr((string) $slug) . '" />';
            wp_nonce_field('sg_apply_security_preset');
            $button_args = [];
            if ($slug === 'maximum') {
                $button_args['onclick'] = 'return confirm(\'' . esc_js(__('Maximum Security enables stricter REST and traffic controls. Confirm whitelists, API clients, and admin recovery paths before applying. Continue?', 'secure-guard')) . '\')';
            }
            submit_button($is_current ? __('Reapply Preset', 'secure-guard') : __('Apply Preset', 'secure-guard'), $is_current ? 'secondary' : 'primary', 'submit', false, $button_args);
            echo '</form>';
            echo '</div>';
        }

        echo '<div class="card sg-preset-card' . ($current_preset === 'custom' ? ' sg-preset-card--active' : '') . '">';
        echo '<h3>' . esc_html__('Custom', 'secure-guard') . '</h3>';
        echo '<p><strong>' . esc_html__('Best for:', 'secure-guard') . '</strong> ' . esc_html__('Teams that want advanced manual control.', 'secure-guard') . '</p>';
        echo '<p class="description">' . esc_html__('Custom mode is selected automatically when settings no longer match a preset.', 'secure-guard') . '</p>';
        echo '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=secure-guard-settings')) . '">' . esc_html__('Open Advanced Settings', 'secure-guard') . '</a></p>';
        echo '</div>';

        echo '</div>';

        $snapshot = get_option(Secure_Guard_Security_Presets::PREVIOUS_SETTINGS_OPTION, []);
        if (is_array($snapshot) && isset($snapshot['settings']) && is_array($snapshot['settings'])) {
            echo '<div class="card sg-lockdown-card" style="margin-top:16px;">';
            echo '<h3>' . esc_html__('Preset Recovery', 'secure-guard') . '</h3>';
            echo '<p class="description">' . esc_html__('Restore the settings snapshot captured before the last preset application.', 'secure-guard') . '</p>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" onsubmit="return confirm(\'' . esc_js(__('Restore previous Secure Guard settings?', 'secure-guard')) . '\')">';
            echo '<input type="hidden" name="action" value="sg_rollback_security_preset" />';
            wp_nonce_field('sg_rollback_security_preset');
            submit_button(__('Restore Previous Settings', 'secure-guard'), 'secondary', 'submit', false);
            echo '</form>';
            echo '</div>';
        }
    }

    private function render_lockdown_panel(?array $lock_data, array $settings): void {
        echo '<h2 style="margin-top:24px;">' . esc_html__('Emergency Lockdown', 'secure-guard') . '</h2>';
        echo '<div class="card sg-lockdown-card">';

        if (empty($settings['lock_state_enabled'])) {
            echo '<p><span class="sg-pill sg-pill--warning">' . esc_html__('Disabled', 'secure-guard') . '</span> ' . esc_html__('Enable the lockdown system in Adaptive Security settings before using this control.', 'secure-guard') . '</p>';
            echo '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=secure-guard-settings&tab=adaptive-security')) . '">' . esc_html__('Open Adaptive Security Settings', 'secure-guard') . '</a></p>';
            echo '</div>';
            return;
        }

        if ($lock_data) {
            echo '<p><span class="sg-pill sg-pill--blocked">' . esc_html__('Active', 'secure-guard') . '</span> ' . esc_html($this->format_lock_summary($lock_data)) . '</p>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            echo '<input type="hidden" name="action" value="sg_lockdown_control" />';
            echo '<input type="hidden" name="lockdown_command" value="release" />';
            wp_nonce_field('sg_lockdown_control');
            submit_button(__('Restore Normal Mode', 'secure-guard'), 'primary', 'submit', false);
            echo '</form>';
            echo '</div>';
            return;
        }

        echo '<p class="description">' . esc_html__('Use during brute-force or scanning incidents. Non-admin traffic is temporarily restricted by the lock-state engine.', 'secure-guard') . '</p>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" class="sg-action-row">';
        echo '<input type="hidden" name="action" value="sg_lockdown_control" />';
        echo '<input type="hidden" name="lockdown_command" value="engage" />';
        wp_nonce_field('sg_lockdown_control');
        echo '<label>' . esc_html__('Duration:', 'secure-guard') . ' <select name="duration_minutes">';
        foreach ([30, 60, 240, 720, 1440] as $minutes) {
            echo '<option value="' . esc_attr((string) $minutes) . '"' . selected($minutes, 60, false) . '>' . esc_html($this->duration_label($minutes)) . '</option>';
        }
        echo '</select></label>';
        echo '<label>' . esc_html__('Reason:', 'secure-guard') . ' <input type="text" name="reason" class="regular-text" value="' . esc_attr__('Manual emergency lockdown', 'secure-guard') . '" /></label>';
        submit_button(__('Enable Emergency Lockdown', 'secure-guard'), 'delete', 'submit', false, ['onclick' => 'return confirm(\'' . esc_js(__('Enable emergency lockdown now?', 'secure-guard')) . '\')']);
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
                'title' => __('Set a stable JWT secret', 'secure-guard'),
                'body' => __('Tokens currently depend on WordPress AUTH_KEY. A dedicated secret prevents accidental token invalidation during key rotation.', 'secure-guard'),
                'action' => __('Configure JWT', 'secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-settings&tab=rest-jwt'),
            ];
        }

        if (empty($settings['email_alerts_enabled'])) {
            $items[] = [
                'severity' => 'info',
                'title' => __('Enable security alerts', 'secure-guard'),
                'body' => __('Email alerts make hard blocks, integrity changes, and token expiry easier to respond to.', 'secure-guard'),
                'action' => __('Open Alerts', 'secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-settings&tab=alerts'),
            ];
        }

        if ($blocked_ips > 0) {
            $items[] = [
                'severity' => 'warning',
                'title' => __('Review active IP blocks', 'secure-guard'),
                'body' => __('Active blocks may include legitimate admins during brute-force events. Review before users report lockouts.', 'secure-guard'),
                'action' => __('Manage Blocks', 'secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-blocked-ips'),
            ];
        }

        if ($active_tokens === 0) {
            $items[] = [
                'severity' => 'info',
                'title' => __('Create the first API token', 'secure-guard'),
                'body' => __('REST lockdown is most useful when API clients use scoped JWT tokens instead of broad cookies.', 'secure-guard'),
                'action' => __('Manage Tokens', 'secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-tokens'),
            ];
        }

        if (!$lock_data && empty($settings['lock_state_enabled'])) {
            $items[] = [
                'severity' => 'warning',
                'title' => __('Enable lockdown readiness', 'secure-guard'),
                'body' => __('Emergency lockdown controls are unavailable until the lock-state engine is enabled.', 'secure-guard'),
                'action' => __('Open Adaptive Security', 'secure-guard'),
                'url' => admin_url('admin.php?page=secure-guard-settings&tab=adaptive-security'),
            ];
        }

        return $items;
    }

    /**
     * @param array<int,array{severity:string,title:string,body:string,action:string,url:string}> $recommendations
     */
    private function render_recommendations(array $recommendations): void {
        echo '<h2 style="margin-top:24px;">' . esc_html__('Recommendations', 'secure-guard') . '</h2>';
        echo '<div class="card sg-recommendations-card">';

        if ($recommendations === []) {
            echo '<p><span class="sg-pill sg-pill--allowed">' . esc_html__('Good', 'secure-guard') . '</span> ' . esc_html__('No high-priority recommendations right now.', 'secure-guard') . '</p>';
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
        $reason = sanitize_text_field((string) ($lock_data['reason'] ?? __('Manual', 'secure-guard')));
        $expires = (int) ($lock_data['expires'] ?? 0);
        if ($expires <= time()) {
            return sprintf(__('Reason: %s. Expiring now.', 'secure-guard'), $reason);
        }

        $minutes = max(1, (int) ceil(($expires - time()) / MINUTE_IN_SECONDS));
        return sprintf(__('Reason: %1$s. Expires in about %2$d minute(s).', 'secure-guard'), $reason, $minutes);
    }

    private function duration_label(int $minutes): string {
        if ($minutes < 60) {
            return sprintf(__('%d minutes', 'secure-guard'), $minutes);
        }

        $hours = (int) ($minutes / 60);
        return sprintf(_n('%d hour', '%d hours', $hours, 'secure-guard'), $hours);
    }
}
