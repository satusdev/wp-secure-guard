<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Tokens_Page {
    private const RECENT_TOKENS_TTL = 600;
    private const PER_PAGE          = 25;

    private Secure_Guard_Token_Repository $tokens;
    private Secure_Guard_Token_Manager $token_manager;
    private array $settings;
    private Secure_Guard_Log_Repository $logs;

    public function __construct(Secure_Guard_Token_Repository $tokens, Secure_Guard_Token_Manager $token_manager, array $settings, Secure_Guard_Log_Repository $logs) {
        $this->tokens = $tokens;
        $this->token_manager = $token_manager;
        $this->settings = $settings;
        $this->logs = $logs;
    }

    public function register(): void {
        add_action('admin_post_secure_guard_create_token',  [$this, 'handle_create']);
        add_action('admin_post_secure_guard_revoke_token',  [$this, 'handle_revoke']);
        add_action('admin_post_secure_guard_delete_token',  [$this, 'handle_delete']);
        add_action('admin_post_secure_guard_reissue_token', [$this, 'handle_reissue']);
        add_action('admin_post_secure_guard_edit_token',    [$this, 'handle_edit']);
        add_action('admin_post_sg_export_tokens', [$this, 'handle_export']);
    }

    public function handle_create(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('secure_guard_create_token');

        $name = sanitize_text_field(wp_unslash((string) ($_POST['name'] ?? 'Token')));
        $scopes_raw = sanitize_text_field(wp_unslash((string) ($_POST['scope'] ?? 'read_posts')));
        // Reject any scope not in the defined allowlist to prevent arbitrary scope inflation.
        $scopes = array_filter(array_map('sanitize_key', array_map('trim', explode(',', $scopes_raw))));
        // Reject any scope not in the defined allowlist to prevent arbitrary scope inflation.
        $scopes = array_values(array_intersect($scopes, Secure_Guard_Config::VALID_SCOPES));
        if (empty($scopes)) {
            $scopes = ['read_posts'];
        }

        $allowed_endpoints = sanitize_textarea_field(wp_unslash((string) ($_POST['allowed_endpoints'] ?? '')));
        $allowed_ips = sanitize_textarea_field(wp_unslash((string) ($_POST['allowed_ips'] ?? '')));
        $rate_limit = isset($_POST['rate_limit_per_minute']) && $_POST['rate_limit_per_minute'] !== '' ? max(1, (int) wp_unslash($_POST['rate_limit_per_minute'])) : null;
        $expires_at = sanitize_text_field(wp_unslash((string) ($_POST['expires_at'] ?? '')));
        $ttl_minutes = max(1, (int) ($this->settings['jwt_ttl_minutes'] ?? 60));
        $default_expires_at = gmdate('Y-m-d H:i:s', time() + ($ttl_minutes * MINUTE_IN_SECONDS));
        if ($expires_at !== '') {
            $expires_timestamp = strtotime($expires_at);
            if ($expires_timestamp === false) {
                $expires_at = $default_expires_at;
            } elseif ($expires_timestamp <= time()) {
                wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=expiry_past'));
                exit;
            } else {
                $expires_at = gmdate('Y-m-d H:i:s', $expires_timestamp);
            }
        } else {
            $expires_at = $default_expires_at;
        }

        $jti = str_replace('-', '', wp_generate_uuid4());
        $kid = 'default';
        $token_id = $this->tokens->create_token($name, '', $scopes, $allowed_endpoints, $allowed_ips, $rate_limit, $expires_at, 'jwt', $jti, $kid);
        if ($token_id <= 0) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=db'));
            exit;
        }

        $token_row = $this->tokens->get_active_by_id($token_id);
        if (!$token_row) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=lookup'));
            exit;
        }

        $plain_token = (string) $this->token_manager->issue_jwt_for_token_row($token_row);
        if ($plain_token === '') {
            $this->tokens->delete($token_id);
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=jwt'));
            exit;
        }

        $this->tokens->store_jwt($token_id, $plain_token);
        $this->logs->log('admin/tokens', 'POST', 'AUDIT', 'Token created: ' . $name, ['token_id' => $token_id, 'admin_user_id' => get_current_user_id()]);

        $recent_tokens = $this->get_recent_tokens();
        $recent_tokens[$token_id] = $plain_token;
        set_transient($this->recent_tokens_transient_key(), $recent_tokens, self::RECENT_TOKENS_TTL);

        delete_transient('sg_dashboard_stats');
        wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&created=1&token_id=' . $token_id));
        exit;
    }

    public function handle_revoke(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('secure_guard_revoke_token');

        $id = (int) wp_unslash($_POST['token_id'] ?? 0);
        if ($id > 0) {
            $this->tokens->revoke($id);
            $this->remove_recent_token($id);
            $this->logs->log('admin/tokens', 'POST', 'AUDIT', 'Token revoked', ['token_id' => $id, 'admin_user_id' => get_current_user_id()]);
        }

        delete_transient('sg_dashboard_stats');
        wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&revoked=1'));
        exit;
    }

    public function handle_reissue(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('secure_guard_reissue_token');

        $id = (int) wp_unslash($_POST['token_id'] ?? 0);
        if ($id <= 0) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=reissue'));
            exit;
        }

        $token_row = $this->tokens->get_active_by_id($id);
        if (!$token_row) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=reissue'));
            exit;
        }

        // Rotate the JTI — old JTI is added to the denylist first.
        $old_jti = (string) ($token_row['jti'] ?? '');
        $new_jti = $this->tokens->rotate_jti($id, $old_jti, $token_row['expires_at'] ?? null);
        if ($new_jti === null) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=jti'));
            exit;
        }

        // Re-fetch to get the updated jti in the row.
        $token_row = $this->tokens->get_active_by_id($id);
        if (!$token_row) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=reissue'));
            exit;
        }

        $plain_token = (string) $this->token_manager->issue_jwt_for_token_row($token_row);
        if ($plain_token === '') {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=jwt'));
            exit;
        }

        $this->tokens->store_jwt($id, $plain_token);
        $this->logs->log('admin/tokens', 'POST', 'AUDIT', 'Token reissued', ['token_id' => $id, 'admin_user_id' => get_current_user_id()]);

        $recent_tokens      = $this->get_recent_tokens();
        $recent_tokens[$id] = $plain_token;
        set_transient($this->recent_tokens_transient_key(), $recent_tokens, self::RECENT_TOKENS_TTL);

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&reissued=1&token_id=' . $id));
        exit;
    }

    public function handle_delete(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('secure_guard_delete_token');

        $id = (int) wp_unslash($_POST['token_id'] ?? 0);
        if ($id > 0) {
            $this->tokens->delete($id);
            $this->remove_recent_token($id);
            $this->logs->log('admin/tokens', 'POST', 'AUDIT', 'Token deleted', ['token_id' => $id, 'admin_user_id' => get_current_user_id()]);
        }

        delete_transient('sg_dashboard_stats');
        wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&deleted=1'));
        exit;
    }

    public function handle_edit(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }
        check_admin_referer('secure_guard_edit_token');

        $id = (int) wp_unslash($_POST['token_id'] ?? 0);
        if ($id <= 0) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=edit'));
            exit;
        }

        $name           = sanitize_text_field(wp_unslash((string) ($_POST['name'] ?? '')));
        $scopes_raw     = sanitize_text_field(wp_unslash((string) ($_POST['scope'] ?? 'read_posts')));
        $scopes         = array_filter(array_map('sanitize_key', array_map('trim', explode(',', $scopes_raw))));
        // Reject any scope not in the defined allowlist.
        $scopes         = array_values(array_intersect($scopes, Secure_Guard_Config::VALID_SCOPES));
        if (empty($scopes)) {
            $scopes = ['read_posts'];
        }
        $allowed_endpoints = sanitize_textarea_field(wp_unslash((string) ($_POST['allowed_endpoints'] ?? '')));
        $allowed_ips    = sanitize_textarea_field(wp_unslash((string) ($_POST['allowed_ips'] ?? '')));
        $rate_limit     = isset($_POST['rate_limit_per_minute']) && $_POST['rate_limit_per_minute'] !== ''
            ? max(1, (int) wp_unslash($_POST['rate_limit_per_minute'])) : null;
        $expires_at_raw = sanitize_text_field(wp_unslash((string) ($_POST['expires_at'] ?? '')));
        $expires_at     = null;
        if ($expires_at_raw !== '') {
            $ts = strtotime($expires_at_raw);
            if ($ts !== false && $ts > time()) {
                $expires_at = gmdate('Y-m-d H:i:s', $ts);
            } elseif ($ts !== false && $ts <= time()) {
                wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=expiry_past&edit_token_id=' . $id));
                exit;
            }
        }

        $ok = $this->tokens->update_token($id, $name, $scopes, $allowed_endpoints, $allowed_ips, $rate_limit, $expires_at);
        if (!$ok) {
            wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&error=edit&edit_token_id=' . $id));
            exit;
        }

        $this->logs->log('admin/tokens', 'POST', 'AUDIT', 'Token edited: ' . $name, ['token_id' => $id, 'admin_user_id' => get_current_user_id()]);
        delete_transient('sg_dashboard_stats');
        wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&edited=1'));
        exit;
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        $recent_tokens    = $this->get_recent_tokens();
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $current_page     = max(1, (int) wp_unslash($_GET['paged'] ?? 1));
        $total_tokens     = $this->tokens->count_tokens();
        $offset           = ($current_page - 1) * self::PER_PAGE;
        $rows             = $this->tokens->all_tokens(self::PER_PAGE, $offset);
        $total_pages      = max(1, (int) ceil($total_tokens / self::PER_PAGE));
        $tokens_base_url  = admin_url('admin.php?page=secure-guard-tokens');
        $created_token_id = isset($_GET['token_id']) ? (int) $_GET['token_id'] : 0;
        $created_token    = $created_token_id > 0 && isset($recent_tokens[$created_token_id]) ? $recent_tokens[$created_token_id] : null;
        $reissued_action  = !empty($_GET['reissued']);
        $reissued_token   = ($reissued_action && $created_token_id > 0 && isset($recent_tokens[$created_token_id])) ? $recent_tokens[$created_token_id] : null;
        $edit_token_id    = isset($_GET['edit_token_id']) ? (int) $_GET['edit_token_id'] : 0;

        $revealed_token_id = 0;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $reveal_nonce = isset($_GET['reveal_nonce']) ? sanitize_text_field(wp_unslash((string) $_GET['reveal_nonce'])) : '';
        if (!empty($_GET['reveal_token_id']) && $reveal_nonce !== '') {
            $candidate_id = (int) $_GET['reveal_token_id'];
            if ($candidate_id > 0 && wp_verify_nonce($reveal_nonce, 'secure_guard_reveal_token_' . $candidate_id)) {
                $revealed_token_id = $candidate_id;
            }
        }

        $hide_url = add_query_arg(['page' => 'secure-guard-tokens'], admin_url('admin.php'));
        ?>
        <div class="wrap secure-guard-ui">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                <h1><?php echo esc_html__('Tokens', 'wp-secure-guard'); ?></h1>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="sg_export_tokens" />
                    <?php wp_nonce_field('sg_export_tokens'); ?>
                    <button type="submit" class="button button-secondary"><?php echo esc_html__('Export to CSV', 'wp-secure-guard'); ?></button>
                </form>
            </div>
            <p class="description"><?php echo esc_html__('JWT token values are hidden by default. You can reveal recently generated tokens on demand for a short time.', 'wp-secure-guard'); ?></p>
            <div class="notice notice-info"><p><?php echo esc_html__('Logged-in WordPress users (Gutenberg, page builders, media library) bypass JWT enforcement automatically. JWT tokens are for external programmatic API callers that send Authorization: Bearer TOKEN.', 'wp-secure-guard'); ?></p></div>

            <?php if ($reissued_action && $reissued_token): ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html__('Token re-issued. Old JWT invalidated. New JWT:', 'wp-secure-guard'); ?> <code style="word-break:break-all;"><?php echo esc_html($reissued_token); ?></code> <button type="button" class="button button-small sg-copy-btn" data-copy="<?php echo esc_attr($reissued_token); ?>"><?php esc_html_e('Copy', 'wp-secure-guard'); ?></button></p></div>
            <?php elseif ($reissued_action): ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html__('Token re-issued successfully. The new JWT is shown in the table below.', 'wp-secure-guard'); ?></p></div>
            <?php endif; ?>

            <?php if (!empty($_GET['edited'])): ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html__('Token updated successfully.', 'wp-secure-guard'); ?></p></div>
            <?php endif; ?>

            <?php if (!empty($_GET['created'])): ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html__('Token created successfully.', 'wp-secure-guard'); ?></p></div>
            <?php endif; ?>

            <?php if (!empty($_GET['revoked'])): ?>
                <div class="notice notice-warning is-dismissible"><p><?php echo esc_html__('Token revoked.', 'wp-secure-guard'); ?></p></div>
            <?php endif; ?>

            <?php if (!empty($_GET['deleted'])): ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html__('Token deleted.', 'wp-secure-guard'); ?></p></div>
            <?php endif; ?>

            <?php if (!empty($_GET['error'])): ?>
                <?php $error_code = sanitize_key((string) $_GET['error']); ?>
                <?php if ($error_code === 'db'): ?>
                    <div class="notice notice-error is-dismissible"><p><?php echo esc_html__('Token could not be created: database insert failed. Check the token table schema and DB permissions.', 'wp-secure-guard'); ?></p></div>
                <?php elseif ($error_code === 'lookup'): ?>
                    <div class="notice notice-error is-dismissible"><p><?php echo esc_html__('Token row was created but could not be loaded back. Check database consistency.', 'wp-secure-guard'); ?></p></div>
                <?php elseif ($error_code === 'expiry_past'): ?>
                    <div class="notice notice-error is-dismissible"><p><?php echo esc_html__('Expiration date must be in the future. Please choose a later date/time.', 'wp-secure-guard'); ?></p></div>
                <?php elseif ($error_code === 'jwt'): ?>
                    <div class="notice notice-error is-dismissible"><p><?php echo esc_html__('JWT could not be signed. Ensure a JWT secret is configured in Settings → REST &amp; JWT.', 'wp-secure-guard'); ?></p></div>
                <?php elseif ($error_code === 'jti'): ?>
                    <div class="notice notice-error is-dismissible"><p><?php echo esc_html__('JTI rotation failed. The old token may already be revoked or the database is unavailable.', 'wp-secure-guard'); ?></p></div>
                <?php elseif ($error_code === 'reissue'): ?>
                    <div class="notice notice-error is-dismissible"><p><?php echo esc_html__('Re-issue failed: token not found or already revoked/expired.', 'wp-secure-guard'); ?></p></div>
                <?php elseif ($error_code === 'edit'): ?>
                    <div class="notice notice-error is-dismissible"><p><?php echo esc_html__('Token update failed. Please check the values and try again.', 'wp-secure-guard'); ?></p></div>
                <?php else: ?>
                    <div class="notice notice-error is-dismissible"><p><?php echo esc_html__('An unexpected error occurred. Check JWT configuration and try again.', 'wp-secure-guard'); ?></p></div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($created_token && !$reissued_action): ?>
                <div class="notice notice-success"><p><?php echo esc_html__('New token generated:', 'wp-secure-guard'); ?> <code style="word-break:break-all;"><?php echo esc_html($created_token); ?></code> <button type="button" class="button button-small sg-copy-btn" data-copy="<?php echo esc_attr($created_token); ?>"><?php esc_html_e('Copy', 'wp-secure-guard'); ?></button></p></div>
            <?php endif; ?>

            <div class="card">
            <h2><?php echo esc_html__('Create Token', 'wp-secure-guard'); ?></h2>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="secure_guard_create_token" />
                <?php wp_nonce_field('secure_guard_create_token'); ?>
                <table class="form-table" role="presentation">
                    <tr><th><?php echo esc_html__('Name', 'wp-secure-guard'); ?></th><td><input type="text" name="name" class="regular-text" required /></td></tr>
                    <tr><th><?php echo esc_html__('Scopes', 'wp-secure-guard'); ?></th><td><input type="text" name="scope" class="regular-text" value="read_posts" /><p class="description"><?php echo esc_html(implode(', ', Secure_Guard_Config::VALID_SCOPES)); ?></p></td></tr>
                    <tr><th><?php echo esc_html__('Allowed Endpoints', 'wp-secure-guard'); ?></th><td><textarea name="allowed_endpoints" rows="5" cols="60" placeholder="/wp/v2/posts*"></textarea></td></tr>
                    <tr><th><?php echo esc_html__('Allowed IPs', 'wp-secure-guard'); ?></th><td><textarea name="allowed_ips" rows="4" cols="60" placeholder="12.34.56.78"></textarea></td></tr>
                    <tr><th><?php echo esc_html__('Rate limit per minute', 'wp-secure-guard'); ?></th><td><input type="number" min="1" name="rate_limit_per_minute" value="100" /></td></tr>
                    <tr><th><?php echo esc_html__('Expiration (UTC)', 'wp-secure-guard'); ?></th><td><input type="datetime-local" name="expires_at" /></td></tr>
                </table>
                <?php submit_button(__('Generate Token', 'wp-secure-guard')); ?>
            </form>
            </div>

            <div class="card">
                <h2><?php echo esc_html__('Existing Tokens', 'wp-secure-guard'); ?></h2>
            <p class="description" style="margin-bottom:8px;">
                <?php
                // translators: 1: start index, 2: end index, 3: total number of tokens
                printf(esc_html__('Showing %1$d–%2$d of %3$d tokens.', 'wp-secure-guard'), (int) ($offset + 1), (int) min($offset + self::PER_PAGE, $total_tokens), (int) $total_tokens);
                ?>
                &nbsp;<button type="button" id="sg-toggle-revoked" class="button button-small" style="margin-left:8px;"><?php esc_html_e('Hide revoked', 'wp-secure-guard'); ?></button>
            </p>
            <table class="widefat striped">
                <thead><tr>
                    <th>ID</th>
                    <th><?php echo esc_html__('Name', 'wp-secure-guard'); ?></th>
                    <th><?php echo esc_html__('Token', 'wp-secure-guard'); ?></th>
                    <th><?php echo esc_html__('Scopes / Policy', 'wp-secure-guard'); ?></th>
                    <th><?php echo esc_html__('Expires', 'wp-secure-guard'); ?></th>
                    <th><?php echo esc_html__('Created', 'wp-secure-guard'); ?></th>
                    <th><?php echo esc_html__('Last used', 'wp-secure-guard'); ?></th>
                    <th><?php echo esc_html__('Status', 'wp-secure-guard'); ?></th>
                    <th><?php echo esc_html__('Actions', 'wp-secure-guard'); ?></th>
                </tr></thead>
                <tbody>
                <?php foreach ($rows as $row): ?>
                    <?php $row_id = (int) $row['id']; ?>
                    <?php
                        $db_jwt      = (string) ($row['token_hash'] ?? '');
                        $has_db_jwt  = str_starts_with($db_jwt, 'eyJ');
                        $transient_token = $recent_tokens[$row_id] ?? null;
                        $display_token   = $has_db_jwt ? $db_jwt : (is_string($transient_token) && $transient_token !== '' ? $transient_token : null);
                        $is_revealed     = $revealed_token_id === $row_id && $display_token !== null;
                    ?>
                    <?php
                        $is_active  = empty($row['revoked_at']);
                        $is_expired = $is_active && !empty($row['expires_at']) && strtotime((string) $row['expires_at']) < time();
                        $has_policy = !empty($row['allowed_endpoints']) || !empty($row['allowed_ips']) || !empty($row['rate_limit_per_minute']);
                        $tr_class   = '';
                        if (!$is_active) {
                            $tr_class = 'sg-row--revoked';
                        } elseif ($is_expired) {
                            $tr_class = 'sg-row--expired';
                        }
                    ?>
                    <tr<?php if ($tr_class) echo ' class="' . esc_attr($tr_class) . '"'; ?>>
                        <td><?php echo esc_html((string) $row_id); ?></td>
                        <td><strong><?php echo esc_html((string) $row['name']); ?></strong></td>
                        <td style="max-width:260px;">
                            <?php if ($is_revealed && $display_token !== null): ?>
                                <code style="word-break:break-all;font-size:11px;"><?php echo esc_html($display_token); ?></code><br />
                                <span class="sg-action-row" style="margin-top:4px;">
                                    <button type="button" class="button button-small sg-copy-btn" data-copy="<?php echo esc_attr($display_token); ?>"><?php esc_html_e('Copy', 'wp-secure-guard'); ?></button>
                                    <a class="button button-small" href="<?php echo esc_url($hide_url); ?>"><?php echo esc_html__('Hide', 'wp-secure-guard'); ?></a>
                                </span>
                            <?php elseif ($display_token !== null): ?>
                                <code>••••••••••••••••••••</code><br />
                                <a class="button button-small" href="<?php echo esc_url(wp_nonce_url(add_query_arg(['page' => 'secure-guard-tokens', 'reveal_token_id' => $row_id], admin_url('admin.php')), 'secure_guard_reveal_token_' . $row_id, 'reveal_nonce')); ?>"><?php echo esc_html__('Show', 'wp-secure-guard'); ?></a>
                            <?php else: ?>
                                <em style="color:#777;"><?php echo esc_html__('Not available', 'wp-secure-guard'); ?></em>
                            <?php endif; ?>
                        </td>
                        <td>
                            <span><?php echo esc_html((string) $row['scope']); ?></span>
                            <?php if ($has_policy): ?>
                            <details style="margin-top:4px;font-size:12px;">
                                <summary style="cursor:pointer;color:#2271b1;"><?php esc_html_e('Policy', 'wp-secure-guard'); ?></summary>
                                <ul style="margin:4px 0 0 12px;padding:0;">
                                    <?php if (!empty($row['allowed_endpoints'])): ?>
                                        <li><strong><?php esc_html_e('Endpoints:', 'wp-secure-guard'); ?></strong><br /><code><?php echo esc_html((string) $row['allowed_endpoints']); ?></code></li>
                                    <?php endif; ?>
                                    <?php if (!empty($row['allowed_ips'])): ?>
                                        <li><strong><?php esc_html_e('IPs:', 'wp-secure-guard'); ?></strong><br /><code><?php echo esc_html((string) $row['allowed_ips']); ?></code></li>
                                    <?php endif; ?>
                                    <?php if (!empty($row['rate_limit_per_minute'])): ?>
                                        <li><strong><?php esc_html_e('Rate limit:', 'wp-secure-guard'); ?></strong> <?php echo esc_html((string) $row['rate_limit_per_minute']); ?> req/min</li>
                                    <?php endif; ?>
                                </ul>
                            </details>
                            <?php endif; ?>
                        </td>
                        <td><?php echo esc_html((string) ($row['expires_at'] ?? '')); ?>
                            <?php if ($is_expired): ?>
                                <span class="sg-expiry-label sg-expiry-label--soon"><?php esc_html_e('Expired', 'wp-secure-guard'); ?></span>
                            <?php elseif (!empty($row['expires_at'])): ?>
                                <?php
                                    $days_left = (int) ceil((strtotime((string) $row['expires_at']) - time()) / DAY_IN_SECONDS);
                                    if ($days_left <= 7 && $days_left > 0):
                                ?>
                                    <span class="sg-expiry-label sg-expiry-label--soon">
                                        <?php
                                        // translators: %d: number of days left
                                        printf(esc_html__('in %d d', 'wp-secure-guard'), (int) $days_left);
                                        ?>
                                    </span>
                                <?php endif; ?>
                            <?php endif; ?>
                        </td>
                        <td><?php echo esc_html((string) ($row['created_at'] ?? '')); ?></td>
                        <td><?php echo !empty($row['last_used_at']) ? esc_html((string) $row['last_used_at']) : '&mdash;'; ?></td>
                        <td>
                            <?php if ($is_expired): ?>
                                <span class="sg-pill sg-pill--warning"><?php echo esc_html__('Expired', 'wp-secure-guard'); ?></span>
                            <?php elseif ($is_active): ?>
                                <span class="sg-pill sg-pill--allowed"><?php echo esc_html__('Active', 'wp-secure-guard'); ?></span>
                            <?php else: ?>
                                <span class="sg-pill sg-pill--revoked"><?php echo esc_html__('Revoked', 'wp-secure-guard'); ?></span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <div class="sg-action-row">
                                <?php if ($is_active): ?>
                                    <a class="button button-small" href="<?php echo esc_url(add_query_arg(['page' => 'secure-guard-tokens', 'edit_token_id' => $row_id], admin_url('admin.php'))); ?>"><?php esc_html_e('Edit', 'wp-secure-guard'); ?></a>
                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                        <input type="hidden" name="action" value="secure_guard_revoke_token" />
                                        <input type="hidden" name="token_id" value="<?php echo esc_attr((string) $row['id']); ?>" />
                                        <?php wp_nonce_field('secure_guard_revoke_token'); ?>
                                        <?php submit_button(__('Revoke', 'wp-secure-guard'), 'delete small', '', false); ?>
                                    </form>
                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                        <input type="hidden" name="action" value="secure_guard_reissue_token" />
                                        <input type="hidden" name="token_id" value="<?php echo esc_attr((string) $row['id']); ?>" />
                                        <?php wp_nonce_field('secure_guard_reissue_token'); ?>
                                        <?php submit_button(__('Re-issue JWT', 'wp-secure-guard'), 'secondary small', '', false); ?>
                                    </form>
                                <?php endif; ?>
                                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" onsubmit="return confirm('<?php echo esc_js(__('Delete this token permanently?', 'wp-secure-guard')); ?>');">
                                    <input type="hidden" name="action" value="secure_guard_delete_token" />
                                    <input type="hidden" name="token_id" value="<?php echo esc_attr((string) $row['id']); ?>" />
                                    <?php wp_nonce_field('secure_guard_delete_token'); ?>
                                    <?php submit_button(__('Delete', 'wp-secure-guard'), 'secondary small', '', false); ?>
                                </form>
                            </div>
                        </td>
                    </tr>
                    <?php if ($edit_token_id === $row_id && $is_active): ?>
                    <tr>
                        <td colspan="9" style="background:#f9f9f9;padding:0;">
                            <div class="sg-edit-form">
                                <h3 style="margin:0 0 12px;">
                                    <?php
                                    // translators: 1: token ID, 2: token name
                                    printf(esc_html__('Edit Token #%1$d — %2$s', 'wp-secure-guard'), (int) $row_id, esc_html((string) $row['name']));
                                    ?>
                                </h3>
                                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                    <input type="hidden" name="action" value="secure_guard_edit_token" />
                                    <input type="hidden" name="token_id" value="<?php echo esc_attr((string) $row_id); ?>" />
                                    <?php wp_nonce_field('secure_guard_edit_token'); ?>
                                    <table class="form-table" role="presentation" style="margin:0;">
                                        <tr><th><?php esc_html_e('Name', 'wp-secure-guard'); ?></th><td><input type="text" name="name" class="regular-text" value="<?php echo esc_attr((string) $row['name']); ?>" required /></td></tr>
                                        <tr><th><?php esc_html_e('Scopes', 'wp-secure-guard'); ?></th><td><input type="text" name="scope" class="regular-text" value="<?php echo esc_attr((string) $row['scope']); ?>" /><p class="description">read_posts, upload_media, full_api_access</p></td></tr>
                                        <tr><th><?php esc_html_e('Allowed Endpoints', 'wp-secure-guard'); ?></th><td><textarea name="allowed_endpoints" rows="5" cols="60"><?php echo esc_textarea((string) ($row['allowed_endpoints'] ?? '')); ?></textarea></td></tr>
                                        <tr><th><?php esc_html_e('Allowed IPs', 'wp-secure-guard'); ?></th><td><textarea name="allowed_ips" rows="4" cols="60"><?php echo esc_textarea((string) ($row['allowed_ips'] ?? '')); ?></textarea></td></tr>
                                        <tr><th><?php esc_html_e('Rate limit per minute', 'wp-secure-guard'); ?></th><td><input type="number" min="1" name="rate_limit_per_minute" value="<?php echo esc_attr((string) ($row['rate_limit_per_minute'] ?? '')); ?>" /></td></tr>
                                        <tr><th><?php esc_html_e('Expiration (UTC)', 'wp-secure-guard'); ?></th><td><input type="datetime-local" name="expires_at" value="<?php $exp = $row['expires_at'] ?? ''; echo $exp ? esc_attr(gmdate('Y-m-d\TH:i', strtotime($exp))) : ''; ?>" /></td></tr>
                                    </table>
                                    <p>
                                        <?php submit_button(__('Save Changes', 'wp-secure-guard'), 'primary', '', false); ?>
                                        &nbsp;
                                        <a class="button" href="<?php echo esc_url(add_query_arg(['page' => 'secure-guard-tokens'], admin_url('admin.php'))); ?>"><?php esc_html_e('Cancel', 'wp-secure-guard'); ?></a>
                                    </p>
                                </form>
                            </div>
                        </td>
                    </tr>
                    <?php endif; ?>
                <?php endforeach; ?>
                </tbody>
            </table>

            <?php if ($total_pages > 1): ?>
            <div class="tablenav bottom" style="margin-top:12px;">
                <div class="tablenav-pages" style="display:flex;align-items:center;gap:8px;">
                    <?php if ($current_page > 1): ?>
                        <a class="button" href="<?php echo esc_url(add_query_arg('paged', $current_page - 1, $tokens_base_url)); ?>">&laquo; <?php esc_html_e('Previous', 'wp-secure-guard'); ?></a>
                    <?php endif; ?>
                    <span class="paging-input">
                        <?php
                        // translators: 1: current page, 2: total pages
                        printf(esc_html__('Page %1$d of %2$d', 'wp-secure-guard'), (int) $current_page, (int) $total_pages);
                        ?>
                    </span>
                    <?php if ($current_page < $total_pages): ?>
                        <a class="button" href="<?php echo esc_url(add_query_arg('paged', $current_page + 1, $tokens_base_url)); ?>"><?php esc_html_e('Next', 'wp-secure-guard'); ?> &raquo;</a>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

            </div>

            <div class="card">
                <h2 style="margin-top:0;"><?php echo esc_html__('Usage & Verification', 'wp-secure-guard'); ?></h2>
                <p class="description"><?php echo esc_html__('Replace SITE and TOKEN values. Without token expect 403; with valid token expect route-specific responses.', 'wp-secure-guard'); ?></p>
                <pre style="white-space:pre-wrap;"><?php echo esc_html("# Without token (expect 403)\ncurl -i https://SITE/wp-json/wp/v2/posts\n\n# With token to non-sensitive route\ncurl -i -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/posts\n\n# With token to sensitive route (requires full_api_access when enabled)\ncurl -i -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/users"); ?></pre>
            </div>
        </div>

        <script>
        (function() {
            document.addEventListener('DOMContentLoaded', function() {
                // Copy button
                document.querySelectorAll('.sg-copy-btn').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        var text = btn.getAttribute('data-copy') || '';
                        if (!text) return;
                        if (navigator.clipboard && navigator.clipboard.writeText) {
                            navigator.clipboard.writeText(text).then(function() {
                                btn.textContent = '<?php echo esc_js(__('Copied!', 'wp-secure-guard')); ?>';
                                btn.classList.add('copied');
                                setTimeout(function() {
                                    btn.textContent = '<?php echo esc_js(__('Copy', 'wp-secure-guard')); ?>';
                                    btn.classList.remove('copied');
                                }, 2000);
                            });
                        } else {
                            var ta = document.createElement('textarea');
                            ta.value = text;
                            ta.style.position = 'fixed';
                            ta.style.opacity = '0';
                            document.body.appendChild(ta);
                            ta.select();
                            try { document.execCommand('copy'); } catch(e) {}
                            document.body.removeChild(ta);
                            btn.textContent = '<?php echo esc_js(__('Copied!', 'wp-secure-guard')); ?>';
                            btn.classList.add('copied');
                            setTimeout(function() {
                                btn.textContent = '<?php echo esc_js(__('Copy', 'wp-secure-guard')); ?>';
                                btn.classList.remove('copied');
                            }, 2000);
                        }
                    });
                });

                // Show / hide revoked rows
                var toggleBtn = document.getElementById('sg-toggle-revoked');
                if (toggleBtn) {
                    var revokedRows = document.querySelectorAll('tr.sg-row--revoked');
                    var hidden = false;
                    toggleBtn.addEventListener('click', function() {
                        hidden = !hidden;
                        revokedRows.forEach(function(r) { r.style.display = hidden ? 'none' : ''; });
                        toggleBtn.textContent = hidden
                            ? '<?php echo esc_js(__('Show revoked', 'wp-secure-guard')); ?>'
                            : '<?php echo esc_js(__('Hide revoked', 'wp-secure-guard')); ?>';
                    });
                }
            });
        })();
        </script>
        <?php
    }

    private function recent_tokens_transient_key(): string {
        return 'secure_guard_recent_tokens_' . get_current_user_id();
    }

    private function get_recent_tokens(): array {
        $value = get_transient($this->recent_tokens_transient_key());
        if (!is_array($value)) {
            return [];
        }

        $tokens = [];
        foreach ($value as $id => $plain_token) {
            $token_id = (int) $id;
            $token = is_string($plain_token) ? $plain_token : '';
            if ($token_id > 0 && $token !== '') {
                $tokens[$token_id] = $token;
            }
        }

        return $tokens;
    }

    private function remove_recent_token(int $token_id): void {
        if ($token_id <= 0) {
            return;
        }

        $tokens = $this->get_recent_tokens();
        if (!isset($tokens[$token_id])) {
            return;
        }

        unset($tokens[$token_id]);
        set_transient($this->recent_tokens_transient_key(), $tokens, self::RECENT_TOKENS_TTL);
    }

    public function handle_export(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        check_admin_referer('sg_export_tokens');

        $tokens = $this->tokens->all_tokens(1000, 0); // Export up to 1000 tokens
        
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=secure-guard-tokens-' . gmdate('Y-m-d') . '.csv');

        $output = fopen('php://output', 'w');
        fputcsv($output, ['ID', 'Name', 'Type', 'Scope', 'Allowed Endpoints', 'Allowed IPs', 'Rate Limit', 'Expires', 'Last Used', 'Created', 'Status']);

        foreach ($tokens as $token) {
            $is_active = empty($token['revoked_at']);
            $is_expired = $is_active && !empty($token['expires_at']) && strtotime((string) $token['expires_at']) < time();
            $status = $is_expired ? 'Expired' : ($is_active ? 'Active' : 'Revoked');

            fputcsv($output, [
                $token['id'],
                $token['name'],
                $token['token_type'],
                $token['scope'],
                $token['allowed_endpoints'],
                $token['allowed_ips'],
                $token['rate_limit_per_minute'] ?? 'None',
                $token['expires_at'] ?? 'Never',
                $token['last_used_at'] ?? 'Never',
                $token['created_at'],
                $status
            ]);
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($output);
        exit;
    }
}
