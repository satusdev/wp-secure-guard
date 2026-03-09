<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Tokens_Page {
    private const RECENT_TOKENS_TTL = 600;

    private Secure_Guard_Token_Repository $tokens;

    public function __construct(Secure_Guard_Token_Repository $tokens) {
        $this->tokens = $tokens;
    }

    public function register(): void {
        add_action('admin_post_secure_guard_create_token', [$this, 'handle_create']);
        add_action('admin_post_secure_guard_revoke_token', [$this, 'handle_revoke']);
        add_action('admin_post_secure_guard_delete_token', [$this, 'handle_delete']);
    }

    public function handle_create(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }
        check_admin_referer('secure_guard_create_token');

        $name = sanitize_text_field((string) ($_POST['name'] ?? 'Token'));
        $scopes_raw = sanitize_text_field((string) ($_POST['scope'] ?? 'read_posts'));
        $scopes = array_filter(array_map('sanitize_key', array_map('trim', explode(',', $scopes_raw))));
        $allowed_endpoints = sanitize_textarea_field((string) ($_POST['allowed_endpoints'] ?? ''));
        $allowed_ips = sanitize_textarea_field((string) ($_POST['allowed_ips'] ?? ''));
        $rate_limit = isset($_POST['rate_limit_per_minute']) && $_POST['rate_limit_per_minute'] !== '' ? max(1, (int) $_POST['rate_limit_per_minute']) : null;
        $expires_at = sanitize_text_field((string) ($_POST['expires_at'] ?? ''));
        $expires_at = $expires_at !== '' ? gmdate('Y-m-d H:i:s', strtotime($expires_at)) : null;

        $plain_token = 'sapg_' . wp_generate_password(24, false, false);
        $token_id = $this->tokens->create_token($name, $plain_token, $scopes, $allowed_endpoints, $allowed_ips, $rate_limit, $expires_at);

        $recent_tokens = $this->get_recent_tokens();
        $recent_tokens[$token_id] = $plain_token;
        set_transient($this->recent_tokens_transient_key(), $recent_tokens, self::RECENT_TOKENS_TTL);

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&created=1&token_id=' . $token_id));
        exit;
    }

    public function handle_revoke(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }
        check_admin_referer('secure_guard_revoke_token');

        $id = (int) ($_POST['token_id'] ?? 0);
        if ($id > 0) {
            $this->tokens->revoke($id);
            $this->remove_recent_token($id);
        }

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&revoked=1'));
        exit;
    }

    public function handle_delete(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }
        check_admin_referer('secure_guard_delete_token');

        $id = (int) ($_POST['token_id'] ?? 0);
        if ($id > 0) {
            $this->tokens->delete($id);
            $this->remove_recent_token($id);
        }

        wp_safe_redirect(admin_url('admin.php?page=secure-guard-tokens&deleted=1'));
        exit;
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        $recent_tokens = $this->get_recent_tokens();
        $rows = $this->tokens->all_tokens();
        $created_token_id = isset($_GET['token_id']) ? (int) $_GET['token_id'] : 0;
        $created_token = $created_token_id > 0 && isset($recent_tokens[$created_token_id]) ? $recent_tokens[$created_token_id] : null;

        $revealed_token_id = 0;
        $reveal_nonce = isset($_GET['reveal_nonce']) ? sanitize_text_field((string) $_GET['reveal_nonce']) : '';
        if (!empty($_GET['reveal_token_id']) && $reveal_nonce !== '') {
            $candidate_id = (int) $_GET['reveal_token_id'];
            if ($candidate_id > 0 && wp_verify_nonce($reveal_nonce, 'secure_guard_reveal_token_' . $candidate_id)) {
                $revealed_token_id = $candidate_id;
            }
        }

        $hide_url = add_query_arg(['page' => 'secure-guard-tokens'], admin_url('admin.php'));
        ?>
        <div class="wrap secure-guard-ui">
            <h1><?php echo esc_html__('Tokens', 'secure-guard'); ?></h1>
            <p class="description"><?php echo esc_html__('Token values are hidden by default. You can reveal recently generated tokens on demand for a short time.', 'secure-guard'); ?></p>

            <?php if (!empty($_GET['created'])): ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html__('Token created successfully.', 'secure-guard'); ?></p></div>
            <?php endif; ?>

            <?php if (!empty($_GET['revoked'])): ?>
                <div class="notice notice-warning is-dismissible"><p><?php echo esc_html__('Token revoked.', 'secure-guard'); ?></p></div>
            <?php endif; ?>

            <?php if (!empty($_GET['deleted'])): ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html__('Token deleted.', 'secure-guard'); ?></p></div>
            <?php endif; ?>

            <?php if ($created_token): ?>
                <div class="notice notice-success"><p><?php echo esc_html__('New token generated:', 'secure-guard'); ?> <strong><?php echo esc_html($created_token); ?></strong></p></div>
            <?php endif; ?>

            <div class="card" style="max-width:1200px;padding:16px;">
            <h2><?php echo esc_html__('Create Token', 'secure-guard'); ?></h2>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="secure_guard_create_token" />
                <?php wp_nonce_field('secure_guard_create_token'); ?>
                <table class="form-table" role="presentation">
                    <tr><th><?php echo esc_html__('Name', 'secure-guard'); ?></th><td><input type="text" name="name" class="regular-text" required /></td></tr>
                    <tr><th><?php echo esc_html__('Scopes', 'secure-guard'); ?></th><td><input type="text" name="scope" class="regular-text" value="read_posts" /><p class="description">read_posts, upload_media, full_api_access</p></td></tr>
                    <tr><th><?php echo esc_html__('Allowed Endpoints', 'secure-guard'); ?></th><td><textarea name="allowed_endpoints" rows="5" cols="60" placeholder="/wp/v2/posts*"></textarea></td></tr>
                    <tr><th><?php echo esc_html__('Allowed IPs', 'secure-guard'); ?></th><td><textarea name="allowed_ips" rows="4" cols="60" placeholder="12.34.56.78"></textarea></td></tr>
                    <tr><th><?php echo esc_html__('Rate limit per minute', 'secure-guard'); ?></th><td><input type="number" min="1" name="rate_limit_per_minute" value="100" /></td></tr>
                    <tr><th><?php echo esc_html__('Expiration (UTC)', 'secure-guard'); ?></th><td><input type="datetime-local" name="expires_at" /></td></tr>
                </table>
                <?php submit_button(__('Generate Token', 'secure-guard')); ?>
            </form>
            </div>

            <div class="card" style="max-width:1200px;padding:16px;margin-top:16px;">
            <h2><?php echo esc_html__('Existing Tokens', 'secure-guard'); ?></h2>
            <table class="widefat striped">
                <thead><tr><th>ID</th><th><?php echo esc_html__('Name', 'secure-guard'); ?></th><th><?php echo esc_html__('Token', 'secure-guard'); ?></th><th><?php echo esc_html__('Scopes', 'secure-guard'); ?></th><th><?php echo esc_html__('Expires', 'secure-guard'); ?></th><th><?php echo esc_html__('Last used', 'secure-guard'); ?></th><th><?php echo esc_html__('Status', 'secure-guard'); ?></th><th><?php echo esc_html__('Action', 'secure-guard'); ?></th></tr></thead>
                <tbody>
                <?php foreach ($rows as $row): ?>
                    <?php $row_id = (int) $row['id']; ?>
                    <?php $row_token = $recent_tokens[$row_id] ?? null; ?>
                    <?php $is_revealed = $revealed_token_id === $row_id && is_string($row_token) && $row_token !== ''; ?>
                    <tr>
                        <td><?php echo esc_html((string) $row_id); ?></td>
                        <td><?php echo esc_html((string) $row['name']); ?></td>
                        <td>
                            <?php if ($is_revealed): ?>
                                <code style="word-break: break-all;"><?php echo esc_html($row_token); ?></code><br />
                                <a class="button button-small" href="<?php echo esc_url($hide_url); ?>"><?php echo esc_html__('Hide', 'secure-guard'); ?></a>
                            <?php elseif (is_string($row_token) && $row_token !== ''): ?>
                                <code>••••••••••••••••••••</code><br />
                                <a class="button button-small" href="<?php echo esc_url(wp_nonce_url(add_query_arg(['page' => 'secure-guard-tokens', 'reveal_token_id' => $row_id], admin_url('admin.php')), 'secure_guard_reveal_token_' . $row_id, 'reveal_nonce')); ?>"><?php echo esc_html__('Show', 'secure-guard'); ?></a>
                            <?php else: ?>
                                <em><?php echo esc_html__('Not available', 'secure-guard'); ?></em>
                            <?php endif; ?>
                        </td>
                        <td><?php echo esc_html((string) $row['scope']); ?></td>
                        <td><?php echo esc_html((string) ($row['expires_at'] ?? '')); ?></td>
                        <td><?php echo esc_html((string) ($row['last_used_at'] ?? '')); ?></td>
                        <td>
                            <?php if (empty($row['revoked_at'])): ?>
                                <span class="sg-pill"><?php echo esc_html__('Active', 'secure-guard'); ?></span>
                            <?php else: ?>
                                <span class="sg-pill"><?php echo esc_html__('Revoked', 'secure-guard'); ?></span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <div class="sg-action-row">
                                <?php if (empty($row['revoked_at'])): ?>
                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                        <input type="hidden" name="action" value="secure_guard_revoke_token" />
                                        <input type="hidden" name="token_id" value="<?php echo esc_attr((string) $row['id']); ?>" />
                                        <?php wp_nonce_field('secure_guard_revoke_token'); ?>
                                        <?php submit_button(__('Revoke', 'secure-guard'), 'delete small', '', false); ?>
                                    </form>
                                <?php endif; ?>

                                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" onsubmit="return confirm('<?php echo esc_js(__('Delete this token permanently?', 'secure-guard')); ?>');">
                                    <input type="hidden" name="action" value="secure_guard_delete_token" />
                                    <input type="hidden" name="token_id" value="<?php echo esc_attr((string) $row['id']); ?>" />
                                    <?php wp_nonce_field('secure_guard_delete_token'); ?>
                                    <?php submit_button(__('Delete', 'secure-guard'), 'secondary small', '', false); ?>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>

            <div class="card" style="max-width:1200px;padding:16px;margin-top:16px;">
                <h2 style="margin-top:0;"><?php echo esc_html__('Usage & Verification', 'secure-guard'); ?></h2>
                <p class="description"><?php echo esc_html__('Replace SITE and TOKEN values. Use Logs page to confirm blocked/allowed decisions.', 'secure-guard'); ?></p>
                <pre style="white-space:pre-wrap;"><?php echo esc_html("# Without token (expect 403 when REST lock is enabled)\ncurl https://SITE/wp-json/wp/v2/posts\n\n# With token (expect route response when endpoint exists and policy allows)\ncurl -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/posts\n\n# Sensitive endpoint check (requires full_api_access scope)\ncurl -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/users\n\n# Missing route check (expect WordPress 404 rest_no_route)\ncurl -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v99/does-not-exist"); ?></pre>
            </div>
        </div>
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
}
