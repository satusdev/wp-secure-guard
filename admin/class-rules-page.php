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

        echo '<div class="wrap secure-guard-ui">';
        echo '<h1>' . esc_html__('API Rules', 'secure-guard') . '</h1>';
        echo '<p class="description">' . esc_html__('Secure Guard enforces strict scanner-facing defaults with JWT-only REST access.', 'secure-guard') . '</p>';

        echo '<div class="card" style="max-width:1100px;padding:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('REST Policy', 'secure-guard') . '</h2>';
        echo '<ul style="margin-top:0;">';
        echo '<li>' . esc_html__('All REST requests require a valid JWT bearer token.', 'secure-guard') . '</li>';
        echo '<li>' . esc_html__('Cookie/session role bypass is disabled for REST.', 'secure-guard') . '</li>';
        echo '<li>' . esc_html__('Token endpoint allowlist, IP allowlist, and token-specific rate limits are enforced.', 'secure-guard') . '</li>';
        echo '<li>' . esc_html__('Sensitive endpoints (for example users/settings/plugins) require full_api_access when that rule is enabled.', 'secure-guard') . '</li>';
        echo '<li><code>/wp-json/wp/v2/posts</code> - ' . esc_html__('Allowed only with valid JWT and matching token policy.', 'secure-guard') . '</li>';
        echo '<li><code>/wp-json/wp/v2/users</code> - ' . esc_html__('Requires full_api_access scope when sensitive endpoint blocking is enabled.', 'secure-guard') . '</li>';
        echo '</ul>';
        echo '</div>';

        echo '<div class="card" style="max-width:1100px;padding:16px;margin-top:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('Scanner Defense Coverage', 'secure-guard') . '</h2>';
        echo '<ul style="margin-top:0;">';
        echo '<li>' . esc_html__('Blocks user enumeration via author query, author archive path, and direct users rest_route probes.', 'secure-guard') . '</li>';
        echo '<li>' . esc_html__('Blocks XML-RPC by filter and returns hard 403 for direct xmlrpc paths (`/xmlrpc.php`, `/wp/xmlrpc.php`) when enabled.', 'secure-guard') . '</li>';
        echo '<li>' . esc_html__('Blocks common fingerprint and exposure probes including Bedrock paths (`/wp/readme.html`, `/wp/license.txt`, `/app/debug.log`).', 'secure-guard') . '</li>';
        echo '<li>' . esc_html__('Blocks public external access to wp-cron paths (`/wp-cron.php`, `/wp/wp-cron.php`) while allowing internal execution.', 'secure-guard') . '</li>';
        echo '<li>' . esc_html__('Passive plugin/theme fingerprinting from public static assets still requires server/CDN controls.', 'secure-guard') . '</li>';
        echo '</ul>';
        echo '</div>';

        echo '<div class="card" style="max-width:1100px;padding:16px;margin-top:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('Usage & Verification', 'secure-guard') . '</h2>';
        echo '<p class="description">' . esc_html__('Replace SITE and TOKEN values. Without JWT expect 403; with valid JWT expect route-specific responses.', 'secure-guard') . '</p>';
        echo '<pre style="white-space:pre-wrap;">' . esc_html("# 1) Without token (expect 403)\ncurl -i https://SITE/wp-json/wp/v2/posts\n\n# 2) With token to non-sensitive route\ncurl -i -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/posts\n\n# 3) With token to sensitive route (requires full_api_access when enabled)\ncurl -i -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/users\n\n# 4) Legacy rest_route query format\ncurl -i -H \"Authorization: Bearer TOKEN\" \"https://SITE/?rest_route=/wp/v2/posts\"") . '</pre>';
        echo '</div>';
        echo '</div>';
    }
}
