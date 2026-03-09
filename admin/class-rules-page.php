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
        echo '<p class="description">' . esc_html__('MVP uses secure defaults and token-level endpoint/IP restrictions from the Tokens page.', 'secure-guard') . '</p>';

        echo '<div class="card" style="max-width:1100px;padding:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('Sensitive Route Policy', 'secure-guard') . '</h2>';
        echo '<ul style="margin-top:0;">';
        echo '<li><code>/wp/v2/users</code> - ' . esc_html__('Blocked unless admin role or full_api_access token scope.', 'secure-guard') . '</li>';
        echo '<li><code>/wp/v2/users/me</code> - ' . esc_html__('Blocked unless admin role or full_api_access token scope.', 'secure-guard') . '</li>';
        echo '<li><code>/wp/v2/settings</code> - ' . esc_html__('Blocked unless admin role or full_api_access token scope.', 'secure-guard') . '</li>';
        echo '<li><code>/wp/v2/plugins</code> - ' . esc_html__('Blocked unless admin role or full_api_access token scope.', 'secure-guard') . '</li>';
        echo '</ul>';
        echo '</div>';

        echo '<div class="card" style="max-width:1100px;padding:16px;margin-top:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('Usage & Verification', 'secure-guard') . '</h2>';
        echo '<p class="description">' . esc_html__('Replace SITE and TOKEN values. Results depend on whether the endpoint exists in WordPress and token policy allows it.', 'secure-guard') . '</p>';
        echo '<pre style="white-space:pre-wrap;">' . esc_html("# 1) Without token (expect 403 when REST lock is enabled)\ncurl https://SITE/wp-json/wp/v2/posts\n\n# 2) With token to existing route (expect 200 or route-specific response)\ncurl -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/posts\n\n# 3) With token to sensitive route (requires full_api_access scope)\ncurl -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v2/users\n\n# 4) With token to missing route (expect WordPress 404 rest_no_route)\ncurl -H \"Authorization: Bearer TOKEN\" https://SITE/wp-json/wp/v99/does-not-exist") . '</pre>';
        echo '</div>';
        echo '</div>';
    }
}
