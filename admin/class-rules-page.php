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
        echo '<p class="description">' . esc_html__('Secure Guard enforces strict scanner-facing defaults. REST API is force-disabled for every route and method.', 'secure-guard') . '</p>';

        echo '<div class="card" style="max-width:1100px;padding:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('REST Policy', 'secure-guard') . '</h2>';
        echo '<ul style="margin-top:0;">';
        echo '<li>' . esc_html__('All REST namespaces and routes are blocked for all clients.', 'secure-guard') . '</li>';
        echo '<li>' . esc_html__('All HTTP methods are blocked: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD.', 'secure-guard') . '</li>';
        echo '<li>' . esc_html__('No JWT, cookie role, or token scope exceptions are applied while this policy is active.', 'secure-guard') . '</li>';
        echo '<li><code>/wp-json</code> - ' . esc_html__('Blocked.', 'secure-guard') . '</li>';
        echo '<li><code>/wp-json/wp/v2/users</code> - ' . esc_html__('Blocked.', 'secure-guard') . '</li>';
        echo '<li><code>?rest_route=/wp/v2/posts</code> - ' . esc_html__('Blocked.', 'secure-guard') . '</li>';
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
        echo '<p class="description">' . esc_html__('Replace SITE. Every command should return HTTP 403 from plugin policy.', 'secure-guard') . '</p>';
        echo '<pre style="white-space:pre-wrap;">' . esc_html("# 1) REST index\ncurl -i https://SITE/wp-json/\n\n# 2) Users endpoint\ncurl -i https://SITE/wp-json/wp/v2/users\n\n# 3) Methods are blocked too\ncurl -i -X POST https://SITE/wp-json/wp/v2/posts\ncurl -i -X PUT https://SITE/wp-json/wp/v2/posts/1\ncurl -i -X DELETE https://SITE/wp-json/wp/v2/posts/1\n\n# 4) Legacy rest_route query format\ncurl -i \"https://SITE/?rest_route=/wp/v2/posts\"") . '</pre>';
        echo '</div>';
        echo '</div>';
    }
}
