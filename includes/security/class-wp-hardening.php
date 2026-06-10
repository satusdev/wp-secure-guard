<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_WP_Hardening {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;

    public function __construct(array $settings, Secure_Guard_Log_Repository $logs) {
        $this->settings = $settings;
        $this->logs = $logs;
    }

    public function register(): void {
        if (!empty($this->settings['hide_wp_info'])) {
            remove_action('wp_head', 'wp_generator');
            remove_action('admin_head', 'wp_generator');
            remove_action('wp_head', 'feed_links', 2);
            remove_action('wp_head', 'feed_links_extra', 3);
            remove_action('wp_head', 'rsd_link');
            remove_action('wp_head', 'wlwmanifest_link');
            remove_action('wp_head', 'wp_shortlink_wp_head', 10);
            remove_action('wp_head', 'rest_output_link_wp_head', 10);
            remove_action('template_redirect', 'rest_output_link_header', 11);
            remove_action('wp_head', 'wp_oembed_add_discovery_links');

            // Ensure .htaccess file contains the web server hardening rules
            if (!get_option('secure_guard_htaccess_hardened')) {
                self::write_htaccess_protection();
                update_option('secure_guard_htaccess_hardened', 1, false);
            }
        }

        if (!empty($this->settings['rest_strict_mode'])) {
            remove_action('wp_head', 'rest_output_link_wp_head', 10);
            remove_action('template_redirect', 'rest_output_link_header', 11);
        }

        if (!empty($this->settings['disable_emojis'])) {
            $this->disable_emojis();
        }

        if (!empty($this->settings['disable_oembeds'])) {
            $this->disable_oembeds();
        }

        if (!empty($this->settings['disable_file_editor']) && !defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }

        if (!empty($this->settings['hide_login_errors'])) {
            add_filter('login_errors', [$this, 'hide_login_errors_callback']);
        }

        if (!empty($this->settings['block_xmlrpc'])) {
            add_filter('xmlrpc_methods', [$this, 'disable_pingbacks']);
        }
    }

    public function hide_login_errors_callback(): string {
        return esc_html__('Error: Invalid login credentials.', 'secure-guard');
    }

    public function disable_pingbacks(array $methods): array {
        unset($methods['pingback.ping']);
        unset($methods['pingback.extensions.getPingbacks']);
        return $methods;
    }

    private function disable_emojis(): void {
        remove_action('wp_head', 'print_emoji_detection_script', 7);
        remove_action('admin_print_scripts', 'print_emoji_detection_script');
        remove_action('wp_print_styles', 'print_emoji_styles');
        remove_action('admin_print_styles', 'print_emoji_styles');
        remove_filter('the_content_feed', 'wp_staticize_emoji');
        remove_filter('comment_text_rss', 'wp_staticize_emoji');
        remove_filter('wp_mail', 'wp_staticize_emoji_for_email');
        add_filter('tiny_mce_plugins', function($plugins) {
            return is_array($plugins) ? array_diff($plugins, ['wpemoji']) : [];
        });
        add_filter('wp_resource_hints', function($urls, $relation_type) {
            if ('dns-prefetch' === $relation_type) {
                $emoji_svg_url = apply_filters('emoji_svg_url', 'https://s.w.org/images/core/emoji/14.0.0/svg/');
                $urls = array_diff($urls, [$emoji_svg_url]);
            }
            return $urls;
        }, 10, 2);
    }

    private function disable_oembeds(): void {
        remove_action('wp_head', 'wp_oembed_add_discovery_links');
        remove_action('wp_head', 'wp_oembed_add_host_js');
        add_filter('embed_oembed_discover', '__return_false');
        remove_filter('oembed_dataparse', 'wp_filter_oembed_result', 10);
    }

    public function hide_generator(string $generator): string {
        if (empty($this->settings['hide_wp_info'])) {
            return $generator;
        }

        return '';
    }

    public function strip_version_query_arg(string $src): string {
        if (empty($this->settings['hide_wp_info'])) {
            return $src;
        }

        return (string) remove_query_arg('ver', $src);
    }

    public function block_probe_files(): void {
        if (empty($this->settings['hide_wp_info'])) {
            return;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? ''));
        $path = strtolower((string) (parse_url($request_uri, PHP_URL_PATH) ?: ''));
        $exact = [
            '/readme.html',
            '/wp/readme.html',
            '/license.txt',
            '/wp/license.txt',
            '/wp-config.php',
            '/wp-config-sample.php',
            '/wp-content/debug.log',
            '/app/debug.log',
            '/phpinfo.php',
            '/info.php',
        ];

        $is_probe_path = in_array($path, $exact, true);
        if (!$is_probe_path && preg_match('#/(db|database|backup|dump)[^/]*\.(sql|zip|gz|tar|bz2)$#i', $path) === 1) {
            $is_probe_path = true;
        }

        // Catch debug.log and error_log at any installation path (standard, Bedrock, custom).
        if (!$is_probe_path && (str_ends_with($path, '/debug.log') || $path === '/debug.log'
            || str_ends_with($path, '/error_log') || $path === '/error_log')) {
            $is_probe_path = true;
        }

        // Catch XML-RPC at any path depth.
        if (!$is_probe_path && str_ends_with($path, '/xmlrpc.php')) {
            $is_probe_path = true;
        }

        if (!$is_probe_path) {
            return;
        }

        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $this->logs->log($path, $method, 'BLOCKED', 'WordPress fingerprint probe blocked', []);

        status_header(403);
        wp_die(esc_html__('Forbidden', 'secure-guard'), esc_html__('Forbidden', 'secure-guard'), ['response' => 403]);
    }

    public static function write_htaccess_protection(): void {
        $files = [
            Secure_Guard_Config::get_htaccess_path(),
            Secure_Guard_Config::get_root_htaccess_path(),
        ];

        $rules = [
            '# BEGIN Secure Guard - Web Server Hardening',
            '<FilesMatch "\.(log|ini|sh|bak|conf)$">',
            '    <IfModule mod_authz_core.c>',
            '        Require all denied',
            '    </IfModule>',
            '    <IfModule !mod_authz_core.c>',
            '        Order deny,allow',
            '        Deny from all',
            '    </IfModule>',
            '</FilesMatch>',
            '<FilesMatch "^(readme\.html|license\.txt|install\.php|upgrade\.php)$">',
            '    <IfModule mod_authz_core.c>',
            '        Require all denied',
            '    </IfModule>',
            '    <IfModule !mod_authz_core.c>',
            '        Order deny,allow',
            '        Deny from all',
            '    </IfModule>',
            '</FilesMatch>',
            '# END Secure Guard - Web Server Hardening'
        ];

        $rules_str = implode("\n", $rules) . "\n";

        foreach ($files as $file) {
            $dir = dirname($file);
            if (!is_dir($dir)) {
                continue;
            }

            if (file_exists($file)) {
                $content = @file_get_contents($file);
                if ($content === false) {
                    continue;
                }

                // Remove old block if present to avoid duplicates
                $content = preg_replace('/# BEGIN Secure Guard - Protect Log Files.*?# END Secure Guard - Protect Log Files\s*/s', '', $content);

                if (strpos($content, 'BEGIN Secure Guard - Web Server Hardening') === false) {
                    // Prepend new rules to avoid interfering with existing ones
                    @file_put_contents($file, $rules_str . "\n" . $content);
                }
            } else {
                @file_put_contents($file, $rules_str);
            }
        }
    }
}
