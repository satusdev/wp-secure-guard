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
        $this->maybe_relocate_debug_log();
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
        return esc_html__('Error: Invalid login credentials.', 'wp-secure-guard');
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
        wp_die(esc_html__('Forbidden', 'wp-secure-guard'), esc_html__('Forbidden', 'wp-secure-guard'), ['response' => 403]);
    }

    private function maybe_relocate_debug_log(): void {
        $default_debug_log = WP_CONTENT_DIR . '/debug.log';

        if (empty($this->settings['hide_wp_info'])) {
            $secure_path = get_option('secure_guard_resolved_debug_log_path');
            if (!empty($secure_path)) {
                if (file_exists($secure_path)) {
                    if (@rename($secure_path, $default_debug_log) === false) {
                        if (@copy($secure_path, $default_debug_log)) {
                            @unlink($secure_path);
                        }
                    }
                }
                delete_option('secure_guard_resolved_debug_log_path');
            }
            return;
        }

        if (!defined('WP_DEBUG_LOG') || !WP_DEBUG_LOG) {
            return;
        }

        $current_log = ini_get('error_log');
        if (empty($current_log)) {
            $current_log = $default_debug_log;
        }

        // Check if the current log is the default public debug.log path
        $is_default = (realpath($current_log) === realpath($default_debug_log)) || 
                      (strtolower(basename($current_log)) === 'debug.log' && 
                       (str_contains(str_replace('\\', '/', $current_log), '/wp-content/') || 
                        str_contains(str_replace('\\', '/', $current_log), '/app/')));

        if (!$is_default) {
            return;
        }

        $secure_path = get_option('secure_guard_resolved_debug_log_path');

        if (empty($secure_path)) {
            $target_dir = '';

            // Check if Bedrock setup
            $is_bedrock = str_ends_with(rtrim(str_replace('\\', '/', ABSPATH), '/'), '/wp') || 
                          file_exists(dirname(ABSPATH) . '/config/application.php');

            if ($is_bedrock) {
                $project_root = dirname(dirname(ABSPATH));
                // Try Bedrock specific paths
                $bedrock_paths = [
                    $project_root . '/storage/logs',
                    $project_root . '/var/log',
                    $project_root
                ];
                foreach ($bedrock_paths as $dir) {
                    if (!is_dir($dir)) {
                        @wp_mkdir_p($dir);
                    }
                    if (is_dir($dir) && is_writable($dir)) {
                        $target_dir = $dir;
                        break;
                    }
                }
            } else {
                // Standard WordPress: try one level above web root
                $parent_dir = dirname(ABSPATH);
                if (is_writable($parent_dir)) {
                    $target_dir = $parent_dir;
                }
            }

            if (!empty($target_dir)) {
                $secure_path = rtrim($target_dir, '/\\') . '/debug.log';
            } else {
                // Fallback: randomized filename in the current directory to prevent guessing
                $secure_path = WP_CONTENT_DIR . '/debug-' . substr(hash('sha256', SECURE_GUARD_FILE), 0, 16) . '.log';
            }

            // Move existing public debug.log to the secure path if it exists
            if (file_exists($default_debug_log)) {
                if (@rename($default_debug_log, $secure_path) === false) {
                    if (@copy($default_debug_log, $secure_path)) {
                        @unlink($default_debug_log);
                    }
                }
            }

            update_option('secure_guard_resolved_debug_log_path', $secure_path, false);
        }

        if (!empty($secure_path)) {
            @ini_set('error_log', $secure_path);
        }
    }

    public static function write_htaccess_protection(): void {
        $settings = Secure_Guard_Config::get_settings();
        
        // 1. Root .htaccess / /web/.htaccess rules
        $root_htaccess = Secure_Guard_Config::get_root_htaccess_path();
        $root_rules = [
            '# BEGIN Secure Guard - Root Hardening',
            '# Protect sensitive files',
            '<FilesMatch "\.(log|ini|sh|bak|conf|sql|env)$">',
            '    <IfModule mod_authz_core.c>',
            '        Require all denied',
            '    </IfModule>',
            '    <IfModule !mod_authz_core.c>',
            '        Order deny,allow',
            '        Deny from all',
            '    </IfModule>',
            '</FilesMatch>',
            '',
            '# Block readme, license, install, upgrade files',
            '<FilesMatch "^(readme\.html|license\.txt|install\.php|upgrade\.php)$">',
            '    <IfModule mod_authz_core.c>',
            '        Require all denied',
            '    </IfModule>',
            '    <IfModule !mod_authz_core.c>',
            '        Order deny,allow',
            '        Deny from all',
            '    </IfModule>',
            '</FilesMatch>'
        ];

        // Bedrock check
        $is_bedrock = str_ends_with(rtrim(str_replace('\\', '/', ABSPATH), '/'), '/wp') || 
                      file_exists(dirname(ABSPATH) . '/config/application.php');
        if ($is_bedrock) {
            $root_rules[] = '';
            $root_rules[] = '# Bedrock directory protection';
            $root_rules[] = '<IfModule mod_rewrite.c>';
            $root_rules[] = '    RewriteEngine On';
            $root_rules[] = '    RewriteRule ^(config|vendor|\.env) - [F,L]';
            $root_rules[] = '</IfModule>';

            // Write local .htaccess to Bedrock directories directly
            $project_root = dirname(dirname(ABSPATH));
            $dirs_to_protect = [
                $project_root . '/config',
                $project_root . '/vendor'
            ];
            foreach ($dirs_to_protect as $dir) {
                if (is_dir($dir) && is_writable($dir)) {
                    $local_htaccess = $dir . '/.htaccess';
                    $local_rules = [
                        '# BEGIN Secure Guard - Local Block',
                        '<IfModule mod_authz_core.c>',
                        '    Require all denied',
                        '</IfModule>',
                        '<IfModule !mod_authz_core.c>',
                        '    Order deny,allow',
                        '    Deny from all',
                        '</IfModule>',
                        '# END Secure Guard - Local Block'
                    ];
                    self::write_to_htaccess($local_htaccess, implode("\n", $local_rules));
                }
            }
        }

        if (!empty($settings['block_xmlrpc'])) {
            $root_rules[] = '';
            $root_rules[] = '# Block XML-RPC';
            $root_rules[] = '<Files xmlrpc.php>';
            $root_rules[] = '    <IfModule mod_authz_core.c>';
            $root_rules[] = '        Require all denied';
            $root_rules[] = '    </IfModule>';
            $root_rules[] = '    <IfModule !mod_authz_core.c>';
            $root_rules[] = '        Order deny,allow';
            $root_rules[] = '        Deny from all';
            $root_rules[] = '    </IfModule>';
            $root_rules[] = '</Files>';
        }

        if (!empty($settings['block_public_wp_cron'])) {
            $root_rules[] = '';
            $root_rules[] = '# Block Public WP-Cron';
            $root_rules[] = '<Files wp-cron.php>';
            $root_rules[] = '    <IfModule mod_authz_core.c>';
            $root_rules[] = '        Require all denied';
            $root_rules[] = '    </IfModule>';
            $root_rules[] = '    <IfModule !mod_authz_core.c>';
            $root_rules[] = '        Order deny,allow';
            $root_rules[] = '        Deny from all';
            $root_rules[] = '    </IfModule>';
            $root_rules[] = '</Files>';
        }

        $root_rules[] = '# END Secure Guard - Root Hardening';
        self::write_to_htaccess($root_htaccess, implode("\n", $root_rules));

        // 2. App / wp-content .htaccess rules
        $app_htaccess = Secure_Guard_Config::get_htaccess_path();
        $app_deny_rules = [
            '    <IfModule mod_authz_core.c>',
            '        Require all denied',
            '    </IfModule>',
            '    <IfModule !mod_authz_core.c>',
            '        Order deny,allow',
            '        Deny from all',
            '    </IfModule>',
        ];
        $app_rules = [
            '# BEGIN Secure Guard - App Hardening',
            '# Protect sensitive and executable files in app/wp-content',
            'Options -Indexes',
            '<FilesMatch "^\.">',
            ...$app_deny_rules,
            '</FilesMatch>',
            '<FilesMatch "\.(php|php3|php4|php5|phtml|phar|pl|py|jsp|asp|aspx|cgi|sh|log|ini|conf|bak|sql|env|gz|tar|zip)$">',
            ...$app_deny_rules,
            '</FilesMatch>',
            '<FilesMatch "^(composer\.(json|lock)|package\.json|yarn\.lock|pnpm-lock\.yaml|\.htpasswd)$">',
            ...$app_deny_rules,
            '</FilesMatch>',
            '<IfModule mod_rewrite.c>',
            '    RewriteEngine On',
            '    RewriteCond %{REQUEST_FILENAME} -f',
            '    RewriteCond %{REQUEST_URI} !\.(css|js|mjs|map|json|jpg|jpeg|png|gif|webp|svg|ico|woff|woff2|ttf|eot|otf|pdf|txt|xml|mp4|webm|mp3|wav|avif)$ [NC]',
            '    RewriteRule ^ - [F,L]',
            '</IfModule>',
            '# END Secure Guard - App Hardening'
        ];
        self::write_to_htaccess($app_htaccess, implode("\n", $app_rules));

        // Create empty index.php files if missing to prevent index listing safely
        $app_dir = dirname($app_htaccess);
        if (is_dir($app_dir) && is_writable($app_dir)) {
            if (!file_exists($app_dir . '/index.php') && !file_exists($app_dir . '/index.html')) {
                @file_put_contents($app_dir . '/index.php', "<?php\n// Silence is golden.\n");
            }
        }

        // 3. Uploads directory .htaccess rules (Disable PHP execution)
        $upload_dir_info = wp_upload_dir();
        if (empty($upload_dir_info['error'])) {
            $uploads_htaccess = rtrim($upload_dir_info['basedir'], '/\\') . '/.htaccess';
            $uploads_rules = [
                '# BEGIN Secure Guard - Uploads Hardening',
                '# Disable PHP execution in uploads directory',
                '<FilesMatch "\.(php|php3|php4|php5|phtml|pl|py|jsp|asp|htm|html|shtml|sh|cgi)$">',
                '    <IfModule mod_authz_core.c>',
                '        Require all denied',
                '    </IfModule>',
                '    <IfModule !mod_authz_core.c>',
                '        Order deny,allow',
                '        Deny from all',
                '    </IfModule>',
                '</FilesMatch>',
                '# END Secure Guard - Uploads Hardening'
            ];
            self::write_to_htaccess($uploads_htaccess, implode("\n", $uploads_rules));

            $uploads_dir = dirname($uploads_htaccess);
            if (is_dir($uploads_dir) && is_writable($uploads_dir)) {
                if (!file_exists($uploads_dir . '/index.php') && !file_exists($uploads_dir . '/index.html')) {
                    @file_put_contents($uploads_dir . '/index.php', "<?php\n// Silence is golden.\n");
                }
            }
        }
    }

    private static function write_to_htaccess(string $file, string $rules_str): void {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            return;
        }

        if (file_exists($file)) {
            $content = @file_get_contents($file);
            if ($content === false) {
                return;
            }

            // Remove legacy block names if present
            $content = preg_replace('/# BEGIN Secure Guard - Protect Log Files.*?# END Secure Guard - Protect Log Files\s*/s', '', $content);
            $content = preg_replace('/# BEGIN Secure Guard - Web Server Hardening.*?# END Secure Guard - Web Server Hardening\s*/s', '', $content);

            // Extract the block name from the first line
            preg_match('/^(# BEGIN Secure Guard - [A-Za-z ]+)/', $rules_str, $matches);
            $block_name = $matches[1] ?? '';
            $end_block_name = str_replace('BEGIN', 'END', $block_name);

            if ($block_name !== '') {
                // Remove existing block of this name to avoid duplicate/stale rules
                $pattern = '/' . preg_quote($block_name, '/') . '.*?' . preg_quote($end_block_name, '/') . '\s*/s';
                $content = preg_replace($pattern, '', $content);
            }

            // Prepend new rules to avoid interfering with existing ones
            @file_put_contents($file, $rules_str . "\n\n" . trim($content));
        } else {
            @file_put_contents($file, $rules_str);
        }
    }

    public static function remove_htaccess_protection(): void {
        $files = [
            Secure_Guard_Config::get_root_htaccess_path(),
            Secure_Guard_Config::get_htaccess_path(),
        ];
        
        $upload_dir_info = wp_upload_dir();
        if (empty($upload_dir_info['error'])) {
            $files[] = rtrim($upload_dir_info['basedir'], '/\\') . '/.htaccess';
        }

        // Bedrock check
        $is_bedrock = str_ends_with(rtrim(str_replace('\\', '/', ABSPATH), '/'), '/wp') || 
                      file_exists(dirname(ABSPATH) . '/config/application.php');
        if ($is_bedrock) {
            $project_root = dirname(dirname(ABSPATH));
            $files[] = $project_root . '/config/.htaccess';
            $files[] = $project_root . '/vendor/.htaccess';
        }

        foreach ($files as $file) {
            if (!file_exists($file)) {
                continue;
            }

            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            // Remove all Secure Guard blocks
            $content = preg_replace('/# BEGIN Secure Guard - Protect Log Files.*?# END Secure Guard - Protect Log Files\s*/s', '', $content);
            $content = preg_replace('/# BEGIN Secure Guard - Web Server Hardening.*?# END Secure Guard - Web Server Hardening\s*/s', '', $content);
            $content = preg_replace('/# BEGIN Secure Guard - Root Hardening.*?# END Secure Guard - Root Hardening\s*/s', '', $content);
            $content = preg_replace('/# BEGIN Secure Guard - App Hardening.*?# END Secure Guard - App Hardening\s*/s', '', $content);
            $content = preg_replace('/# BEGIN Secure Guard - Uploads Hardening.*?# END Secure Guard - Uploads Hardening\s*/s', '', $content);
            $content = preg_replace('/# BEGIN Secure Guard - Local Block.*?# END Secure Guard - Local Block\s*/s', '', $content);

            $content = trim($content);
            if (empty($content)) {
                @unlink($file);
            } else {
                @file_put_contents($file, $content);
            }
        }
    }

    public static function test_exposure_status(): array {
        $results = [];
        $site_url = site_url();
        
        // Bedrock check
        $is_bedrock = str_ends_with(rtrim(str_replace('\\', '/', ABSPATH), '/'), '/wp') || 
                      file_exists(dirname(ABSPATH) . '/config/application.php');

        $paths_to_test = [
            'readme.html' => [
                'path' => '/readme.html',
                'label' => __('WordPress readme', 'wp-secure-guard'),
            ],
            'license.txt' => [
                'path' => '/license.txt',
                'label' => __('WordPress license', 'wp-secure-guard'),
            ],
            'debug.log' => [
                'path' => $is_bedrock ? '/app/debug.log' : '/wp-content/debug.log',
                'label' => __('Debug log', 'wp-secure-guard'),
            ],
            'error_log' => [
                'path' => $is_bedrock ? '/app/error_log' : '/wp-content/error_log',
                'label' => __('Error log', 'wp-secure-guard'),
            ],
            'app_env' => [
                'path' => $is_bedrock ? '/app/.env' : '/wp-content/.env',
                'label' => __('App .env', 'wp-secure-guard'),
            ],
            'app_composer' => [
                'path' => $is_bedrock ? '/app/composer.json' : '/wp-content/composer.json',
                'label' => __('App composer.json', 'wp-secure-guard'),
            ],
            'app_unknown_path' => [
                'path' => $is_bedrock ? '/app/dsd' : '/wp-content/dsd',
                'label' => __('Unknown app file', 'wp-secure-guard'),
            ],
        ];

        foreach ($paths_to_test as $name => $test) {
            $url = rtrim($site_url, '/') . $test['path'];
            
            // Perform local/external HTTP request
            $response = wp_remote_get($url, [
                'timeout'     => 3,
                'redirection' => 0,
                'sslverify'   => false,
            ]);

            if (is_wp_error($response)) {
                $results[$name] = [
                    'status' => 'unknown',
                    'code'   => 0,
                    'msg'    => $response->get_error_message(),
                    'label'  => $test['label'],
                    'path'   => $test['path'],
                ];
                continue;
            }

            $code = wp_remote_retrieve_response_code($response);
            
            if ($code === 200) {
                $results[$name] = [
                    'status' => 'exposed',
                    'code'   => $code,
                    'msg'    => __('Exposed! File is publicly downloadable.', 'wp-secure-guard'),
                    'label'  => $test['label'],
                    'path'   => $test['path'],
                ];
            } elseif ($code >= 400) {
                $results[$name] = [
                    'status' => 'protected',
                    'code'   => $code,
                    'msg'    => sprintf(__('Protected (Returned %d)', 'wp-secure-guard'), $code),
                    'label'  => $test['label'],
                    'path'   => $test['path'],
                ];
            } else {
                $results[$name] = [
                    'status' => 'unknown',
                    'code'   => $code,
                    'msg'    => sprintf(__('Unsure (Returned %d)', 'wp-secure-guard'), $code),
                    'label'  => $test['label'],
                    'path'   => $test['path'],
                ];
            }
        }

        return $results;
    }
}
