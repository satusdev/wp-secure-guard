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
        $app_rules = [
            '# BEGIN Secure Guard - App Hardening',
            '# Protect sensitive files in app directory',
            '<FilesMatch "\.(log|ini|sh|bak|conf|sql|env)$">',
            '    <IfModule mod_authz_core.c>',
            '        Require all denied',
            '    </IfModule>',
            '    <IfModule !mod_authz_core.c>',
            '        Order deny,allow',
            '        Deny from all',
            '    </IfModule>',
            '</FilesMatch>',
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
        
        $paths_to_test = [
            'readme.html' => '/readme.html',
            'license.txt' => '/license.txt',
            'debug.log'   => '/app/debug.log',
        ];

        // Bedrock check
        $is_bedrock = str_ends_with(rtrim(str_replace('\\', '/', ABSPATH), '/'), '/wp') || 
                      file_exists(dirname(ABSPATH) . '/config/application.php');
        if (!$is_bedrock) {
            $paths_to_test['debug.log'] = '/wp-content/debug.log';
        }

        foreach ($paths_to_test as $name => $path) {
            $url = rtrim($site_url, '/') . $path;
            
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
                ];
                continue;
            }

            $code = wp_remote_retrieve_response_code($response);
            
            if ($code === 200) {
                $results[$name] = [
                    'status' => 'exposed',
                    'code'   => $code,
                    'msg'    => __('Exposed! File is publicly downloadable.', 'wp-secure-guard'),
                ];
            } elseif ($code >= 400) {
                $results[$name] = [
                    'status' => 'protected',
                    'code'   => $code,
                    'msg'    => sprintf(__('Protected (Returned %d)', 'wp-secure-guard'), $code),
                ];
            } else {
                $results[$name] = [
                    'status' => 'unknown',
                    'code'   => $code,
                    'msg'    => sprintf(__('Unsure (Returned %d)', 'wp-secure-guard'), $code),
                ];
            }
        }

        return $results;
    }
}
