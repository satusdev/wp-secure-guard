<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Endpoint_Blocker {
    private array $settings;
    private array $blocked_routes = [
        '/wp/v2/users',
        '/wp/v2/users/me',
        '/wp/v2/settings',
        '/wp/v2/plugins',
    ];

    public function __construct(array $settings) {
        $this->settings = $settings;
    }

    public function is_sensitive_route(string $route): bool {
        foreach ($this->blocked_routes as $blocked) {
            if ($route === $blocked || str_starts_with($route, $blocked . '/')) {
                return true;
            }
        }

        return false;
    }

    public function is_protected_path_request(string $uri): bool {
        $path = strtolower((string) (parse_url($uri, PHP_URL_PATH) ?: ''));
        if ($path === '') {
            return false;
        }

        $exact_paths = [
            '/wp-config.php',
            '/wp-config-sample.php',
            '/.env',
            '/.git',
            '/wp-content/debug.log',
            '/app/debug.log',
            '/xmlrpc.php',
            '/wp/xmlrpc.php',
            '/wp-cron.php',
            '/wp/wp-cron.php',
            '/readme.html',
            '/wp/readme.html',
            '/license.txt',
            '/wp/license.txt',
            '/phpinfo.php',
            '/info.php',
        ];

        foreach ($exact_paths as $blocked_path) {
            if ($path === $blocked_path || str_starts_with($path, $blocked_path . '/')) {
                return true;
            }
        }

        if (preg_match('#/(db|database|backup|dump)[^/]*\.(sql|zip|gz|tar|bz2)$#i', $path) === 1) {
            return true;
        }

        return false;
    }

    public function should_block_sensitive_endpoints(): bool {
        return !empty($this->settings['block_sensitive_endpoints']);
    }
}
