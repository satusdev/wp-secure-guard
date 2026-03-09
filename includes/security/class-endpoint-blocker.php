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
        $sensitive = ['wp-config.php', '/.env', '/.git', '/wp-content/debug.log', '/xmlrpc.php'];
        foreach ($sensitive as $needle) {
            if (stripos($uri, $needle) !== false) {
                return true;
            }
        }

        return false;
    }

    public function should_block_sensitive_endpoints(): bool {
        return !empty($this->settings['block_sensitive_endpoints']);
    }
}
