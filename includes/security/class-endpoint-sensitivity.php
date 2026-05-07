<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Endpoint_Sensitivity {
    private array $settings;

    private const ROUTE_MAP = [
        '/wp/v2/users'      => ['weight' => 10, 'tier' => 'ultra_strict'],
        '/wp/v2/settings'   => ['weight' => 10, 'tier' => 'ultra_strict'],
        '/wp/v2/plugins'    => ['weight' => 10, 'tier' => 'ultra_strict'],
        '/wp/v2/themes'     => ['weight' => 10, 'tier' => 'ultra_strict'],
        '/wp-login.php'     => ['weight' => 20, 'tier' => 'ultra_strict'],
        '/wp-json/wp/v2/posts' => ['weight' => 1,  'tier' => 'lenient'],
        '/wp-json'          => ['weight' => 2,  'tier' => 'normal'],
    ];

    public function __construct(array $settings) {
        $this->settings = $settings;
    }

    public function get_weight(string $route): int {
        if (empty($this->settings['endpoint_sensitivity_enabled'])) {
            return 1;
        }

        foreach (self::ROUTE_MAP as $pattern => $data) {
            if ($route === $pattern || str_starts_with($route, $pattern . '/')) {
                return $data['weight'];
            }
        }

        return 1;
    }

    public function get_tier(string $route): string {
        foreach (self::ROUTE_MAP as $pattern => $data) {
            if ($route === $pattern || str_starts_with($route, $pattern . '/')) {
                return $data['tier'];
            }
        }

        return 'normal';
    }

    public function get_limit_multiplier(string $route): float {
        $tier = $this->get_tier($route);
        
        switch ($tier) {
            case 'ultra_strict':
                return 0.1; // 10% of normal limit
            case 'strict':
                return 0.5; // 50%
            case 'lenient':
                return 2.0; // 200%
            default:
                return 1.0;
        }
    }
}
