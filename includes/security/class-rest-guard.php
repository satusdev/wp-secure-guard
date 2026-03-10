<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_REST_Guard {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;
    private Secure_Guard_Token_Manager $token_manager;
    private Secure_Guard_IP_Whitelist $ip_whitelist;
    private Secure_Guard_Rate_Limit $rate_limit;
    private Secure_Guard_Endpoint_Blocker $endpoint_blocker;

    public function __construct(
        array $settings,
        Secure_Guard_Log_Repository $logs,
        Secure_Guard_Token_Manager $token_manager,
        Secure_Guard_IP_Whitelist $ip_whitelist,
        Secure_Guard_Rate_Limit $rate_limit,
        Secure_Guard_Endpoint_Blocker $endpoint_blocker
    ) {
        $this->settings = $settings;
        $this->logs = $logs;
        $this->token_manager = $token_manager;
        $this->ip_whitelist = $ip_whitelist;
        $this->rate_limit = $rate_limit;
        $this->endpoint_blocker = $endpoint_blocker;
    }

    public function authenticate($result) {
        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $route = $this->extract_route($request_uri);
        $ip = $this->ip_whitelist->get_request_ip();

        if (!$this->is_rest_request($request_uri, $route)) {
            return $result;
        }

        $this->logs->log($route, $method, 'BLOCKED', 'REST API fully disabled by policy', ['ip' => $ip]);

        return new WP_Error('secure_guard_rest_disabled', __('REST API is disabled by security policy.', 'secure-guard'), ['status' => 403]);
    }

    public function pre_dispatch($response, WP_REST_Server $server, WP_REST_Request $request) {
        $route = (string) $request->get_route();
        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? ''));
        $method = sanitize_text_field((string) $request->get_method());
        $ip = $this->ip_whitelist->get_request_ip();

        if (!$this->is_rest_request($request_uri, $route)) {
            return $response;
        }

        $this->logs->log($route === '' ? $request_uri : $route, $method, 'BLOCKED', 'REST pre-dispatch blocked by policy', ['ip' => $ip]);

        return new WP_Error('secure_guard_rest_disabled', __('REST API is disabled by security policy.', 'secure-guard'), ['status' => 403]);
    }

    private function is_rest_request(string $request_uri, string $route): bool {
        if ($route !== '') {
            return true;
        }

        if (str_contains($request_uri, '/wp-json')) {
            return true;
        }

        if (str_contains($request_uri, 'rest_route=')) {
            return true;
        }

        return false;
    }

    private function extract_route(string $request_uri): string {
        $parts = parse_url($request_uri);
        $path = isset($parts['path']) ? (string) $parts['path'] : '';
        $query = isset($parts['query']) ? (string) $parts['query'] : '';

        if ($query !== '') {
            $query_params = [];
            parse_str($query, $query_params);
            if (isset($query_params['rest_route'])) {
                $rest_route = trim((string) $query_params['rest_route']);
                if ($rest_route !== '') {
                    return str_starts_with($rest_route, '/') ? $rest_route : '/' . $rest_route;
                }
            }
        }

        $wp_json_pos = strpos($path, '/wp-json');
        if ($wp_json_pos !== false) {
            $route = substr($path, $wp_json_pos + strlen('/wp-json'));
            return $route === '' ? '/' : $route;
        }

        return $path;
    }

}
