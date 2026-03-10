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
        $token = $this->token_manager->extract_bearer_token();
        $token_row = null;

        if (!$this->is_rest_request($request_uri, $route)) {
            return $result;
        }

        if ($result instanceof WP_Error) {
            return $result;
        }

        $token_row = $this->token_manager->validate_token($token);
        if (!$token_row) {
            $this->logs->log($route, $method, 'BLOCKED', 'Missing or invalid JWT token', ['ip' => $ip]);
            return new WP_Error('secure_guard_invalid_token', __('REST API requires a valid JWT token.', 'secure-guard'), ['status' => 403]);
        }

        if ($this->endpoint_blocker->should_block_sensitive_endpoints() && $this->endpoint_blocker->is_sensitive_route($route)) {
            $is_admin_scope = in_array('full_api_access', $this->token_manager->get_token_scopes($token_row), true);
            if (!$is_admin_scope) {
                $this->logs->log($route, $method, 'BLOCKED', 'Sensitive endpoint blocked for JWT scope', ['token_id' => $token_row['id'] ?? 0, 'ip' => $ip]);
                return new WP_Error('secure_guard_sensitive_blocked', __('Endpoint blocked.', 'secure-guard'), ['status' => 403]);
            }
        }

        if (!$this->token_manager->route_allowed($token_row, $route)) {
            $this->logs->log($route, $method, 'BLOCKED', 'Route not allowed for token', ['token_id' => $token_row['id'] ?? 0, 'ip' => $ip]);
            return new WP_Error('secure_guard_route_forbidden', __('Token is not allowed for this endpoint.', 'secure-guard'), ['status' => 403]);
        }

        if (!$this->ip_whitelist->is_allowed($ip, (string) ($token_row['allowed_ips'] ?? ''))) {
            $this->logs->log($route, $method, 'BLOCKED', 'IP not allowed', ['token_id' => $token_row['id'] ?? 0, 'ip' => $ip]);
            return new WP_Error('secure_guard_ip_forbidden', __('IP is not allowed.', 'secure-guard'), ['status' => 403]);
        }

        $subject = 'token:' . (int) ($token_row['id'] ?? 0);
        $token_limit = isset($token_row['rate_limit_per_minute']) ? (int) $token_row['rate_limit_per_minute'] : null;
        if (!$this->rate_limit->allow($subject, $token_limit)) {
            $this->logs->log($route, $method, 'BLOCKED', 'Rate limit exceeded', ['token_id' => $token_row['id'] ?? 0, 'ip' => $ip]);
            return new WP_Error('secure_guard_rate_limit', __('Rate limit exceeded.', 'secure-guard'), ['status' => 429]);
        }

        $this->logs->log($route, $method, 'ALLOWED', 'JWT API request allowed', ['token_id' => $token_row['id'] ?? 0, 'ip' => $ip]);

        return $result;
    }

    public function pre_dispatch($response, WP_REST_Server $server, WP_REST_Request $request) {
        $route = (string) $request->get_route();
        if ($route === '') {
            return $response;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? ''));
        $method = sanitize_text_field((string) $request->get_method());

        if ($this->endpoint_blocker->is_protected_path_request($request_uri)) {
            $this->logs->log($request_uri, $method, 'BLOCKED', 'Protected path request', []);
            return new WP_Error('secure_guard_path_blocked', __('Forbidden.', 'secure-guard'), ['status' => 403]);
        }

        return $response;
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
