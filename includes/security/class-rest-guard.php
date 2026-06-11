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
    private Secure_Guard_Reputation_Engine $reputation_engine;
    private Secure_Guard_Endpoint_Sensitivity $sensitivity;
    private Secure_Guard_Lock_State $lock_state;

    public function __construct(
        array $settings,
        Secure_Guard_Log_Repository $logs,
        Secure_Guard_Token_Manager $token_manager,
        Secure_Guard_IP_Whitelist $ip_whitelist,
        Secure_Guard_Rate_Limit $rate_limit,
        Secure_Guard_Endpoint_Blocker $endpoint_blocker,
        Secure_Guard_Reputation_Engine $reputation_engine,
        Secure_Guard_Endpoint_Sensitivity $sensitivity,
        Secure_Guard_Lock_State $lock_state
    ) {
        $this->settings = $settings;
        $this->logs = $logs;
        $this->token_manager = $token_manager;
        $this->ip_whitelist = $ip_whitelist;
        $this->rate_limit = $rate_limit;
        $this->endpoint_blocker = $endpoint_blocker;
        $this->reputation_engine = $reputation_engine;
        $this->sensitivity = $sensitivity;
        $this->lock_state = $lock_state;
    }

    public function authenticate($result) {
        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $route = $this->extract_route($request_uri);
        $ip = $this->ip_whitelist->get_request_ip();
        $ua = sanitize_text_field((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''));
        $token = $this->token_manager->extract_bearer_token();
        $token_row = null;

        if (!$this->is_rest_request($request_uri, $route)) {
            return $result;
        }

        if ($result instanceof WP_Error) {
            return $result;
        }

        // Reputation check - Block if IP is in BLOCKED tier
        if ($this->reputation_engine->get_tier($ip) === Secure_Guard_Reputation_Engine::TIER_BLOCKED) {
            $this->logs->log($route, $method, 'BLOCKED', 'IP blocked by reputation', ['ip' => $ip]);
            return new WP_Error('secure_guard_reputation_blocked', __('Access denied by security engine.', 'wp-secure-guard'), ['status' => 403]);
        }

        // Logged-in browser sessions use WP cookie auth — bypass JWT enforcement
        if (is_user_logged_in()) {
            return $result;
        }

        // Bypass JWT check for whitelisted plugin namespaces
        if ($this->is_namespace_allowed($route)) {
            return $result;
        }

        $token_row = $this->token_manager->validate_token($token);
        if (!$token_row) {
            $this->reputation_engine->add_score($ip, 5, 'Invalid JWT attempt');
            $this->logs->log($route, $method, 'BLOCKED', 'Missing or invalid JWT token', ['ip' => $ip]);
            return new WP_Error('secure_guard_invalid_token', __('REST API requires a valid JWT token.', 'wp-secure-guard'), ['status' => 403]);
        }

        // Sensitivity scoring and reputation feed
        $weight = $this->sensitivity->get_weight($route);
        if ($weight > 1) {
            $this->reputation_engine->add_score($ip, (int) ($weight / 2), 'Sensitive endpoint hit');
        }

        if ($this->endpoint_blocker->should_block_sensitive_endpoints() && $this->endpoint_blocker->is_sensitive_route($route)) {
            $is_admin_scope = in_array('full_api_access', $this->token_manager->get_token_scopes($token_row), true);
            if (!$is_admin_scope) {
                $this->reputation_engine->add_score($ip, 10, 'Sensitive endpoint unauthorized access attempt');
                $this->logs->log($route, $method, 'BLOCKED', 'Sensitive endpoint blocked for JWT scope', ['token_id' => $token_row['id'] ?? 0, 'ip' => $ip]);
                return new WP_Error('secure_guard_sensitive_blocked', __('Endpoint blocked.', 'wp-secure-guard'), ['status' => 403]);
            }
        }

        if (!$this->token_manager->route_allowed($token_row, $route)) {
            $this->logs->log($route, $method, 'BLOCKED', 'Route not allowed for token', ['token_id' => $token_row['id'] ?? 0, 'ip' => $ip]);
            return new WP_Error('secure_guard_route_forbidden', __('Token is not allowed for this endpoint.', 'wp-secure-guard'), ['status' => 403]);
        }

        if (!$this->ip_whitelist->is_allowed($ip, (string) ($token_row['allowed_ips'] ?? ''))) {
            $this->logs->log($route, $method, 'BLOCKED', 'IP not allowed', ['token_id' => $token_row['id'] ?? 0, 'ip' => $ip]);
            return new WP_Error('secure_guard_ip_forbidden', __('IP is not allowed.', 'wp-secure-guard'), ['status' => 403]);
        }

        // Multi-dimensional rate limiting
        $token_id = (int) ($token_row['id'] ?? 0);
        $token_limit = isset($token_row['rate_limit_per_minute']) ? (int) $token_row['rate_limit_per_minute'] : (int) ($this->settings['rate_limit_per_minute'] ?? 100);
        
        // Scale limit based on endpoint sensitivity
        $multiplier = $this->sensitivity->get_limit_multiplier($route);
        $scaled_limit = max(1, (int) ($token_limit * $multiplier));

        // Adaptive Scaling: Reduce limit based on reputation tier
        $rep_tier = $this->reputation_engine->get_tier($ip);
        if ($rep_tier === Secure_Guard_Reputation_Engine::TIER_CHALLENGED) {
            $scaled_limit = max(1, (int) ($scaled_limit * 0.5));
        } elseif ($rep_tier === Secure_Guard_Reputation_Engine::TIER_THROTTLED) {
            $scaled_limit = max(1, (int) ($scaled_limit * 0.2));
        }

        $subjects = [
            'token:' . $token_id,                    // Dimension 1: Token
            'ip:' . $ip,                            // Dimension 2: IP
            'ip_endpoint:' . md5($ip . ':' . $route), // Dimension 3: IP + Endpoint
            'ip_ua:' . md5($ip . ':' . $ua),        // Dimension 4: IP + UA
        ];

        foreach ($subjects as $subject) {
            if (!$this->rate_limit->allow($subject, $scaled_limit)) {
                $this->reputation_engine->add_score($ip, 5, 'Rate limit exceeded (' . $subject . ')');
                $this->logs->log($route, $method, 'BLOCKED', 'Rate limit exceeded: ' . $subject, ['token_id' => $token_id, 'ip' => $ip]);
                return new WP_Error('secure_guard_rate_limit', __('Rate limit exceeded.', 'wp-secure-guard'), ['status' => 429]);
            }
        }

        // Logged-in user reputation bonus
        $this->reputation_engine->add_score($ip, 1, 'Normal request');

        // touch_last_used is already handled inside validate_token().
        // Only log ALLOWED events when explicitly enabled (reduces DB write pressure).
        if (!empty($this->settings['log_allowed_requests'])) {
            $this->logs->log($route, $method, 'ALLOWED', 'JWT API request allowed', ['token_id' => $token_row['id'] ?? 0, 'ip' => $ip]);
        }

        return $result;
    }

    public function pre_dispatch($response, WP_REST_Server $server, WP_REST_Request $request) {
        $route = (string) $request->get_route();
        
        if ($this->lock_state->is_locked() && !$this->lock_state->is_route_allowed_in_lockdown($route)) {
            return new WP_Error('secure_guard_locked', __('System is in emergency lockdown mode.', 'wp-secure-guard'), ['status' => 503]);
        }

        if ($route === '') {
            return $response;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? ''));
        $method = sanitize_text_field((string) $request->get_method());

        if ($this->endpoint_blocker->is_protected_path_request($request_uri)) {
            $this->logs->log($request_uri, $method, 'BLOCKED', 'Protected path request', []);
            return new WP_Error('secure_guard_path_blocked', __('Forbidden.', 'wp-secure-guard'), ['status' => 403]);
        }

        return $response;
    }

    public function final_gate($response, WP_REST_Server $server, WP_REST_Request $request) {
        // Final gatekeeper logic - could re-verify auth or state
        if ($this->lock_state->is_locked() && !is_user_logged_in()) {
             return new WP_Error('secure_guard_locked_final', __('Access denied.', 'wp-secure-guard'), ['status' => 403]);
        }
        return $response;
    }

    public function register_routes(): void {
        register_rest_route('secure-guard/v1', '/status', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_status'],
            'permission_callback' => '__return_true', // Enforced by authenticate() filter
        ]);
    }

    public function get_status(): WP_REST_Response {
        return new WP_REST_Response([
            'status'  => 'active',
            'version' => SECURE_GUARD_VERSION,
            'lockdown' => $this->lock_state->is_locked(),
        ]);
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

    private function is_namespace_allowed(string $route): bool {
        $allowed_raw = $this->settings['allowed_rest_namespaces'] ?? '';
        if (trim($allowed_raw) === '') {
            return false;
        }

        $allowed_namespaces = array_filter(array_map('trim', explode("\n", $allowed_raw)));
        foreach ($allowed_namespaces as $namespace) {
            $namespace = '/' . ltrim($namespace, '/');
            if ($route === $namespace || str_starts_with($route, $namespace . '/')) {
                return true;
            }
        }

        return false;
    }

}
