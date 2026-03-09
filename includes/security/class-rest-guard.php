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
        if (!empty($result)) {
            return $result;
        }

        if (empty($this->settings['rest_lock_enabled'])) {
            return $result;
        }

        if ($this->current_user_has_allowed_role()) {
            return $result;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $route = $this->extract_route($request_uri);
        $ip = $this->ip_whitelist->get_request_ip();

        if ($this->endpoint_blocker->should_block_sensitive_endpoints() && $this->endpoint_blocker->is_sensitive_route($route)) {
            $token = $this->token_manager->extract_bearer_token();
            $token_row = $this->token_manager->validate_token($token);
            $is_admin_scope = $token_row && in_array('full_api_access', $this->token_manager->get_token_scopes($token_row), true);

            if (!$is_admin_scope) {
                $this->logs->log($route, $method, 'BLOCKED', 'Sensitive endpoint blocked', ['ip' => $ip]);
                return new WP_Error('secure_guard_sensitive_blocked', __('Endpoint blocked.', 'secure-guard'), ['status' => 403]);
            }
        }

        $token = $this->token_manager->extract_bearer_token();
        $token_row = $this->token_manager->validate_token($token);
        if (!$token_row) {
            $this->logs->log($route, $method, 'BLOCKED', 'Missing or invalid token', ['ip' => $ip]);
            return new WP_Error('secure_guard_invalid_token', __('REST API is locked. Valid token required.', 'secure-guard'), ['status' => 403]);
        }

        if (!$this->token_manager->route_allowed($token_row, $route)) {
            $this->logs->log($route, $method, 'BLOCKED', 'Route not allowed for token', ['token_id' => $token_row['id']]);
            return new WP_Error('secure_guard_route_forbidden', __('Token is not allowed for this endpoint.', 'secure-guard'), ['status' => 403]);
        }

        if (!$this->ip_whitelist->is_allowed($ip, (string) ($token_row['allowed_ips'] ?? ''))) {
            $this->logs->log($route, $method, 'BLOCKED', 'IP not allowed', ['token_id' => $token_row['id'], 'ip' => $ip]);
            return new WP_Error('secure_guard_ip_forbidden', __('IP is not allowed.', 'secure-guard'), ['status' => 403]);
        }

        $subject = 'token:' . (int) $token_row['id'];
        $token_limit = isset($token_row['rate_limit_per_minute']) ? (int) $token_row['rate_limit_per_minute'] : null;
        if (!$this->rate_limit->allow($subject, $token_limit)) {
            $this->logs->log($route, $method, 'BLOCKED', 'Rate limit exceeded', ['token_id' => $token_row['id']]);
            return new WP_Error('secure_guard_rate_limit', __('Rate limit exceeded.', 'secure-guard'), ['status' => 429]);
        }

        $this->logs->log($route, $method, 'ALLOWED', 'API request allowed', ['token_id' => $token_row['id'], 'ip' => $ip]);

        return $result;
    }

    public function pre_dispatch($response, WP_REST_Server $server, WP_REST_Request $request) {
        $route = (string) $request->get_route();
        if ($route === '') {
            return $response;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? ''));
        if ($this->endpoint_blocker->is_protected_path_request($request_uri)) {
            $this->logs->log($request_uri, (string) $request->get_method(), 'BLOCKED', 'Protected path request', []);
            return new WP_Error('secure_guard_path_blocked', __('Forbidden.', 'secure-guard'), ['status' => 403]);
        }

        return $response;
    }

    public function register_fallback_user_routes(): void {
        $server = rest_get_server();
        if (!$server instanceof WP_REST_Server) {
            return;
        }

        $routes = $server->get_routes();
        if (isset($routes['/wp/v2/users']) && $this->route_supports_get($routes['/wp/v2/users'])) {
            return;
        }

        register_rest_route(
            'wp/v2',
            '/users',
            [
                [
                    'methods' => WP_REST_Server::READABLE,
                    'callback' => [$this, 'fallback_users_collection'],
                    'permission_callback' => [$this, 'fallback_users_permission'],
                    'args' => [
                        'page' => [
                            'type' => 'integer',
                            'default' => 1,
                            'required' => false,
                        ],
                        'per_page' => [
                            'type' => 'integer',
                            'default' => 10,
                            'required' => false,
                        ],
                        'search' => [
                            'type' => 'string',
                            'required' => false,
                        ],
                    ],
                ],
            ]
        );
    }

    public function ensure_users_collection_endpoint(array $endpoints): array {
        if (isset($endpoints['/wp/v2/users']) && $this->route_supports_get($endpoints['/wp/v2/users'])) {
            return $endpoints;
        }

        $endpoints['/wp/v2/users'] = [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'fallback_users_collection'],
                'permission_callback' => [$this, 'fallback_users_permission'],
                'args' => [
                    'page' => [
                        'type' => 'integer',
                        'default' => 1,
                        'required' => false,
                    ],
                    'per_page' => [
                        'type' => 'integer',
                        'default' => 10,
                        'required' => false,
                    ],
                    'search' => [
                        'type' => 'string',
                        'required' => false,
                    ],
                ],
            ],
        ];

        return $endpoints;
    }

    private function current_user_has_allowed_role(): bool {
        if (!is_user_logged_in()) {
            return false;
        }

        $user = wp_get_current_user();
        if (!$user || !isset($user->roles) || !is_array($user->roles)) {
            return false;
        }

        $allowed_roles = $this->settings['allowed_roles'] ?? ['administrator'];
        foreach ($user->roles as $role) {
            if (in_array($role, $allowed_roles, true)) {
                return true;
            }
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

    private function route_supports_get(array $route_config): bool {
        foreach ($route_config as $endpoint) {
            if (!is_array($endpoint) || !isset($endpoint['methods'])) {
                continue;
            }

            $methods = $endpoint['methods'];
            if (is_string($methods) && strtoupper($methods) === 'GET') {
                return true;
            }

            if (is_array($methods) && in_array('GET', array_map('strtoupper', $methods), true)) {
                return true;
            }
        }

        return false;
    }

    public function fallback_users_permission(WP_REST_Request $request) {
        if (current_user_can('list_users')) {
            return true;
        }

        $token = $this->token_manager->extract_bearer_token();
        $token_row = $this->token_manager->validate_token($token);
        if (!$token_row) {
            return new WP_Error('secure_guard_invalid_token', __('REST API is locked. Valid token required.', 'secure-guard'), ['status' => 403]);
        }

        $scopes = $this->token_manager->get_token_scopes($token_row);
        if (!in_array('full_api_access', $scopes, true)) {
            return new WP_Error('secure_guard_sensitive_blocked', __('Endpoint blocked.', 'secure-guard'), ['status' => 403]);
        }

        if (!$this->token_manager->route_allowed($token_row, '/wp/v2/users')) {
            return new WP_Error('secure_guard_route_forbidden', __('Token is not allowed for this endpoint.', 'secure-guard'), ['status' => 403]);
        }

        $ip = $this->ip_whitelist->get_request_ip();
        if (!$this->ip_whitelist->is_allowed($ip, (string) ($token_row['allowed_ips'] ?? ''))) {
            return new WP_Error('secure_guard_ip_forbidden', __('IP is not allowed.', 'secure-guard'), ['status' => 403]);
        }

        return true;
    }

    public function fallback_users_collection(WP_REST_Request $request): WP_REST_Response {
        $page = max(1, (int) ($request->get_param('page') ?? 1));
        $per_page = min(100, max(1, (int) ($request->get_param('per_page') ?? 10)));
        $search = sanitize_text_field((string) ($request->get_param('search') ?? ''));

        $args = [
            'number' => $per_page,
            'offset' => ($page - 1) * $per_page,
            'orderby' => 'ID',
            'order' => 'ASC',
        ];

        if ($search !== '') {
            $args['search'] = '*' . $search . '*';
            $args['search_columns'] = ['user_login', 'user_nicename', 'display_name', 'user_email'];
        }

        $query = new WP_User_Query($args);
        $results = $query->get_results();

        $users = array_map(static function ($user): array {
            return [
                'id' => (int) $user->ID,
                'name' => (string) $user->display_name,
                'slug' => (string) $user->user_nicename,
                'link' => (string) get_author_posts_url((int) $user->ID),
            ];
        }, $results);

        $this->logs->log('/wp/v2/users', 'GET', 'ALLOWED', 'Fallback users endpoint served', []);

        $response = rest_ensure_response($users);
        $response->header('X-WP-Total', (string) $query->get_total());
        $response->header('X-WP-TotalPages', (string) max(1, (int) ceil(((int) $query->get_total()) / $per_page)));

        return $response;
    }
}
