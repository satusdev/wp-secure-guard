<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_User_Enumeration_Blocker {
    private array $settings;
    private Secure_Guard_Log_Repository $logs;
    private Secure_Guard_Token_Manager $token_manager;

    public function __construct(array $settings, Secure_Guard_Log_Repository $logs, Secure_Guard_Token_Manager $token_manager) {
        $this->settings = $settings;
        $this->logs = $logs;
        $this->token_manager = $token_manager;
    }

    public function block_author_enumeration(): void {
        if (empty($this->settings['block_user_enumeration'])) {
            return;
        }

        if (is_user_logged_in() && current_user_can('list_users')) {
            return;
        }

        $request_uri = sanitize_text_field((string) ($_SERVER['REQUEST_URI'] ?? '/'));
        $method = sanitize_text_field((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $path = strtolower((string) (parse_url($request_uri, PHP_URL_PATH) ?: '/'));

        $reason = '';
        if (isset($_GET['author'])) {
            $reason = 'User enumeration via author query blocked';
        } elseif ($path === '/author' || str_starts_with($path, '/author/')) {
            $reason = 'User enumeration via author archive blocked';
        } elseif (isset($_GET['rest_route'])) {
            $rest_route = strtolower((string) wp_unslash($_GET['rest_route']));
            if ($rest_route === '/wp/v2/users' || str_starts_with($rest_route, '/wp/v2/users/')) {
                $reason = 'User enumeration via rest_route blocked';
            }
        }

        if ($reason === '') {
            return;
        }

        $this->logs->log($request_uri, $method, 'BLOCKED', $reason, []);

        status_header(403);
        wp_die(esc_html__('Forbidden', 'secure-guard'), esc_html__('Forbidden', 'secure-guard'), ['response' => 403]);
    }

    /**
     * Blocks the WP REST users collection endpoint for unauthenticated / low-privilege requests,
     * independent of rest_lock_enabled or block_sensitive_endpoints settings.
     * Hooked to rest_pre_dispatch at priority 5.
     *
     * Allows: logged-in users with list_users capability (admins), and valid JWT tokens
     * carrying the full_api_access scope (programmatic admin callers).
     *
     * @param mixed           $response
     * @param WP_REST_Server  $server
     * @param WP_REST_Request $request
     * @return mixed WP_Error on block, original response otherwise.
     */
    public function block_rest_users_endpoint($response, WP_REST_Server $server, WP_REST_Request $request) {
        if (empty($this->settings['block_user_enumeration'])) {
            return $response;
        }

        $route = (string) $request->get_route();
        if ($route !== '/wp/v2/users' && !str_starts_with($route, '/wp/v2/users/')) {
            return $response;
        }

        // Logged-in admins and editors with user management capability are always allowed.
        if (is_user_logged_in() && current_user_can('list_users')) {
            return $response;
        }

        // A JWT token with full_api_access scope represents an explicitly trusted programmatic
        // caller — allow it so REST admin integrations continue to work.
        $bearer = $this->token_manager->extract_bearer_token();
        if ($bearer !== null) {
            $token_row = $this->token_manager->validate_token($bearer);
            if ($token_row && in_array('full_api_access', $this->token_manager->get_token_scopes($token_row), true)) {
                return $response;
            }
        }

        $method = sanitize_text_field((string) $request->get_method());
        $this->logs->log('/wp/v2/users', $method, 'BLOCKED', 'User enumeration via REST API blocked', []);

        return new WP_Error(
            'secure_guard_user_enum_blocked',
            __('Endpoint not available.', 'secure-guard'),
            ['status' => 403]
        );
    }
}
