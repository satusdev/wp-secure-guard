<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Token_Manager {
    private Secure_Guard_Token_Repository $tokens;
    private array $settings;
    private ?string $cached_token = null;
    private ?array $cached_row = null;
    private bool $cache_initialized = false;

    public function __construct(Secure_Guard_Token_Repository $tokens, array $settings) {
        $this->tokens = $tokens;
        $this->settings = $settings;
    }

    public function extract_bearer_token(): ?string {
        $header = '';
        if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
            $header = (string) $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $header = (string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }

        if ($header === '' || stripos($header, 'Bearer ') !== 0) {
            return null;
        }

        $token = trim(substr($header, 7));
        if ($token === '') {
            return null;
        }

        return preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $token);
    }

    public function validate_token(?string $plain_token): ?array {
        if (!$plain_token) {
            return null;
        }

        if ($this->cache_initialized && $this->cached_token === $plain_token) {
            return $this->cached_row;
        }

        $this->cache_initialized = true;
        $this->cached_token = $plain_token;

        if (!$this->looks_like_jwt($plain_token)) {
            $this->cached_row = null;
            return null;
        }

        $this->cached_row = $this->validate_jwt_token($plain_token);
        return $this->cached_row;
    }

    public function issue_jwt_for_token_row(array $token_row): ?string {
        if ((string) ($token_row['token_type'] ?? 'static') !== 'jwt') {
            return null;
        }

        $secret = $this->get_jwt_secret();
        if ($secret === '') {
            return null;
        }

        $now = time();
        $exp = !empty($token_row['expires_at']) ? (strtotime((string) $token_row['expires_at']) ?: 0) : 0;
        if ($exp <= $now) {
            return null;
        }

        $issuer = (string) ($this->settings['jwt_issuer'] ?? home_url('/'));
        $audience = (string) ($this->settings['jwt_audience'] ?? home_url('/'));
        $jti = sanitize_text_field((string) ($token_row['jti'] ?? ''));
        if ($jti === '') {
            return null;
        }

        $claims = [
            'iss' => $issuer,
            'aud' => $audience,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $exp,
            'jti' => $jti,
            'tid' => (int) $token_row['id'],
        ];

        $kid = sanitize_text_field((string) ($token_row['kid'] ?? 'default'));

        return JWT::encode($claims, $secret, 'HS256', $kid);
    }

    private function validate_jwt_token(string $jwt): ?array {
        $secret = $this->get_jwt_secret();
        if ($secret === '') {
            return null;
        }

        $clock_skew = max(0, (int) ($this->settings['jwt_clock_skew_seconds'] ?? 30));
        $previous_leeway = JWT::$leeway;
        JWT::$leeway = $clock_skew;

        try {
            $claims = (array) JWT::decode($jwt, new Key($secret, 'HS256'));
        } catch (Throwable $exception) {
            JWT::$leeway = $previous_leeway;
            return null;
        }

        JWT::$leeway = $previous_leeway;

        $expected_issuer = (string) ($this->settings['jwt_issuer'] ?? home_url('/'));
        $issuer = isset($claims['iss']) ? (string) $claims['iss'] : '';
        if ($expected_issuer !== '' && !hash_equals($expected_issuer, $issuer)) {
            return null;
        }

        $expected_audience = (string) ($this->settings['jwt_audience'] ?? home_url('/'));
        $audience_claim = $claims['aud'] ?? '';
        if (!$this->audience_matches($audience_claim, $expected_audience)) {
            return null;
        }

        $token_id = isset($claims['tid']) ? (int) $claims['tid'] : 0;
        $jti = isset($claims['jti']) ? sanitize_text_field((string) $claims['jti']) : '';
        if ($token_id <= 0 || $jti === '') {
            return null;
        }

        if ($this->tokens->is_jti_revoked($jti)) {
            return null;
        }

        $token_row = $this->tokens->get_active_by_id($token_id);
        if (!$token_row) {
            return null;
        }

        if ((string) ($token_row['token_type'] ?? 'static') !== 'jwt') {
            return null;
        }

        $stored_jti = sanitize_text_field((string) ($token_row['jti'] ?? ''));
        if ($stored_jti === '' || !hash_equals($stored_jti, $jti)) {
            return null;
        }

        if (!empty($token_row['expires_at']) && strtotime((string) $token_row['expires_at']) < time()) {
            return null;
        }

        $this->tokens->touch_last_used((int) $token_row['id']);
        $token_row['scopes'] = $this->extract_scopes($token_row);

        return $token_row;
    }

    private function looks_like_jwt(string $token): bool {
        return preg_match('/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/', $token) === 1;
    }

    private function extract_scopes(array $token_row): array {
        return array_filter(array_map('trim', explode(',', (string) ($token_row['scope'] ?? ''))));
    }

    private function get_jwt_secret(): string {
        $secret = '';
        if (defined('SECURE_GUARD_JWT_SECRET')) {
            $secret = (string) SECURE_GUARD_JWT_SECRET;
        }

        if ($secret === '') {
            $secret = (string) ($this->settings['jwt_secret'] ?? '');
        }

        if ($secret === '' && defined('AUTH_KEY')) {
            $secret = (string) AUTH_KEY;
        }

        return trim($secret);
    }

    private function audience_matches($audience_claim, string $expected_audience): bool {
        if ($expected_audience === '') {
            return true;
        }

        if (is_string($audience_claim)) {
            return hash_equals($expected_audience, $audience_claim);
        }

        if (is_array($audience_claim)) {
            foreach ($audience_claim as $audience_value) {
                if (is_string($audience_value) && hash_equals($expected_audience, $audience_value)) {
                    return true;
                }
            }
        }

        return false;
    }

    public function route_allowed(array $token_row, string $route): bool {
        $allowed_endpoints = trim((string) ($token_row['allowed_endpoints'] ?? ''));
        if ($allowed_endpoints === '') {
            return true;
        }

        $patterns = preg_split('/\r\n|\r|\n/', $allowed_endpoints) ?: [];
        foreach ($patterns as $pattern) {
            $pattern = trim($pattern);
            if ($pattern === '') {
                continue;
            }

            if (str_ends_with($pattern, '*')) {
                $prefix = substr($pattern, 0, -1);
                if (str_starts_with($route, $prefix)) {
                    return true;
                }
                continue;
            }

            if ($route === $pattern) {
                return true;
            }
        }

        return false;
    }

    public function get_token_scopes(array $token_row): array {
        if (!isset($token_row['scopes']) || !is_array($token_row['scopes'])) {
            return [];
        }

        return array_values(array_unique(array_map('sanitize_key', $token_row['scopes'])));
    }
}
