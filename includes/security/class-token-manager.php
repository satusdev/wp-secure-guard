<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Token_Manager {
    private Secure_Guard_Token_Repository $tokens;

    public function __construct(Secure_Guard_Token_Repository $tokens) {
        $this->tokens = $tokens;
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

        $token_row = $this->tokens->get_by_plain_token($plain_token);
        if (!$token_row) {
            return null;
        }

        if (!empty($token_row['expires_at']) && strtotime((string) $token_row['expires_at']) < time()) {
            return null;
        }

        $this->tokens->touch_last_used((int) $token_row['id']);
        $token_row['scopes'] = array_filter(array_map('trim', explode(',', (string) $token_row['scope'])));

        return $token_row;
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
