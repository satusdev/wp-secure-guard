<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Token_Repository {
    private wpdb $db;
    private string $table;
    private string $jwt_denylist_table;

    public function __construct() {
        global $wpdb;
        $this->db = $wpdb;
        $this->table = $wpdb->prefix . 'sg_tokens';
        $this->jwt_denylist_table = $wpdb->prefix . 'sg_jwt_denylist';
    }

    public function create_token(string $name, string $plain_token, array $scopes, string $allowed_endpoints, string $allowed_ips, ?int $rate_limit_per_minute, ?string $expires_at, string $token_type = 'jwt', ?string $jti = null, ?string $kid = null): int {
        $token_type = 'jwt';
        $hash_source = $jti ?: wp_generate_uuid4();
        $hash = hash('sha256', $hash_source . '|' . wp_generate_uuid4() . '|' . microtime(true));
        $now = current_time('mysql', true);

        $this->db->insert(
            $this->table,
            [
                'name' => $name,
                'token_type' => $token_type,
                'token_hash' => $hash,
                'jti' => $jti,
                'kid' => $kid,
                'scope' => implode(',', array_map('sanitize_key', $scopes)),
                'allowed_endpoints' => $allowed_endpoints,
                'allowed_ips' => $allowed_ips,
                'rate_limit_per_minute' => $rate_limit_per_minute,
                'expires_at' => $expires_at,
                'created_at' => $now,
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s']
        );

        return (int) $this->db->insert_id;
    }

    public function get_by_plain_token(string $plain_token): ?array {
        // Deprecated in JWT-only mode. Kept for backward schema compatibility.
        $hash = hash('sha256', $plain_token);
        $query = $this->db->prepare("SELECT * FROM {$this->table} WHERE token_type = 'static' AND token_hash = %s AND revoked_at IS NULL LIMIT 1", $hash);
        $row = $this->db->get_row($query, ARRAY_A);

        if (!$row) {
            return null;
        }

        return $row;
    }

    public function get_active_by_id(int $id): ?array {
        $query = $this->db->prepare("SELECT * FROM {$this->table} WHERE id = %d AND revoked_at IS NULL LIMIT 1", $id);
        $row = $this->db->get_row($query, ARRAY_A);
        if (!$row) {
            return null;
        }

        if (!empty($row['expires_at']) && strtotime((string) $row['expires_at']) < time()) {
            return null;
        }

        return $row;
    }

    public function touch_last_used(int $id): void {
        $this->db->update(
            $this->table,
            ['last_used_at' => current_time('mysql', true)],
            ['id' => $id],
            ['%s'],
            ['%d']
        );
    }

    public function all_tokens(): array {
        return $this->db->get_results("SELECT id, name, token_type, jti, scope, expires_at, rate_limit_per_minute, last_used_at, created_at, revoked_at FROM {$this->table} ORDER BY id DESC", ARRAY_A) ?: [];
    }

    public function revoke(int $id): void {
        $row = $this->get_active_by_id($id);
        $this->db->update(
            $this->table,
            ['revoked_at' => current_time('mysql', true)],
            ['id' => $id],
            ['%s'],
            ['%d']
        );

        if (is_array($row) && (string) ($row['token_type'] ?? 'static') === 'jwt') {
            $jti = sanitize_text_field((string) ($row['jti'] ?? ''));
            if ($jti !== '') {
                $until = !empty($row['expires_at']) ? (string) $row['expires_at'] : gmdate('Y-m-d H:i:s', time() + (2 * DAY_IN_SECONDS));
                $this->revoke_jti($jti, $until);
            }
        }
    }

    public function delete(int $id): void {
        $this->db->delete(
            $this->table,
            ['id' => $id],
            ['%d']
        );
    }

    public function count_active(): int {
        $result = $this->db->get_var("SELECT COUNT(*) FROM {$this->table} WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())");
        return (int) $result;
    }

    public function revoke_jti(string $jti, ?string $revoked_until): void {
        if ($jti === '') {
            return;
        }

        $this->db->query(
            $this->db->prepare(
                "INSERT INTO {$this->jwt_denylist_table} (jti, revoked_until, created_at)
                 VALUES (%s, %s, %s)
                 ON DUPLICATE KEY UPDATE revoked_until = VALUES(revoked_until)",
                $jti,
                $revoked_until,
                current_time('mysql', true)
            )
        );
    }

    public function is_jti_revoked(string $jti): bool {
        if ($jti === '') {
            return true;
        }

        $query = $this->db->prepare("SELECT revoked_until FROM {$this->jwt_denylist_table} WHERE jti = %s LIMIT 1", $jti);
        $row = $this->db->get_row($query, ARRAY_A);
        if (!$row) {
            return false;
        }

        $revoked_until = isset($row['revoked_until']) ? (string) $row['revoked_until'] : '';
        if ($revoked_until === '') {
            return true;
        }

        return (strtotime($revoked_until) ?: 0) >= time();
    }
}
