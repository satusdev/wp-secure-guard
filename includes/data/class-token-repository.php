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

    public function all_tokens(int $limit = 0, int $offset = 0): array {
        $base = "SELECT id, name, token_type, jti, token_hash, scope,
                        allowed_endpoints, allowed_ips, rate_limit_per_minute,
                        expires_at, last_used_at, created_at, revoked_at
                 FROM {$this->table} ORDER BY id DESC";

        if ($limit > 0) {
            $sql = $this->db->prepare($base . ' LIMIT %d OFFSET %d', $limit, $offset);
        } else {
            $sql = $base;
        }

        return $this->db->get_results($sql, ARRAY_A) ?: [];
    }

    /**
     * Total row count — used for pagination on the Tokens admin page.
     */
    public function count_tokens(): int {
        return (int) $this->db->get_var("SELECT COUNT(*) FROM {$this->table}");
    }

    /**
     * Returns active, non-expired tokens whose expiry falls within $days days from now.
     * Used by the Security_Maintenance token-expiry alert check.
     *
     * @return array<int,array<string,mixed>>
     */
    public function get_expiring_soon(int $days): array {
        $days  = max(1, $days);
        $query = $this->db->prepare(
            "SELECT * FROM {$this->table}
              WHERE revoked_at  IS NULL
                AND expires_at  IS NOT NULL
                AND expires_at  >  UTC_TIMESTAMP()
                AND expires_at  <= (UTC_TIMESTAMP() + INTERVAL %d DAY)
              ORDER BY expires_at ASC",
            $days
        );

        return $this->db->get_results($query, ARRAY_A) ?: [];
    }

    /**
     * Persist the signed JWT string directly on the row so it is always retrievable.
     */
    public function store_jwt(int $id, string $jwt): void {
        $this->db->update(
            $this->table,
            ['token_hash' => $jwt],
            ['id' => $id],
            ['%s'],
            ['%d']
        );
    }

    /**
     * Update mutable token fields. Does not touch jti, kid, token_type, created_at, revoked_at.
     */
    public function update_token(
        int $id,
        string $name,
        array $scopes,
        string $allowed_endpoints,
        string $allowed_ips,
        ?int $rate_limit_per_minute,
        ?string $expires_at
    ): bool {
        $result = $this->db->update(
            $this->table,
            [
                'name'                  => $name,
                'scope'                 => implode(',', array_map('sanitize_key', $scopes)),
                'allowed_endpoints'     => $allowed_endpoints,
                'allowed_ips'           => $allowed_ips,
                'rate_limit_per_minute' => $rate_limit_per_minute,
                'expires_at'            => $expires_at,
            ],
            ['id' => $id],
            ['%s', '%s', '%s', '%s', '%d', '%s'],
            ['%d']
        );

        return $result !== false;
    }

    /**
     * Denylist the existing JTI, generate a fresh one, and write it to the row.
     * Returns the new JTI on success, null on DB failure.
     * Call this before re-issuing a JWT so the old copy is immediately invalidated.
     */
    public function rotate_jti(int $id, string $old_jti, ?string $token_expires_at): ?string {
        // Denylist the old JTI first so any outstanding JWT copy is rejected immediately.
        if ($old_jti !== '') {
            $until = !empty($token_expires_at)
                ? $token_expires_at
                : gmdate('Y-m-d H:i:s', time() + 2 * DAY_IN_SECONDS);
            $this->revoke_jti($old_jti, $until);
        }

        $new_jti = str_replace('-', '', wp_generate_uuid4());

        $updated = $this->db->update(
            $this->table,
            ['jti' => $new_jti],
            ['id'  => $id],
            ['%s'],
            ['%d']
        );

        return $updated !== false ? $new_jti : null;
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
