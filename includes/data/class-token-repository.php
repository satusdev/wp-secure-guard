<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Token_Repository {
    private wpdb $db;
    private string $table;

    public function __construct() {
        global $wpdb;
        $this->db = $wpdb;
        $this->table = $wpdb->prefix . 'sg_tokens';
    }

    public function create_token(string $name, string $plain_token, array $scopes, string $allowed_endpoints, string $allowed_ips, ?int $rate_limit_per_minute, ?string $expires_at): int {
        $hash = hash('sha256', $plain_token);
        $now = current_time('mysql', true);

        $this->db->insert(
            $this->table,
            [
                'name' => $name,
                'token_hash' => $hash,
                'scope' => implode(',', array_map('sanitize_key', $scopes)),
                'allowed_endpoints' => $allowed_endpoints,
                'allowed_ips' => $allowed_ips,
                'rate_limit_per_minute' => $rate_limit_per_minute,
                'expires_at' => $expires_at,
                'created_at' => $now,
            ],
            ['%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s']
        );

        return (int) $this->db->insert_id;
    }

    public function get_by_plain_token(string $plain_token): ?array {
        $hash = hash('sha256', $plain_token);
        $query = $this->db->prepare("SELECT * FROM {$this->table} WHERE token_hash = %s AND revoked_at IS NULL LIMIT 1", $hash);
        $row = $this->db->get_row($query, ARRAY_A);

        if (!$row) {
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
        return $this->db->get_results("SELECT id, name, scope, expires_at, rate_limit_per_minute, last_used_at, created_at, revoked_at FROM {$this->table} ORDER BY id DESC", ARRAY_A) ?: [];
    }

    public function revoke(int $id): void {
        $this->db->update(
            $this->table,
            ['revoked_at' => current_time('mysql', true)],
            ['id' => $id],
            ['%s'],
            ['%d']
        );
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
}
