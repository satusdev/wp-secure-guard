<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Log_Repository {
    private wpdb $db;
    private string $table;

    public function __construct() {
        global $wpdb;
        $this->db = $wpdb;
        $this->table = $wpdb->prefix . 'sg_logs';
    }

    public function log(string $endpoint, string $method, string $result, string $reason, array $context = []): void {
        $ip = sanitize_text_field((string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'));

        $this->db->insert(
            $this->table,
            [
                'ip' => $ip,
                'endpoint' => substr($endpoint, 0, 255),
                'method' => substr($method, 0, 12),
                'result' => substr($result, 0, 32),
                'reason' => substr($reason, 0, 190),
                'context' => wp_json_encode($context),
                'created_at' => current_time('mysql', true),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );
    }

    public function recent(int $limit = 200): array {
        $limit = max(1, min(1000, $limit));
        $query = $this->db->prepare("SELECT * FROM {$this->table} ORDER BY id DESC LIMIT %d", $limit);

        return $this->db->get_results($query, ARRAY_A) ?: [];
    }

    public function purge_older_than_days(int $days): void {
        $days = max(1, $days);
        $query = $this->db->prepare("DELETE FROM {$this->table} WHERE created_at < (UTC_TIMESTAMP() - INTERVAL %d DAY)", $days);
        $this->db->query($query);
    }

    public function count_by_reason(string $reason): int {
        $query = $this->db->prepare("SELECT COUNT(*) FROM {$this->table} WHERE reason = %s", $reason);
        return (int) $this->db->get_var($query);
    }

    public function count_endpoint_prefix(string $prefix): int {
        $query = $this->db->prepare("SELECT COUNT(*) FROM {$this->table} WHERE endpoint LIKE %s", $prefix . '%');
        return (int) $this->db->get_var($query);
    }
}
