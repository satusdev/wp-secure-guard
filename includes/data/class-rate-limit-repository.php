<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Rate_Limit_Repository {
    private wpdb $db;
    private string $table;

    public function __construct() {
        global $wpdb;
        $this->db = $wpdb;
        $this->table = $wpdb->prefix . 'sg_rate_limits';
    }

    public function get(string $subject): ?array {
        $query = $this->db->prepare("SELECT * FROM {$this->table} WHERE subject = %s LIMIT 1", $subject);
        $row = $this->db->get_row($query, ARRAY_A);

        return $row ?: null;
    }

    public function upsert(string $subject, string $window_started_at, int $hit_count, ?string $blocked_until): void {
        $existing = $this->get($subject);

        if ($existing) {
            $this->db->update(
                $this->table,
                [
                    'window_started_at' => $window_started_at,
                    'hit_count' => $hit_count,
                    'blocked_until' => $blocked_until,
                ],
                ['subject' => $subject],
                ['%s', '%d', '%s'],
                ['%s']
            );

            return;
        }

        $this->db->insert(
            $this->table,
            [
                'subject' => $subject,
                'window_started_at' => $window_started_at,
                'hit_count' => $hit_count,
                'blocked_until' => $blocked_until,
            ],
            ['%s', '%s', '%d', '%s']
        );
    }

    public function count_active_blocks(string $subject_like = '%'): int {
        $query = $this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE subject LIKE %s AND blocked_until IS NOT NULL AND blocked_until > UTC_TIMESTAMP()",
            $subject_like
        );
        $result = $this->db->get_var($query);

        return (int) $result;
    }
}
