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
        // Single atomic INSERT ... ON DUPLICATE KEY UPDATE avoids a TOCTOU race condition
        // when concurrent requests from the same IP hit this code path simultaneously.
        // The UNIQUE KEY on `subject` guarantees at-most-one row per subject.
        if ($blocked_until !== null) {
            $this->db->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
                $this->db->prepare(
                    "INSERT INTO {$this->table} (subject, window_started_at, hit_count, blocked_until)
                     VALUES (%s, %s, %d, %s)
                     ON DUPLICATE KEY UPDATE
                     window_started_at = VALUES(window_started_at),
                     hit_count = VALUES(hit_count),
                     blocked_until = VALUES(blocked_until)",
                    $subject, $window_started_at, $hit_count, $blocked_until
                )
            );
        } else {
            $this->db->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
                $this->db->prepare(
                    "INSERT INTO {$this->table} (subject, window_started_at, hit_count, blocked_until)
                     VALUES (%s, %s, %d, NULL)
                     ON DUPLICATE KEY UPDATE
                     window_started_at = VALUES(window_started_at),
                     hit_count = VALUES(hit_count),
                     blocked_until = NULL",
                    $subject, $window_started_at, $hit_count
                )
            );
        }
    }

    public function count_active_blocks(string $subject_like = '%'): int {
        $query = $this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE subject LIKE %s AND blocked_until IS NOT NULL AND blocked_until > UTC_TIMESTAMP()",
            $subject_like
        );
        $result = $this->db->get_var($query);

        return (int) $result;
    }

    /**
     * Returns paginated rows of active IP blocks for the Blocked IPs admin page.
     *
     * @return array<int,array<string,mixed>>
     */
    public function get_active_blocks(int $limit = 25, int $offset = 0): array {
        $limit  = max(1, min(200, $limit));
        $offset = max(0, $offset);
        $query  = $this->db->prepare(
            "SELECT * FROM {$this->table} WHERE subject LIKE %s AND blocked_until IS NOT NULL AND blocked_until > UTC_TIMESTAMP() ORDER BY blocked_until DESC LIMIT %d OFFSET %d",
            'ip-block:%', $limit, $offset
        );

        return $this->db->get_results($query, ARRAY_A) ?: [];
    }

    /**
     * Total count of active IP blocks (for pagination in the Blocked IPs admin page).
     */
    public function count_active_ip_blocks(): int {
        $query = $this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE subject LIKE %s AND blocked_until IS NOT NULL AND blocked_until > UTC_TIMESTAMP()",
            'ip-block:%'
        );

        return (int) $this->db->get_var($query);
    }

    /**
     * Delete a rate-limit row by its subject key (e.g. 'ip-block:1.2.3.4').
     * Returns true on success or if the row did not exist.
     */
    public function delete_block(string $subject): bool {
        $result = $this->db->delete($this->table, ['subject' => $subject], ['%s']);

        return $result !== false;
    }
}
