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
            $result = $this->db->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
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
            $result = $this->db->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
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

        if ($result === false) {
            do_action('secure_guard_rate_limit_write_failed', $subject, (string) $this->db->last_error);
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
            "SELECT * FROM {$this->table} WHERE (subject LIKE %s OR subject LIKE %s) AND blocked_until IS NOT NULL AND blocked_until > UTC_TIMESTAMP() ORDER BY blocked_until DESC LIMIT %d OFFSET %d",
            'ip-block:%', 'login-block:%', $limit, $offset
        );

        return $this->db->get_results($query, ARRAY_A) ?: [];
    }

    /**
     * Returns active block rows matching a single subject prefix.
     *
     * @return array<int,array<string,mixed>>
     */
    public function get_active_blocks_by_prefix(string $subject_prefix, int $limit = 1000): array {
        $limit = max(1, min(5000, $limit));
        $query = $this->db->prepare(
            "SELECT * FROM {$this->table} WHERE subject LIKE %s AND blocked_until IS NOT NULL AND blocked_until > UTC_TIMESTAMP() ORDER BY blocked_until DESC LIMIT %d",
            $subject_prefix . '%',
            $limit
        );

        return $this->db->get_results($query, ARRAY_A) ?: [];
    }

    /**
     * Total count of active IP blocks (for pagination in the Blocked IPs admin page).
     */
    public function count_active_ip_blocks(): int {
        $query = $this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE (subject LIKE %s OR subject LIKE %s) AND blocked_until IS NOT NULL AND blocked_until > UTC_TIMESTAMP()",
            'ip-block:%', 'login-block:%'
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

    /**
     * Atomic increment of reputation score for a subject (usually 'rep:{IP}').
     * Uses GREATEST(0, ...) to prevent unsigned integer underflow if delta is negative.
     */
    public function upsert_reputation(string $subject, int $delta): int {
        $result = $this->db->query(
            $this->db->prepare(
                "INSERT INTO {$this->table} (subject, window_started_at, hit_count, reputation_score)
                 VALUES (%s, UTC_TIMESTAMP(), 0, GREATEST(0, %d))
                 ON DUPLICATE KEY UPDATE
                 reputation_score = GREATEST(0, CAST(reputation_score AS SIGNED) + %d)",
                $subject, $delta, $delta
            )
        );

        if ($result === false) {
            do_action('secure_guard_rate_limit_write_failed', $subject, (string) $this->db->last_error);
        }

        return $this->get_reputation($subject);
    }

    public function reset_reputation(string $subject): void {
        $result = $this->db->update($this->table, ['reputation_score' => 0], ['subject' => $subject], ['%d'], ['%s']);
        if ($result === false) {
            do_action('secure_guard_rate_limit_write_failed', $subject, (string) $this->db->last_error);
        }
    }

    public function set_reputation(string $subject, int $score): void {
        $this->upsert($subject, gmdate('Y-m-d H:i:s'), 0, null);
        $this->db->update($this->table, ['reputation_score' => max(0, $score)], ['subject' => $subject], ['%d'], ['%s']);
    }

    public function get_reputation(string $subject): int {
        $query = $this->db->prepare("SELECT reputation_score FROM {$this->table} WHERE subject = %s LIMIT 1", $subject);
        return (int) $this->db->get_var($query);
    }

    public function count_reputations(string $search_ip, string $tier, array $settings): int {
        [$where_sql, $params] = $this->build_reputation_filters($search_ip, $tier, $settings);
        $query = $params === []
            ? "SELECT COUNT(*) FROM {$this->table} WHERE {$where_sql}"
            : $this->db->prepare("SELECT COUNT(*) FROM {$this->table} WHERE {$where_sql}", ...$params);

        return (int) $this->db->get_var($query);
    }

    /**
     * @return array<int,array{subject:string,reputation_score:int}>
     */
    public function list_reputations(string $search_ip, string $tier, array $settings, int $limit, int $offset): array {
        $limit  = max(1, min(200, $limit));
        $offset = max(0, $offset);
        [$where_sql, $params] = $this->build_reputation_filters($search_ip, $tier, $settings);
        $params[] = $limit;
        $params[] = $offset;

        $query = $this->db->prepare(
            "SELECT subject, reputation_score FROM {$this->table} WHERE {$where_sql} ORDER BY reputation_score DESC LIMIT %d OFFSET %d",
            ...$params
        );

        return $this->db->get_results($query, ARRAY_A) ?: [];
    }

    /**
     * Decays reputation scores globally.
     */
    public function decay_reputation(int $decay_amount = 1): void {
        $this->db->query(
            $this->db->prepare(
                "UPDATE {$this->table} SET reputation_score = GREATEST(0, CAST(reputation_score AS SIGNED) - %d) WHERE reputation_score > 0",
                $decay_amount
            )
        );
    }

    /**
     * @return array{0:string,1:array<int,mixed>}
     */
    private function build_reputation_filters(string $search_ip, string $tier, array $settings): array {
        $where = ["reputation_score > 0", "subject LIKE 'rep:%'"];
        $params = [];

        if ($search_ip !== '') {
            $where[] = 'subject LIKE %s';
            $params[] = 'rep:%' . $this->db->esc_like($search_ip) . '%';
        }

        if ($tier !== '') {
            $block_score = (int) ($settings['reputation_block_score'] ?? 100);
            $challenge_score = (int) ($settings['reputation_challenge_score'] ?? 50);
            $throttle_score = (int) ($settings['reputation_throttle_score'] ?? 20);

            switch ($tier) {
                case 'blocked':
                    $where[] = 'reputation_score >= %d';
                    $params[] = $block_score;
                    break;
                case 'challenged':
                    $where[] = 'reputation_score >= %d AND reputation_score < %d';
                    $params[] = $challenge_score;
                    $params[] = $block_score;
                    break;
                case 'throttled':
                    $where[] = 'reputation_score >= %d AND reputation_score < %d';
                    $params[] = $throttle_score;
                    $params[] = $challenge_score;
                    break;
                case 'normal':
                    $where[] = 'reputation_score < %d';
                    $params[] = $throttle_score;
                    break;
            }
        }

        return [implode(' AND ', $where), $params];
    }
}
