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
        // Prefer the resolved client IP from $context['ip'] when present — security modules that call
        // IP_Whitelist::get_request_ip() pass the real client IP here, which correctly handles
        // Cloudflare / reverse-proxy setups. Fall back to REMOTE_ADDR for modules that don't set it.
        $ip = sanitize_text_field((string) ($context['ip'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'));

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

    /**
     * Paginated log fetch with optional filters.
     *
     * @param int    $limit     Rows per page.
     * @param int    $offset    Row offset.
     * @param string $result    Optional filter: 'BLOCKED', 'ALLOWED', or '' for all.
     * @param string $ip        Optional partial IP filter (LIKE match).
     * @param string $date_from Optional start date filter (Y-m-d).
     * @param string $date_to   Optional end date filter (Y-m-d).
     * @return array<int,array<string,mixed>>
     */
    public function recent_filtered(int $limit = 25, int $offset = 0, string $result = '', string $ip = '', string $date_from = '', string $date_to = ''): array {
        $limit  = max(1, min(200, $limit));
        $offset = max(0, $offset);

        [$where, $params] = $this->build_where_clause($result, $ip, $date_from, $date_to);

        if ($where === '') {
            $query = $this->db->prepare(
                "SELECT * FROM {$this->table} ORDER BY id DESC LIMIT %d OFFSET %d",
                $limit, $offset
            );
        } else {
            $query = $this->db->prepare(
                "SELECT * FROM {$this->table} {$where} ORDER BY id DESC LIMIT %d OFFSET %d",
                ...[...$params, $limit, $offset]
            );
        }

        return $this->db->get_results($query, ARRAY_A) ?: [];
    }

    /**
     * Total count with optional filters (used for pagination).
     */
    public function count_filtered(string $result = '', string $ip = '', string $date_from = '', string $date_to = ''): int {
        [$where, $params] = $this->build_where_clause($result, $ip, $date_from, $date_to);

        if ($where === '') {
            $query = "SELECT COUNT(*) FROM {$this->table}";
        } else {
            $query = $this->db->prepare(
                "SELECT COUNT(*) FROM {$this->table} {$where}",
                ...$params
            );
        }

        return (int) $this->db->get_var($query);
    }

    /**
     * Builds a parameterized WHERE clause from optional filter values.
     *
     * @return array{string, array<int,mixed>} Tuple of [where_string, params_array].
     */
    private function build_where_clause(string $result, string $ip, string $date_from, string $date_to): array {
        $conditions = [];
        $params     = [];

        if ($result !== '') {
            $conditions[] = 'result = %s';
            $params[]     = strtoupper($result);
        }

        if ($ip !== '') {
            $conditions[] = 'ip LIKE %s';
            $params[]     = '%' . $this->db->esc_like($ip) . '%';
        }

        if ($date_from !== '') {
            $conditions[] = 'created_at >= %s';
            $params[]     = $date_from . ' 00:00:00';
        }

        if ($date_to !== '') {
            $conditions[] = 'created_at <= %s';
            $params[]     = $date_to . ' 23:59:59';
        }

        if ($conditions === []) {
            return ['', []];
        }

        return ['WHERE ' . implode(' AND ', $conditions), $params];
    }
}
