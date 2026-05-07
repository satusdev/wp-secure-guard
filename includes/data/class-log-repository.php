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
        $cluster = $this->auto_detect_cluster($reason, $endpoint);
        $this->log_clustered($endpoint, $method, $result, $reason, $context, $cluster);
    }

    public function log_clustered(string $endpoint, string $method, string $result, string $reason, array $context = [], string $cluster = 'unknown'): void {
        $ip = sanitize_text_field((string) ($context['ip'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'));
        $country_code = $this->get_country_code($ip);

        $this->db->insert(
            $this->table,
            [
                'ip' => $ip,
                'endpoint' => substr($endpoint, 0, 255),
                'method' => substr($method, 0, 12),
                'result' => substr($result, 0, 32),
                'reason' => substr($reason, 0, 190),
                'attack_cluster' => substr($cluster, 0, 32),
                'country_code' => $country_code,
                'context' => wp_json_encode($context),
                'created_at' => current_time('mysql', true),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );
    }

    private function get_country_code(string $ip): string {
        if ($ip === '127.0.0.1' || $ip === '::1') {
            return 'LO'; // Local
        }

        $cache_key = 'sg_geo_' . md5($ip);
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            return (string) $cached;
        }

        // Use HTTPS for privacy and a tight timeout to avoid blocking requests.
        $response = wp_remote_get("https://ip-api.com/json/{$ip}?fields=status,countryCode", [
            'timeout' => 2,
        ]);

        $code = '??';
        if (!is_wp_error($response)) {
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            if (is_array($data) && ($data['status'] ?? '') === 'success') {
                $code = strtoupper((string) ($data['countryCode'] ?? '??'));
            }
        }

        set_transient($cache_key, $code, WEEK_IN_SECONDS);
        return $code;
    }

    private function auto_detect_cluster(string $reason, string $endpoint): string {
        $reason = strtolower($reason);
        $endpoint = strtolower($endpoint);

        if (str_contains($reason, 'login') || str_contains($reason, 'brute force') || str_contains($endpoint, 'wp-login')) return 'brute_force';
        if (str_contains($reason, 'scan') || str_contains($reason, '404') || str_contains($endpoint, '.php')) return 'scanning';
        if (str_contains($reason, 'rest') || str_contains($reason, 'api') || str_contains($reason, 'jwt')) return 'api_abuse';
        if (str_contains($reason, 'enumeration') || str_contains($endpoint, 'users')) return 'enumeration';
        if (str_contains($reason, 'bot') || str_contains($reason, 'fingerprint')) return 'bot_activity';
        if (str_contains($endpoint, 'xmlrpc') || str_contains($endpoint, 'cron')) return 'system_probes';

        return 'unknown';
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

    public function count_by_result(string $result, int $days = 0): int {
        if ($days > 0) {
            $query = $this->db->prepare(
                "SELECT COUNT(*) FROM {$this->table} WHERE result = %s AND created_at >= (UTC_TIMESTAMP() - INTERVAL %d DAY)",
                strtoupper($result),
                $days
            );
        } else {
            $query = $this->db->prepare("SELECT COUNT(*) FROM {$this->table} WHERE result = %s", strtoupper($result));
        }
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
     * Returns aggregated counts per cluster for the dashboard.
     */
    public function get_cluster_summary(int $hours = 24): array {
        $query = $this->db->prepare(
            "SELECT attack_cluster as cluster, COUNT(*) as count FROM {$this->table} WHERE created_at >= (UTC_TIMESTAMP() - INTERVAL %d HOUR) GROUP BY attack_cluster",
            $hours
        );
        return $this->db->get_results($query, ARRAY_A) ?: [];
    }

    /**
     * Returns the most recent reasons logged for an IP address.
     *
     * @return array<int,array{reason:string,created_at:string}>
     */
    public function recent_reasons_by_ip(string $ip, int $limit = 3): array {
        $limit = max(1, min(10, $limit));
        $query = $this->db->prepare(
            "SELECT reason, created_at FROM {$this->table} WHERE ip = %s ORDER BY id DESC LIMIT %d",
            $ip,
            $limit
        );

        return $this->db->get_results($query, ARRAY_A) ?: [];
    }

    /**
     * Builds a parameterized WHERE clause from optional filter values.
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
