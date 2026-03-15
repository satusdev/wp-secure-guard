<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Rate_Limit {
    private Secure_Guard_Rate_Limit_Repository $repository;
    private array $settings;

    public function __construct(Secure_Guard_Rate_Limit_Repository $repository, array $settings) {
        $this->repository = $repository;
        $this->settings = $settings;
    }

    public function allow(string $subject, ?int $token_limit = null): bool {
        $limit = $token_limit && $token_limit > 0 ? $token_limit : (int) ($this->settings['rate_limit_per_minute'] ?? 100);
        return $this->allow_with_policy($subject, $limit, 60, 60);
    }

    public function allow_with_policy(string $subject, int $limit, int $window_seconds, int $block_seconds): bool {
        // Transient-backed sliding window — zero DB queries per check when using a
        // persistent object cache (Redis/Memcached); one option-table read otherwise,
        // still far cheaper than the previous SELECT + UPDATE pair per request.
        $key  = 'sg_rl_' . substr(md5($subject), 0, 20);
        $now  = time();
        $ttl  = max($window_seconds, $block_seconds) + 60;

        $current = get_transient($key);

        if (!is_array($current)) {
            set_transient($key, ['s' => $now, 'h' => 1, 'b' => 0], $ttl);
            return true;
        }

        $blocked_until = (int) ($current['b'] ?? 0);
        if ($blocked_until > $now) {
            return false;
        }

        $started_at = (int) ($current['s'] ?? 0);
        $hit_count  = (int) ($current['h'] ?? 0);

        if ($started_at < ($now - $window_seconds)) {
            // Window expired — start a fresh window.
            set_transient($key, ['s' => $now, 'h' => 1, 'b' => 0], $ttl);
            return true;
        }

        $hit_count++;
        if ($hit_count > $limit) {
            set_transient($key, ['s' => $started_at, 'h' => $hit_count, 'b' => $now + max(1, $block_seconds)], $block_seconds + 60);
            return false;
        }

        set_transient($key, ['s' => $started_at, 'h' => $hit_count, 'b' => 0], $ttl);
        return true;
    }
}
