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
        $burst_limit = (int) ($this->settings['burst_limit'] ?? 30);
        $burst_window = (int) ($this->settings['burst_window_seconds'] ?? 2);

        return $this->allow_sliding($subject, $limit, 60, $burst_limit, $burst_window);
    }

    /**
     * Sliding window rate limiting with burst control.
     * Uses a transient-backed array of timestamps.
     */
    public function allow_sliding(string $subject, int $limit, int $window_seconds, int $burst_limit, int $burst_window): bool {
        $key = 'sg_rl_sw_' . substr(md5($subject), 0, 20);
        $now = microtime(true);
        $ttl = $window_seconds + 60;

        $history = get_transient($key);
        if (!is_array($history)) {
            $history = [];
        }

        // Evict expired entries from main window
        $history = array_values(array_filter($history, function($ts) use ($now, $window_seconds) {
            return $ts > ($now - $window_seconds);
        }));

        // Check burst limit
        $recent_count = 0;
        foreach ($history as $ts) {
            if ($ts > ($now - $burst_window)) {
                $recent_count++;
            }
        }

        if ($recent_count >= $burst_limit) {
            return false;
        }

        // Check main window limit
        if (count($history) >= $limit) {
            return false;
        }

        // Add current hit
        $history[] = $now;
        set_transient($key, $history, $ttl);

        return true;
    }

    /**
     * Legacy support for fixed policy if needed, but redirects to sliding.
     */
    public function allow_with_policy(string $subject, int $limit, int $window_seconds, int $block_seconds): bool {
        // For simple traffic firewall checks, we use sliding window with default burst.
        $burst_limit = (int) ($this->settings['burst_limit'] ?? 30);
        $burst_window = (int) ($this->settings['burst_window_seconds'] ?? 2);
        
        return $this->allow_sliding($subject, $limit, $window_seconds, $burst_limit, $burst_window);
    }
}
